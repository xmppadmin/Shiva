"""
This module is responsible honeypot learning and email classification

"""


import pickle
import logging
import os

from sklearn import tree
from sklearn.metrics import f1_score

import lamson.server
import backend_operations
import statistics

from phishing import check_url_phishing


# files used by module
CLASSIFIER_PKL = 'run/classifier.pkl'
LEARNING_LOCK = 'run/learning.lock'


#global variables
global_classifier = None
global_shiva_threshold = 0.5
global_sa_threshold = 0.5

def __init_classifier():
    """ 
    initialize classifier
    
    loads stored classifier  from pickle files if exist,
    otherwise it performs learning
    """
    
    global global_classifier
    global global_shiva_threshold
    global global_sa_threshold
    
    if global_classifier:
        return
    
    
    global_shiva_threshold, global_sa_threshold = backend_operations.get_current_detection_thresholds()
    logging.info("Learning: Loaded thresholds: {0} {1}".format(global_shiva_threshold,global_sa_threshold))
    
    logging.info("Learning: Trying to load classifier from file.")
    if os.path.exists(CLASSIFIER_PKL):
        classifier_file = open(CLASSIFIER_PKL,'rb')
        if classifier_file:
            global_classifier = pickle.load(classifier_file)
            classifier_file.close()
    
    if global_classifier:
        logging.info("Learning: Classifier successfully loaded.")
    
    else:
        logging.info("Learning: Classifier not found, trying to re-learn...")
        learn()
    
        

def learn():
    """
    start honeypot email classifiers learning process
    results of learning are stored in database table 'learningstate'
    """
    if not __check_learning_and_lock():
        logging.warn('Learning: attempt to learn honeypot while learning is already in progress. Nothing to do.')
        return
        
    classifier_status = __learn_classifier()
    spamassassin_status = __learn_spamassassin()
    
    shiva_threshold, sa_threshold = __compute_classifier_decision_tresholds()
    
    global global_shiva_threshold
    global global_sa_threshold
    global_shiva_threshold = shiva_threshold
    global_sa_threshold = sa_threshold
    
    backend_operations.save_learning_report(classifier_status, spamassassin_status, shiva_threshold, sa_threshold)
    
    free_learning_lock()

def __learn_classifier():
    """
    check if results can be read directly from database or 
    deep relearning is needed
    """
    
    if not backend_operations.check_stored_rules_results_integrity():
        logging.info('DEEP RELEARN')
        __deep_relearn()
        
    
    
    learning_matrix = statistics.prepare_matrix()
    
    # see statistics.prepare_matrix()
    sample_vectors = map(lambda a: a[1:], learning_matrix[1:])
    result_vector = map(lambda a: a[0], learning_matrix[1:])

    if not sample_vectors or not result_vector:
        #nothing to - no mails database?
        return True
    
    # create classifier and fit it with samples
    classifier = tree.DecisionTreeClassifier(min_samples_leaf=10,max_depth=8,class_weight='balanced',criterion='gini')
    classifier.fit(sample_vectors, result_vector)
    
    global global_classifier
    global_classifier = classifier
    
    # store classifier to picke file
    f = open(CLASSIFIER_PKL, 'wb')
    pickle.dump(classifier, f, pickle.HIGHEST_PROTOCOL)
    f.close()
    
    logging.info("Learning: Learning of classifier successfully finished.")
    return True

    

def __learn_spamassassin():
    """
    learn spamassassin Bayes filter on captured emails
    return False if error occurs, True otherwise
    
    NOTE: in this context, spamassassin term 'spam' is equal to phishing and 'ham' to regular spam
    """
    import subprocess,fnmatch,shlex
    
    logging.info('Learning - re-learning spamassassin.')
    try:
        retval = subprocess.call(shlex.split('spamc -K'))
        if retval != 0:
            logging.error('Learning: spamassassin daemon isn\'t running, exiting')
            return
    except subprocess.CalledProcessError:
        logging.error('Learning: error occered during communication with spamassassin daemon.')
        return
    
    rawspampath = lamson.server.shivaconf.get('analyzer', 'rawspampath')
        
    phishing_mail_path = rawspampath + "phishing/"
    phishing_mail_count = len(fnmatch.filter(os.listdir(phishing_mail_path), '*'))
    phishing_learn_cmd = 'sa-learn --spam ' + phishing_mail_path + '*'
    
    spam_mail_path = rawspampath + "spam/"
    spam_mail_count = len(fnmatch.filter(os.listdir(spam_mail_path), '*'))
    spam_learn_cmd = 'sa-learn --ham ' + spam_mail_path + '*'
    
    try:
        logging.info('Learning: dropping old spamassassin database.')
        retval = subprocess.call(shlex.split('sa-learn --clear'))
        
        logging.info('Learning: learning spamassassin Bayes filter on {} PHISHING emails in {}.'.format(phishing_mail_count, phishing_mail_path))
        retval += subprocess.call(shlex.split(phishing_learn_cmd))
        
        logging.info('Learning: learning spamassassin Bayes filter on {} SPAM emails in {}.'.format(spam_mail_count, spam_mail_path))
        retval += subprocess.call(shlex.split(spam_learn_cmd))
        
        if retval == 0:
            logging.info('Learning: spamassassin successfully learned.')
        else:
            logging.error('Learning: error occurred during spamassassin learnig process.')
        
    except subprocess.CalledProcessError as ex:
        logging.error('Learning: error occurred during communication with spamassassin daemon.')
        logging.error(ex)
        return False
    return True
    
    
def get_spamassassin_bayes_score(mailFields):
    """
    return score [0.00, 1.00] of given mail from spamassassin Bayes filter, 
    if error occurs, 0 is returned
    """ 
    import subprocess,shlex,re
    
    result = 0.00
    
    for currentKey in ('text','html'):
        
        if not mailFields[currentKey]:
            continue
        
        p = subprocess.Popen(shlex.split('spamc --full'),stdin=subprocess.PIPE,stdout=subprocess.PIPE)
        spamassassin_output = p.communicate(input=mailFields[currentKey])[0] 
         
        match_bayes = re.search('BAYES_\d\d.*\n.*score:\s+\d+\.\d+]', spamassassin_output)
        if match_bayes:
            match_score = re.search('\d+\.\d+]',match_bayes.group(0))
            score = float(match_score.group(0)[:-1])
            result = score if score > result else result

    return result
    
def check_mail(mailFields):
    """ 
    return computed probability and decision whether email should be considered as phishing
    
    dict {
      verdict: True/False
      urlPhishing: True/False
      shiva_prob: float
      sa_prob: float
    }
    
    """
    __init_classifier()
    global global_classifier
    global global_shiva_threshold
    global global_sa_threshold
    
    
    mailVector = process_single_record(mailFields)
    logging.critical(mailVector)
    
    shiva_prob = global_classifier.predict_proba((mailVector,))[0][1]
    sa_prob = get_spamassassin_bayes_score(mailFields)
    
    
    
    url_phishing = check_url_phishing(mailFields)
    
    result = {'verdict' : url_phishing or shiva_prob >= global_shiva_threshold or sa_prob >= global_sa_threshold,
              'urlPhishing' : url_phishing,
              'shiva_prob' : shiva_prob,
              'sa_prob' : sa_prob }
    logging.info('VERDICT: ' + str(result))
    
    return result

def process_single_record(mailFields):
    """
    applies all phishing rules on email and returns list of results sorted by code of rule
    """
    
    from phishing import rulelist
    used_rules = []
    computed_results = []
    result = []
    
    for rule in rulelist.get_rules():
        rule_result = rule.apply_rule(mailFields)
        rule_code = rule.get_rule_code()
        result.append({'code': rule_code, 'result': rule_result})
        used_rules.append({'code': rule_code, 'description': rule.get_rule_description()})
        
        db_result = rule_result
        
        
        computed_results.append({'spamId': mailFields['s_id'], 'code': rule.code ,'result': db_result})
        
    # store result of email to database    
    backend_operations.store_computed_results(computed_results, used_rules)    
    
    # sort result by rule code in order to ensure order
    sorted_rules = sorted(result,key=lambda a: a['code'])
    
    # extract numerical values for sorted_result_vector
    sorted_result_vector = map(lambda a: a['result'],sorted_rules)

    return sorted_result_vector


def __deep_relearn():
    """
    drops all computed results in database a computes everything again
    
    essential in case of adding new detection rules to honeypot
    """
    backend_operations.init_deep_relearn()
    rercord_count = 0
    
    while True:
        records = backend_operations.retrieve(10, rercord_count)
        if len(records) == 0 :
            break
        for record in records:
            process_single_record(record)
            rercord_count += 1

def __check_learning_and_lock():
    """ 
    check whether learning can be performed - existence of file LEARNING_LOCK
    if file doesn't exist it's created ant True is returned. If file already exists,
    it remains untouched and False is returned.
    """
    
    import os.path
    if os.path.exists(LEARNING_LOCK):
        return False
    
    open(LEARNING_LOCK, 'a').close()
    return True    
    
def __compute_classifier_decision_tresholds():
    """
    compute optimal thresholds for marking emails as phishing
    using F1 function
    
    threashold is value between 0.4 and 0.6
    
    return tuple (shiva_threshold,spamassasin_threshold)
    """
    classification_results = backend_operations.get_detection_results_for_thresholds()
    
    # no reason to shift shiva score when KNN classifier is used
    shiva_thres = .5
    
    default_result = (shiva_thres,.5,)
    
    # return default if there are suitable emails
    if not classification_results:
        return (default_result)
    
    expected_results = []
    for line in classification_results:
        if line[3] != None:
            expected_results.append(line[3])
        else:
            expected_results.append(1 if line[2] == 1 else 0)
    
    best_thres_sa = 0.5 
    best_score_sa = 0.
    
    try:
        # go through possible thresholds and find best suitable threshold for spamassassin classifier
        for i in range(40, 60, 1):
            current_thres =  i / 100.0
            
            sa_result = map(lambda a: 1 if a[1] > current_thres else 0, classification_results)
            
            # don't compute f1_score if we have all zeroes or ones
            if all(sa_result) or not any(sa_result):
                continue
           
            sa_score = f1_score(expected_results, sa_result, average='binary')
    
            if best_score_sa <= sa_score:
                best_score_sa = sa_score
                best_thres_sa = current_thres

        return (shiva_thres, best_thres_sa,)
    
    except Exception, e:
        logging.error(e)
        
    # return default thresholds if error occurs
    return default_result

    
def free_learning_lock():
    """
    delete fiLe LEARNING_LOCK if exits
    WARNING:
    should be used only during restarting of honeypot in order to recover from error
    """
    if os.path.exists(LEARNING_LOCK):
        os.remove(LEARNING_LOCK)