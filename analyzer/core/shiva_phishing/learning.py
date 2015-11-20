import pickle
import logging
import os

from sklearn.neighbors import KNeighborsClassifier

import lamson.server
import backend_operations
import shivastatistics

from lamson.shiva_phishing.phishing import has_blacklisted_url

# files used by module
CLASSIFIER_PKL = 'run/classifier.pkl'
BOOST_VECTOR_PKL = 'run/local_boost_vector.pkl'
LEARNING_LOCK = 'run/learning.lock'


#global variables
boost_vector = None
classifier = None
global_shiva_threshold = 0.5
global_sa_threshold = 0.5

def __init_classifier():
    """ 
    initialize classifier
    
    loads stored classifier from pickle file if exists,
    otherwise is performs learning
    """
    
    global classifier
    global boost_vector
    global global_shiva_threshold
    global global_sa_threshold
    
    if classifier and boost_vector:
        return
    
    
    global_shiva_threshold, global_sa_threshold = backend_operations.get_current_detection_thresholds()
    logging.info("Learning: Loaded thresholds: {0} {1}".format(global_shiva_threshold,global_sa_threshold))
    
    logging.info("Learning: Trying to load classifier from file.")
    if os.path.exists(CLASSIFIER_PKL):
        classifier_file = open(CLASSIFIER_PKL,'rb')
        if classifier_file:
            classifier = pickle.load(classifier_file)
            classifier_file.close()
            
    if os.path.exists(BOOST_VECTOR_PKL):
        boost_vector_file = open(BOOST_VECTOR_PKL,'rb')
        if boost_vector_file:
            boost_vector = pickle.load(boost_vector_file)
            boost_vector_file.close()
        
    if boost_vector:
        logging.info("Learning: Boost vector successfully loaded.")
        
    
    if classifier:
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
    
    global  global_shiva_threshold
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
        
    
    
    learning_matrix = shivastatistics.prepare_matrix()
    
    # see shivastatistics.prepare_matrix()
    keys_vector = learning_matrix[0][1:]
    local_boost_vector = learning_matrix[1][1:]
    sample_vectors = map(lambda a: a[1:], learning_matrix[2:])
    result_vector = map(lambda a: a[0], learning_matrix[2:])
    
    # compute new boost vector from current state of honeypot
    local_boost_vector = __compute_new_chi2_boost_vector(sample_vectors,result_vector, local_boost_vector)
    logging.critical('BOOST:' + str(local_boost_vector))

    if not sample_vectors or not result_vector:
        #nothing to - no mails database?
        return True
    
    # boost samples with boost vector
    for i in range(0,len(sample_vectors)):
        for j in range(0,len(sample_vectors[i])):
            if sample_vectors[i][j] > 0:
                sample_vectors[i][j] =  sample_vectors[i][j]  * local_boost_vector[j]
      
#     logging.critical(str(sample_vectors))
    
    classifier = KNeighborsClassifier(weights='distance',n_neighbors=15)
 
    classifier.fit(sample_vectors, result_vector)

    f = open(CLASSIFIER_PKL, 'wb')
    pickle.dump(classifier, f, pickle.HIGHEST_PROTOCOL)
    f.close()
    
    f = open(BOOST_VECTOR_PKL, 'wb')
    global boost_vector
    boost_vector = dict(zip(keys_vector, local_boost_vector)) 
    pickle.dump(boost_vector, f, pickle.HIGHEST_PROTOCOL)
    
    f.close()
    
    
    logging.info("Learning: Learning of classifier successfully finished.")
    logging.info(classifier)
    return True

    

def __learn_spamassassin():
    """
    learn spamassassin Bayes filter on captured emails
    return False if error occurs, True otherwise
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
        return False
    return True
    
    
def get_spamassassin_bayes_score(mailFields):
    """
    return score [0.00, 1.00] of given mail from spamassassin Bayes filter
    """ 
    import subprocess,shlex,re
    
    result = 0.00
    
    for currentKey in ('text','html'):
        
        if not mailFields[currentKey]:
            continue
        
        """ TODO check communication with spamassassin daemon"""
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
      blacklisted: True/False
      shiva_prob: float
      sa_prob: float
    }
    
    """
    __init_classifier()
    global classifier
    global global_shiva_threshold
    global global_sa_threshold
    
    
    mailVector = process_single_record(mailFields)
    logging.critical(mailVector)
    
    
    shiva_prob = classifier.predict_proba(mailVector)[0][1]
    sa_prob = get_spamassassin_bayes_score(mailFields)
    
    is_blacklisted = has_blacklisted_url(mailFields)
    
    result = {'verdict' : is_blacklisted or shiva_prob >= global_shiva_threshold or sa_prob >= global_sa_threshold,
              'blacklisted' : is_blacklisted,
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
    
    global boost_vector 
    
    for rule in rulelist.get_rules():
        rule_result = rule.apply_rule(mailFields)
        rule_code = rule.get_rule_code()
        rule_boost = rule.get_rule_boost_factor() if (not boost_vector or rule_code not in boost_vector) else boost_vector[rule_code]
        
        result.append({'code': rule_code, 'result': rule_result, 'boost':rule_boost})
        used_rules.append({'code': rule_code, 'boost': rule_boost, 'description': rule.get_rule_description()})
        
        db_result = rule_result
        if rule_result > 1 or rule_result < -1:
            # if score does't belong to interval (-1,1)
            # it was boosted for sure and therefore rule passed
            # this solves problems with negative boosting  
            db_result = 1
        
        
        computed_results.append({'spamId': mailFields['s_id'], 'code': rule.code ,'result': db_result})
        
    # store result of email to database    
    backend_operations.store_computed_results(computed_results, used_rules)    
    
    # return list of results sorted by rule code
    sorted_rules = sorted(result,key=lambda a: a['code'])
    
    # apply boost vector on computed results,
    # but only on positive ones
    sorted_result_vector = map(lambda a: a['result'],sorted_rules)
    sorted_boost_vector = map(lambda a: a['boost'],sorted_rules)

    return [x * y if x > 0 else x for x, y in zip(sorted_result_vector,sorted_boost_vector)]


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
    if file doesn't exist it's craeted ant True is returned. If file already exists,
    it remains untouched and False is returned.
    """
    
    import os.path
    if os.path.exists(LEARNING_LOCK):
        return False
    
    open(LEARNING_LOCK, 'a').close()
    return True

def __compute_new_chi2_boost_vector(sample_vectors=[],result_vector=[],former_boost_vector=[]):
    """
    compute chi2 boost vector for next learning
    
    sample_vectors = list of lists of samples
    result_vectors = list of results
    former_boost_vector = list of boost factors
    
    It must hold:
    len(sample_vectors[i]) == len(former_boost_vector)
    len(sample_vectors == len(results)
    
    if condition doesn't hold or other problem occurs, formem_boost_vector is returned
    """
    
    from sklearn.feature_selection import chi2
    from math import ceil,isnan
    from operator import and_
    
    required_len = len(former_boost_vector)
    
    # every vector of samples must have exactly same length as vector of results
    if not reduce(and_, map(lambda a: len(a) == required_len, sample_vectors)):
        return former_boost_vector
    
    if not len(result_vector) == len(sample_vectors):
        return former_boost_vector
    
    score = chi2(map(lambda a: map(lambda b: b if b > 0 else 0, a),sample_vectors), result_vector)
    
    chi2_boost_vector = []
    for i in range(0,len(score[0])):
        current_chi2_score = ceil(score[0][i]) if not isnan(score[0][i]) else .0
        
        # ensure keeping negative boost
        if former_boost_vector[i] < 0:
            current_chi2_score *= -1
        chi2_boost_vector.append(current_chi2_score)
        
    return chi2_boost_vector
    
    
def __compute_classifier_decision_tresholds():
    """
    compute optimal thresholds for marking emails as phishing
    """
    from sklearn.metrics import f1_score
    classification_results = backend_operations.get_detection_results_for_thresholds()
    
    default_result = (.5,.5,)
    
    # return default if there are suitable emails
    if not classification_results:
        return (default_result)
    
    expected_results = []
    for line in classification_results:
        if line[3] != None:
            expected_results.append(line[3])
        else:
            expected_results.append(1 if line[2] == 1 else 0)

    best_thres_shiva = 0.
    best_score_shiva = 0.
    
    best_thres_sa = 0. 
    best_score_sa = 0.
    
    try:
        # go through possible thresholds and find best suitable threshold for each classifier
        for i in range(5, 100, 5):
            current_thres =  i / 100.0
            
            shiva_result = map(lambda a: 1 if a[0] > current_thres else 0, classification_results)
            sa_result = map(lambda a: 1 if a[1] > current_thres else 0, classification_results)
           
            shiva_score = f1_score(expected_results, shiva_result, average='binary')
            sa_score = f1_score(expected_results, sa_result, average='binary')
    
            
            if best_score_shiva <= shiva_score:
                best_score_shiva = shiva_score
                best_thres_shiva = current_thres
            if best_score_sa <= sa_score:
                best_score_sa = sa_score
                best_thres_sa = current_thres

        return (best_thres_shiva, best_thres_sa,)
    
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