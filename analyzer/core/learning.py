import pickle
import logging
import server
import os

from sklearn import svm


import shivamaindb
import shivastatistics
from sklearn.tree.tree import DecisionTreeClassifier



CLASSIFIER_PKL = 'run/classifier.pkl'
LEARNING_LOCK = 'run/learning.lock'
classifier = None

def __init_classifier():
    """ 
    initialize classifier
    
    loads stored classifier from pickle file if exists,
    otherwise is performs learning
    """
    
    global classifier
    if classifier:
        return
    
    logging.info(os.getcwd())
    logging.info("Learning: Trying to load classifier from file.")
    if os.path.exists(CLASSIFIER_PKL):
        classifier_file = open(CLASSIFIER_PKL,'rb')
        if classifier_file:
            classifier = pickle.load(classifier_file)
            classifier_file.close()
        
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
    
    shivamaindb.save_learning_report(classifier_status, spamassassin_status)
    
    free_learning_lock()

def __learn_classifier():
    
    
    # check iff results can be read directly from database or 
    # full relearning is needed

    if not shivamaindb.check_stored_rules_results_integrity():
        logging.info('DEEP RELEARN')
        __deep_relearn()
        
        
    
    learning_matrix = shivastatistics.prepare_matrix()
    
    # see shivastatistics.prepare_matrix()
    keys_vector = learning_matrix[0][1:]
    boost_vector = learning_matrix[1][1:]
    sample_vectors = map(lambda a: a[1:], learning_matrix[2:])
    result_vector = map(lambda a: a[0], learning_matrix[2:])

    boost_vector = __compute_new_chi2_boost_vector(sample_vectors,result_vector, boost_vector)
    logging.critical('BOOST:' + str(boost_vector))

    if not sample_vectors or not result_vector:
        #nothing to - no mails database?
        return True
    
    for i in range(0,len(sample_vectors)):
        for j in range(0,len(sample_vectors[i])):
            if sample_vectors[i][j] > 0:
                sample_vectors[i][j] =  sample_vectors[i][j]  * boost_vector[j]
#      
    logging.critical(str(sample_vectors))
     
    classifier = svm.SVC(C=1.0, 
                         cache_size=200, 
                         class_weight='auto', 
                         coef0=0.0, 
                         degree=3, 
                         gamma=0.5,
                         kernel='rbf',
                         max_iter=-1,
                         probability=True,
                         random_state=None,
                         shrinking=True,
                         tol=0.001,
                         verbose=False)
    from sklearn import tree
    classifier = DecisionTreeClassifier(max_features=10)
    
    from sklearn.neighbors import KNeighborsClassifier
    classifier = KNeighborsClassifier(weights='distance',n_neighbors=15)
 
    classifier.fit(sample_vectors, result_vector)

    f = open(CLASSIFIER_PKL, 'wb')
    pickle.dump(classifier, f, pickle.HIGHEST_PROTOCOL)
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
    
    rawspampath = server.shivaconf.get('analyzer', 'rawspampath')
        
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
    return computed probability that given mail should be marked as phishing
    
    """
    __init_classifier()
    global classifier
    mailVector = process_single_record(mailFields)
    logging.critical(mailVector)
    return (classifier.predict_proba(mailVector)[0][1],get_spamassassin_bayes_score(mailFields))

def process_single_record(mailFields):
    """
    applies all phishing rules on email and returns list of results sorted by code of rule
    """
    
    from phishing import rulelist
    used_rules = []
    computed_results = []
    result = []
    for rule in rulelist.get_rules():
        rule_result = rule.get_final_rule_score(mailFields)
        result.append({'code': rule.get_rule_code(), 'result': rule_result})
        used_rules.append({'code': rule.get_rule_code(), 'boost': rule.get_rule_boost_factor(), 'description': rule.get_rule_description()})
        
        db_result = rule_result
        if rule_result > 1 or rule_result < -1:
            # if score does't belong to interval (-1,1)
            # it was boosted for sure and therefore rule passed
            # this solves problems with negative boosting  
            db_result = 1
        
        
        computed_results.append({'spamId': mailFields['s_id'], 'code': rule.get_rule_code() ,'result': db_result})
        
    # stored result of email to database    
    shivamaindb.store_computed_results(computed_results,used_rules)
    
    # return list of results sorted by rule code
    sorted_rules = sorted(result,key=lambda a: a['code'])
    return [x * y if x > 0 else x for x, y in zip(map(lambda a: a['result'], sorted_rules), [0.0, 1.0, 0.0, 321.0, -86.0, 28.0, 0.0, 18.0, 155.0, 19.0, 106.0, 25.0, 93.0, 1.0, 25.0, 1.0, 67.0])]
#     return map(lambda a: a['result'], sorted_rules)

def __deep_relearn():
    """
    drops all computed results in database a computes everything again
    
    essential in case of adding new detection rules to honeypot
    """
    shivamaindb.init_deep_relearn()
    rercord_count = 0
    
    while True:
        records = shivamaindb.retrieve(10, rercord_count)
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
    logging.info(str(sample_vectors))
    logging.info(result_vector)
    
    # every vector of samples must have exactly same length as vector of results
    if not reduce(and_, map(lambda a: len(a) == required_len, sample_vectors)):
        logging.error('critical 1')
        return former_boost_vector
    
    if not len(result_vector) == len(sample_vectors):
        logging.error('critical 2')
        return former_boost_vector
    
    score =  chi2(map(lambda a: map(lambda b: b if b > 0 else 0, a),sample_vectors), result_vector)
    
    chi2_boost_vector = []
    for i in range(0,len(score[0])):
        current_chi2_score = ceil(score[0][i]) if not isnan(score[0][i]) else .0
#         if boost_vector[i] == 0:
#             current_chi2_score = 0;
        # ensure keeping of negative boost
        if former_boost_vector[i] < 0:
            current_chi2_score *= -1
        chi2_boost_vector.append(current_chi2_score)
        
    return chi2_boost_vector
    
    
def __compute_classifier_decision_treshold():
    """
    compute threshold for marking email as phishing
    """
    base_threshold = .5

    
   
    
    
def free_learning_lock():
    """
    delete fiLe LEARNING_LOCK if exits
    WARNING:
    should be used only during restarting of honeypot in order to recover from error
    """
    if os.path.exists(LEARNING_LOCK):
        os.remove(LEARNING_LOCK)