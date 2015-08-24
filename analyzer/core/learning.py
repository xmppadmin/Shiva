import pickle
import logging
import server

from sklearn import svm

import shivastatistics



CLASSIFIER_PKL = 'classifier.pkl';
classifier = None

def init_classifier():
    """ 
    initialize classifier
    """
    global classifier
    if classifier:
        return
    
    logging.info("Learning: Trying to load classifier from file.")
    f = open(CLASSIFIER_PKL, 'rb')
    classifier = pickle.load(f)
    f.close()
    
    if classifier:
        logging.info("Learning: Classifier successfully loaded.")
    else:
        logging.info("Learning: Classifier not found, trying to re-learn...")
        learn()
    
        

def learn():
    learning_matrix = shivastatistics.prepare_matrix(filterType='none', matrixType='learning')
    weights = learning_matrix[0]
    """ remove phishing indicator
        NOTE: not needed when classes weights works as expected
    """
    samples = map(lambda a: a[1:], learning_matrix[1:])
    results = map(lambda a: a[0],  learning_matrix[1:])
    
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
    
    
    classifier.fit(samples, results)
    
    f = open(CLASSIFIER_PKL, 'wb')
    pickle.dump(classifier, f, pickle.HIGHEST_PROTOCOL)
    f.close()
    
    logging.info("Learning: Learning successfully finished.")

    

def learn_spamassassin():
    """ learn spamassassin Bayes filter on captured emails """
    import subprocess,os,fnmatch,shlex
    
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
            logging.error('Learning: error occered during spamassassin learnig process.')
        
    except subprocess.CalledProcessError as ex:
        logging.error('Learning: error occered during communication with spamassassin daemon.')
    
    
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
    init_classifier()
    global classifier
    mailVector = shivastatistics.process_single_record(mailFields)
    return (classifier.predict_proba(mailVector[1:])[0][1],get_spamassassin_bayes_score(mailFields))