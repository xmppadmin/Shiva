import pickle
import logging

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
        logging.info("Learning: Classifier not found, re-learning...")
        learn()
    
        

def learn():
    learning_matrix = shivastatistics.prepare_matrix(filterType='none', matrixType='learning')
    weights = learning_matrix[0]
    """ remove phishing indicator
        NOTE: not needed when classes weights works as expected
    """
    samples = map(lambda a: a[1:], learning_matrix[1:])
    results = map(lambda a: a[0],  learning_matrix[1:])
    print results
    
#     logging.info("LERNING: weights: " + str(len(weights)))
#     logging.info("LERNING: results: " + str(len(results[0])))
#     logging.info("LERNING: samples: " + str(len(samples[0])))
    
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

    

        
    
def check_mail(mailFields):
    """ 
    return computed probability that given mail should be marked as phishing
    
    """
    init_classifier()
    global classifier
    mailVector = shivastatistics.process_single_record(mailFields)
    result = classifier.predict_proba(mailVector[1:])
    return result[0][1]