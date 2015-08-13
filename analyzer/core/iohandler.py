import logging

import re

from shivastatistics import generate_statistics
import learning




def handle_api_request(json_request):
    
    if not json_request or not json_request.has_key('action'):
        return False
    
    action = json_request['action']
    
    if re.match('^generate_stats$', action):
        logging.info("Generate stats called")
        generate_statistics()
        return True
    
    if re.match('^generate_stats_phish$', action):
        logging.info("IO: Generate stats filterType = 'phish' called")
        generate_statistics(filterType="phish")
        return True

    if re.match('^generate_stats_spam$', action):
        logging.info("IO: Generate stats filterType = 'spam' called")
        generate_statistics(filterType="spam")
        return True
    
    if re.match('^learn$', action):
        logging.info("IO: Learning from stored emails")
        learning.learn()
        return True
    
    if re.match('^learn_spamassassin$', action):
        logging.info("IO: Learning spamassassin Bayes filter")
        learning.learn_spamassassin()
        return True
    
    
    logging.info("IO: NO action selected.")
    return False
    
    

    

