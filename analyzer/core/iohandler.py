import socket
import os
import threading
import logging

import re

from shivastatistics import generate_statistics
import learning

# FIXME
SOCKET_NAME = "/tmp/shivaio.socket"

def main():
    """Start another thread and listen on socket"""
    t = threading.Thread(target=SocketListener)
    t.start()


def SocketListener():
    logging.info("Starting INPUT listener thread.")
    if os.path.exists(SOCKET_NAME):
        os.remove(SOCKET_NAME)
        
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    
    try:
        s.bind(SOCKET_NAME)
    except socket.error as msg:
        logging.error('Bind failed. Error Code : ' + str(msg[0]) + ' Message ' + msg[1])
        return
    
    s.listen(10) 
    while True:
        conn,addr = s.accept()
        content =  conn.recv(256)
        logging.info(content)
        
        content = content.strip()
        if re.match('^generate_stats$', content):
            logging.info("Generate stats called")
            generate_statistics()
            continue
        
        if re.match('^generate_stats_phish$', content):
            logging.info("IO: Generate stats filterType = 'phish' called")
            generate_statistics(filterType="phish")
            continue
    
        if re.match('^generate_stats_spam$', content):
            logging.info("IO: Generate stats filterType = 'spam' called")
            generate_statistics(filterType="spam")
            continue
        
        if re.match('^learn$', content):
            logging.info("IO: Learning from stored emails")
            learning.learn()
            continue
        
        if re.match('^learn_spamassassin$', content):
            logging.info("IO: Learning spamassassin Bayes filter")
            learning.learn_spamassassin()
            continue
        
        logging.info("IO: NO action selected.")
    
    

    

