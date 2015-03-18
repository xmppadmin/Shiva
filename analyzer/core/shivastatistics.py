import signal
import logging

import shivamaindb

def main():
    """register asynchronous signal handler"""
    signal.signal(signal.SIGUSR2, signal_handler)

def signal_handler(signum, frame): 
    generatestatistics()
    
def generatestatistics():
    recordcount = 0
    while True:
        records = shivamaindb.retrieve(10, recordcount)
        if len(records) == 0 :
            break
        
        for record in records:
            recordcount += 1
            process_single_record(record)
            
            
def process_single_record(record):
    logging.info(str(record))
     
     


        