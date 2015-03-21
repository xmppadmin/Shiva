import signal
import logging

import shivamaindb
from string import join

class MailClassificationRule(object):
    def __init__(self):
        self.rulename = "base_rule"
    
    def get_rule_name(self):
        return self.rulename
    
    def apply_rule(self, mailFields):
        return 0
    
class Rule1(MailClassificationRule):
    def __init__(self):
        self.rulename = "sample_rule_1"
            
    def apply_rule(self, mailFields):
        return 1
    
class Rule0(MailClassificationRule):
    def __init__(self):
        self.rulename = "sample_rule_0"
        
    def apply_rule(self, mailFields):
        return 0
    
"""Class represents list of MailClassificationRules to be
   applied on mail
"""     
class MailClassificationRuleList(object):
    
    def __init__(self):
        self.rulelist = list()
    
    """
    Add rule to list
    rule - instance of MailClassificationRules
    """ 
    def add_rule(self, rule):
        if isinstance(rule, MailClassificationRule):
            self.rulelist.append(rule)
    
    """
    Apply all rules on given mailFields
    return - list of results
    """
    def apply_rules(self, mailFields):
        result = []
        for rule in self.rulelist:
            result.append(str(rule.apply_rule(mailFields)))  
        return result 
    
    """
    retrieve names of all rules
    """
    def get_rule_names(self):
        result = []
        for rule in self.rulelist:
            result.append(rule.get_rule_name())
        return result
        
    
    
    
"""setup rules"""
rulelist = MailClassificationRuleList()
rulelist.add_rule(Rule0())
rulelist.add_rule(Rule1())
rulelist.add_rule(Rule0())



def main():
    """register asynchronous signal handler"""
    signal.signal(signal.SIGUSR2, signal_handler)
    
    
def signal_handler(signum, frame): 
    generate_statistics()
    
"""
apply all MailClassificationRules from rulelist on
each mail in the database

"""
def generate_statistics():
    statmatrix = [];
    statmatrix.append(rulelist.get_rule_names())
    recordcount = 0
    while True:
        records = shivamaindb.retrieve(10, recordcount)
        if len(records) == 0 :
            break
        
        for record in records:
            recordcount += 1
            statmatrix.append(process_single_record(record))
    
    outfile = open("stat_file.csv", "w")
    for row in statmatrix:
        outfile.write(join(row, ","))
        outfile.write("\n")
    outfile.close()
            
def process_single_record(mailFields):
    return rulelist.apply_rules(mailFields)

    
        

