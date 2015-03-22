import signal
import logging
import re

import matplotlib.pyplot as plot
import numpy as np

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

class ContainsUrlRule(MailClassificationRule):
    def __init__(self):
        self.rulename = "contain URL"
        
    def apply_rule(self, mailFields):
        return 1 if len(mailFields['links']) > 0  else 0


class ContainsImageAttachmentRule(MailClassificationRule):
    def __init__(self):
        self.rulename = "contain image"
        
    def apply_rule(self, mailFields):
        for suffix in mailFields['attachmentFileType']:
            if re.match(r".*(jpg|jpeg|png|gif|swf)$", suffix, re.IGNORECASE):
                return 1
        return 0

class ContainsExecutableAttachmentRule(MailClassificationRule):
    def __init__(self):
        self.rulename = "contain exec file"
        
    def apply_rule(self, mailFields):
        for suffix in mailFields['attachmentFileType']:
            if re.match(r".*(sh|exe)$", suffix, re.IGNORECASE):
                return 1
        return 0

class ContainsDocumentAttachmentRule(MailClassificationRule):
    def __init__(self):
        self.rulename = "contain document"
        
    def apply_rule(self, mailFields):
        for suffix in mailFields['attachmentFileType']:
            if re.match(r".*(doc|docx|pdf)$", suffix, re.IGNORECASE):
                return 1
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
            result.append(rule.apply_rule(mailFields))  
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
rulelist.add_rule(ContainsImageAttachmentRule())
rulelist.add_rule(ContainsExecutableAttachmentRule())
rulelist.add_rule(ContainsDocumentAttachmentRule())
rulelist.add_rule(ContainsUrlRule())


def main():
    logging.info("[+]Inside shivastatistics Module")
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
    statmatrixunique = []
    statmatrix.append(rulelist.get_rule_names())
    statmatrixunique.append(rulelist.get_rule_names())
    recordcount = 0
    while True:
        records = shivamaindb.retrieve(10, recordcount)
        if len(records) == 0 :
            break
        
        for record in records:
            recordcount += 1
            
            recordresult = process_single_record(record)
            
            """determinate how many times was email caught"""
            try:
                occurences = int(record['totalCounter'])
            except ValueError:
                occurences = 1
            
            statmatrixunique.append(recordresult)
            for i in range(1, occurences):
                statmatrix.append(recordresult)
                
        
    
#     outfile = open("stat_file.csv", "w")
#     for row in statmatrix:
#         outfile.write(join(row, ","))
#         outfile.write("\n")
#     
#     outfile.close()
    

    output_graphs(statmatrix)
    output_graphs(statmatrixunique, unique=True)
    
            
def process_single_record(mailFields):
    return rulelist.apply_rules(mailFields)

def output_graphs(statmatrix, unique=False):
    aggregated = aggregate_statistics(statmatrix)
    arr = np.arange(len(statmatrix[0]))
    barwidth = 0.35
    bars = plot.bar(arr, aggregated)
    plot.xticks(arr + barwidth, arr)
    
    colors = 'rgkymcb'
    for i in range(0,len(arr)):
        bars[i].set_color(colors[i % 7])
        
    ax = plot.subplot(111)
    box = ax.get_position()
    ax.set_position([box.x0, box.y0, box.width * 0.7, box.height])

    # Put a legend to the right of the current axis
#     ax.legend(loc='center left', bbox_to_anchor=(1, 0.5))
    """TODO dynamic scaling"""
    """TODO load settings from configuration files"""
    plot.figlegend(bars, statmatrix[0], 'center right')
    title =  'Statistics of ' + str(len(statmatrix) -1)
    outfile = 'plot'
    if unique:
        outfile += '-unique'
        title += ' unique '
    title += ' emails'
    outfile += '.png'
    plot.title(title)
    plot.savefig(outfile)
    plot.close()
    
def aggregate_statistics(statmatrix):
    aggregated = list();
    for i in range(0,len(statmatrix[0])):
        aggregated.append(0);
    
    for row in range(1, len(statmatrix)):
        for column in range(0, len(statmatrix[i])):
            aggregated[column] += statmatrix[row][column]
    
    return aggregated
         
            
    
        

