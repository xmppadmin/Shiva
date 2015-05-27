import signal
import logging
import re

import matplotlib.pyplot as plot
import numpy as np

import shivamaindb
from string import join

from bs4 import BeautifulSoup

URL_REGEX_PATTERN = re.compile(ur'(?i)\b((?:https?://|www\d{0,3}[.]|[a-z0-9.\-]+[.][a-z]{2,4}/)(?:[^\s()<>]+|\(([^\s()<>]+|(\([^\s()<>]+\)))*\))+(?:\(([^\s()<>]+|(\([^\s()<>]+\)))*\)|[^\s`!()\[\]{};:\'".,<>?\xab\xbb\u201c\u201d\u2018\u2019]))')
URL_IP_PATTERN = re.compile(ur'(?:\d{1,3}\.){3}\d{1,3}')
URL_DOMAIN_PATTERN = re.compile(ur'[a-z0-9.\-]+[.][a-z]{2,4}')

def extractdomain(url):
    """parse domain name from given url

    Keyword arguments:
    url - string
    """
    if not url:
        return ''
    m = re.match(URL_REGEX_PATTERN, url)
    if m:
        m = re.search(URL_DOMAIN_PATTERN, url)
        if m:
            return re.sub('^www\.', '', m.group())
    return ''

def extractip(url):
    """parse ip address given url

    Keyword arguments:
    url - string
    """
    if not url:
        return ''
    
    ips = re.findall(URL_IP_PATTERN, url)
    if len(ips) == 0:
        return ''
    ip = ips[0]
    
    domain = extractdomain(url)
    if not domain:
        return ip
    """check whether ip isn't part of query or params""" 
    return ip if url.find(ip) < url.find(domain) else '' 

def samedomain(url1, url2):
    if not url1 or not url2:
        return False
    
    url1_splitted = url1.split('.')
    url2_splitted = url2.split('.')
    min_length = min(len(url1_splitted), len(url2_splitted))
    if min_length < 2 :
        return False
    url1_splitted.reverse()
    url2_splitted.reverse()
    
    if (url1_splitted[0] != url2_splitted[0]) | (url1_splitted[1] != url2_splitted[1]):
        return False
    return True

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
        
class RuleC1(MailClassificationRule):
    def __init__(self):
        self.rulename = "C1"
        
    def apply_rule(self, mailFields):
        if not mailFields['html']:
            return 0
        soup = BeautifulSoup(mailFields['html'])
        for a_tag in soup.find_all('a'):
            href = extractdomain(a_tag.get('href'))
            text = extractdomain(a_tag.get_text())
            
            if not href or not text:
                return 0
            
            if not samedomain(href, text):
                return 1 
        return 0
    
class RuleC2(MailClassificationRule):
    def __init__(self):
        self.rulename = "C2"
        
    def apply_rule(self, mailFields):
        if not mailFields['html']:
            return 0
        soup = BeautifulSoup(mailFields['html'])
        for a_tag in soup.find_all('a'):
            text = a_tag.get_text()
            if not text:
                return 0
            
            href = extractdomain(a_tag.get('href'))
            href_split = href.split('.')
            matches = True
            for part in href_split:
                matches &= True if re.match(r'\d+', part) else False
           
            if matches & len(href_split) > 0:
                return 1
        return 0
    
class RuleC3(MailClassificationRule):
    def __init__(self):
        self.rulename = "C3"
        
    def apply_rule(self, mailFields):
        return True if mailFields['html'] else False

class RuleC5(MailClassificationRule):
    def __init__(self):
        self.rulename = "C5"
        
    def apply_rule(self, mailFields):
        if not mailFields['from'] or not mailFields['links']:
            return 0
        
        sender = mailFields['from'];
        sender_splitted = sender.split('@',2)
        if len(sender_splitted) < 2:
            return 0
        
        m = re.search(URL_DOMAIN_PATTERN, sender_splitted[1])
        if not m:
            return 0
        
        sender_domain = m.group()
        for url in mailFields['links']:
            if not samedomain(sender_domain, url):
                return 1
        return 0

class RuleC6(MailClassificationRule):
    def __init__(self):
        self.rulename = "C6"
        
    def apply_rule(self, mailFields):
        if not mailFields['html'] or not mailFields['links']:
            return 0
        
        domain_list = filter(lambda url: url, (map(extractdomain, mailFields['links'])))
        soup = BeautifulSoup(mailFields['html'])
        for img_tag in soup.find_all('img'):
            src_domain = extractdomain(img_tag.get('src'))
            if src_domain:
                retval = False
                for domain in domain_list:
                    if samedomain(src_domain, domain):
                        retval = True
                if not retval:
                    return 1
        return 0

class RuleC7(MailClassificationRule):
    def __init__(self):
        self.rulename = "C7"
        
    def apply_rule(self, mailFields):
        if not mailFields['html']:
            return 0
        soup = BeautifulSoup(mailFields['html'])
        for img_tag in soup.find_all('img'):
            src_ip = extractip(img_tag.get('src'))
            if src_ip:
                return 1
        return 0

class RuleC11(MailClassificationRule):
    def __init__(self):
        self.rulename = "C11"
        
    def apply_rule(self, mailFields):
        if not mailFields['html']:
            return 0
        soup = BeautifulSoup(mailFields['html'])
        for a_tag in soup.find_all('a'):
            href = extractdomain(a_tag.get('href'))
            text = extractdomain(a_tag.get_text())
            return 1 if (not text and href) else 0
        return 0
        


    
"""setup rules"""
rulelist = MailClassificationRuleList()
rulelist.add_rule(ContainsImageAttachmentRule())
rulelist.add_rule(ContainsExecutableAttachmentRule())
rulelist.add_rule(ContainsDocumentAttachmentRule())
rulelist.add_rule(ContainsUrlRule())
rulelist.add_rule(RuleC1())
rulelist.add_rule(RuleC2())
rulelist.add_rule(RuleC3())
rulelist.add_rule(RuleC5())
rulelist.add_rule(RuleC6())
rulelist.add_rule(RuleC7())
rulelist.add_rule(RuleC11())

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
        
    """TODO load settings from configuration files"""

    legend = plot.legend(bars, statmatrix[0], loc='upper center', bbox_to_anchor=(0.5,-0.1))
    title =  'SHIVA honeypot - statistics of ' + str(len(statmatrix) -1)
    outfile = 'plot'
    if unique:
        outfile += '-unique'
        title += ' unique '
    title += ' emails'
    outfile += '.png'
    plot.title(title)
    plot.savefig(outfile, bbox_extra_artists=(legend,), bbox_inches='tight')
    plot.close()
    
def aggregate_statistics(statmatrix):
    aggregated = list();
    for i in range(0,len(statmatrix[0])):
        aggregated.append(0);
    
    for row in range(1, len(statmatrix)):
        for column in range(0, len(statmatrix[i])):
            aggregated[column] += statmatrix[row][column]
    
    return aggregated
         
            
    
        

