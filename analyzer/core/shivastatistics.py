import signal
import logging
import re

import matplotlib.pyplot as plot
import numpy as np

import shivamaindb

from bs4 import BeautifulSoup
TLD_LIST = ['abb','abbott','abogado','ac','academy','accenture','accountant','accountants','active','actor','ad','ads','adult','ae','aero','af','afl','ag',
'agency','ai','aig','airforce','al','allfinanz','alsace','am','amsterdam','an','android','ao','apartments','aq','aquarelle','ar','archi','army','arpa','as',
'asia','associates','at','attorney','au','auction','audio','auto','autos','aw','ax','axa','az','ba','band','bank','bar','barclaycard','barclays','bargains',
'bauhaus','bayern','bb','bbc','bd','be','beer','berlin','best','bf','bg','bh','bi','bid','bike','bingo','bio','biz','bj','black','blackfriday','bloomberg',
'blue','bm','bmw','bn','bnpparibas','bo','boats','bond','boo','boutique','br','bridgestone','broker','brother','brussels','bs','bt','budapest','build',
'builders','business','buzz','bv','bw','by','bz','bzh','ca','cab','cafe','cal','camera','camp','cancerresearch','canon','capetown','capital','caravan',
'cards','care','career','careers','cars','cartier','casa','cash','casino','cat','catering','cbn','cc','cd','center','ceo','cern','cf','cfa','cfd','cg','ch',
'channel','chat','cheap','chloe','christmas','chrome','church','ci','cisco','citic','city','ck','cl','claims','cleaning','click','clinic','clothing','club',
'cm','cn','co','coach','codes','coffee','college','cologne','com','community','company','computer','condos','construction','consulting','contractors','cooking',
'cool','coop','corsica','country','coupons','courses','cr','credit','creditcard','cricket','crs','cruises','cu','cuisinella','cv','cw','cx','cy','cymru','cyou',
'cz','dabur','dad','dance','date','dating','datsun','day','dclk','de','deals','degree','delivery','democrat','dental','dentist','desi','design','dev','diamonds',
'diet','digital','direct','directory','discount','dj','dk','dm','dnp','do','docs','dog','doha','domains','doosan','download','durban','dvag','dz','earth','eat',
'ec','edu','education','ee','eg','email','emerck','energy','engineer','engineering','enterprises','epson','equipment','er','erni','es','esq','estate','et','eu',
'eurovision','eus','events','everbank','exchange','expert','exposed','express','fail','faith','fan','fans','farm','fashion','feedback','fi','film','finance',
'financial','firmdale','fish','fishing','fit','fitness','fj','fk','flights','florist','flowers','flsmidth','fly','fm','fo','foo','football','forex','forsale',
'foundation','fr','frl','frogans','fund','furniture','futbol','fyi','ga','gal','gallery','garden','gb','gbiz','gd','gdn','ge','gent','gf','gg','ggee','gh',
'gi','gift','gifts','gives','gl','glass','gle','global','globo','gm','gmail','gmo','gmx','gn','gold','goldpoint','golf','goo','goog','google','gop','gov',
'gp','gq','gr','graphics','gratis','green','gripe','gs','gt','gu','guge','guide','guitars','guru','gw','gy','hamburg','hangout','haus','healthcare','help',
'here','hermes','hiphop','hitachi','hiv','hk','hm','hn','hockey','holdings','holiday','homes','honda','horse','host','hosting','house','how','hr','ht','hu',
'ibm','icbc','icu','id','ie','ifm','il','im','immo','immobilien','in','industries','infiniti','info','ing','ink','institute','insure','int','international',
'investments','io','iq','ir','irish','is','it','iwc','java','jcb','je','jetzt','jewelry','jll','jm','jo','jobs','joburg','jp','juegos','kaufen','kddi','ke',
'kg','kh','ki','kim','kitchen','kiwi','km','kn','koeln','komatsu','kp','kr','krd','kred','kw','ky','kyoto','kz','la','lacaixa','land','lat','latrobe','lawyer',
'lb','lc','lds','lease','leclerc','legal','lgbt','li','liaison','lidl','life','lighting','limited','limo','link','lk','loan','loans','lol','london','lotte',
'lotto','love','lr','ls','lt','ltda','lu','lupin','luxe','luxury','lv','ly','ma','madrid','maif','maison','management','mango','market','marketing','markets',
'marriott','mba','mc','md','me','media','meet','melbourne','meme','memorial','men','menu','mg','mh','miami','mil','mini','mk','ml','mm','mma','mn','mo','mobi',
'moda','moe','monash','money','mormon','mortgage','moscow','motorcycles','mov','movie','mp','mq','mr','ms','mt','mtn','mtpc','mu','museum','mv','mw','mx','my',
'mz','na','nadex','nagoya','name','navy','nc','ne','nec','net','network','neustar','new','news','nexus','nf','ng','ngo','nhk','ni','nico','ninja','nissan','nl',
'no','np','nr','nra','nrw','ntt','nu','nyc','nz','okinawa','om','one','ong','onl','online','ooo','oracle','org','organic','osaka','otsuka','ovh','pa','page',
'panerai','paris','partners','parts','party','pe','pf','pg','ph','pharmacy','philips','photo','photography','photos','physio','piaget','pics','pictet','pictures',
'pink','pizza','pk','pl','place','plumbing','plus','pm','pn','pohl','poker','porn','post','pr','praxi','press','pro','prod','productions','prof','properties',
'property','ps','pt','pub','pw','py','qa','qpon','quebec','racing','re','realtor','recipes','red','redstone','rehab','reise','reisen','reit','ren','rent','rentals',
'repair','report','republican','rest','restaurant','review','reviews','rich','rio','rip','ro','rocks','rodeo','rs','rsvp','ru','ruhr','run','rw','ryukyu','sa',
'saarland','sale','samsung','sap','sarl','saxo','sb','sc','sca','scb','schmidt','scholarships','school','schule','schwarz','science','scot','sd','se','seat',
'sener','services','sew','sex','sexy','sg','sh','shiksha','shoes','show','shriram','si','singles','site','sj','sk','sky','sl','sm','sn','so','soccer','social',
'software','sohu','solar','solutions','sony','soy','space','spiegel','spreadbetting','sr','st','study','style','su','sucks','supplies','supply','support','surf',
'surgery','suzuki','sv','swiss','sx','sy','sydney','systems','sz','taipei','tatar','tattoo','tax','taxi','tc','td','team','tech','technology','tel','temasek',
'tennis','tf','tg','th','thd','theater','tickets','tienda','tips','tires','tirol','tj','tk','tl','tm','tn','to','today','tokyo','tools','top','toray','toshiba',
'tours','town','toys','tr','trade','trading','training','travel','trust','tt','tui','tv','tw','tz','ua','ug','uk','university','uno','uol','us','uy','uz','va',
'vacations','vc','ve','vegas','ventures','versicherung','vet','vg','vi','viajes','video','villas','vision','vlaanderen','vn','vodka','vote','voting','voto',
'voyage','vu','wales','wang','watch','webcam','website','wed','wedding','weir','wf','whoswho','wien','wiki','williamhill','win','wme','work','works','world',
'ws','wtc','wtf','xerox','xin','xn','xxx','xyz','yachts','yandex','ye','yodobashi','yoga','yokohama','youtube','yt','za','zip','zm','zone','zuerich','zw'];

URL_REGEX_PATTERN = re.compile(ur'(?i)\b((?:https?://|(www\d{0,3}[.])*|[a-z0-9.\-]+[.][a-z]{2,4}/)(?:[^\s()<>]+|\(([^\s()<>]+|(\([^\s()<>]+\)))*\))+(?:\(([^\s()<>]+|(\([^\s()<>]+\)))*\)|[^\s`!()\[\]{};:\'".,<>?\xab\xbb\u201c\u201d\u2018\u2019]))')
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

def extractalldomains(url):
    """extract all domains from given url"""
    urls = list()
    for match in re.findall(URL_DOMAIN_PATTERN, url):
        for tld in TLD_LIST:
            if match.endswith('.' + tld):
                urls.append(match)
    return urls

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
        self.rulename = "R1: Email contains URL"
        
    def apply_rule(self, mailFields):
        return 1 if len(mailFields['links']) > 0  else 0


class ContainsImageAttachmentRule(MailClassificationRule):
    def __init__(self):
        self.rulename = "R2: Email contains image"
        
    def apply_rule(self, mailFields):
        for suffix in mailFields['attachmentFileType']:
            if re.match(r".*(jpg|jpeg|png|gif|swf)$", suffix, re.IGNORECASE):
                return 1
        return 0

class ContainsExecutableAttachmentRule(MailClassificationRule):
    def __init__(self):
        self.rulename = "R3: Email contains executable attachment"
        
    def apply_rule(self, mailFields):
        for suffix in mailFields['attachmentFileType']:
            if re.match(r".*(sh|exe)$", suffix, re.IGNORECASE):
                return 1
        return 0

class ContainsDocumentAttachmentRule(MailClassificationRule):
    def __init__(self):
        self.rulename = "R4: Email contains document(doc,pdf)"
        
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
        self.rulename = "C1: Hyperlink with visible URL, pointing to different URL"
        
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
        self.rulename = "C2: Hyperlink with visible text pointing to IP based URL"
        
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
        self.rulename = "C3: Email body in HTML format"
        
    def apply_rule(self, mailFields):
        return True if mailFields['html'] else False

class RuleC5(MailClassificationRule):
    def __init__(self):
        self.rulename = "C5: Sender domain different from some URL in message body"
        
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
        self.rulename = "C6: Image with external domain different from URLs in email body"
        
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
        self.rulename = "C7: Image source is IP address"
        
    def apply_rule(self, mailFields):
        if not mailFields['html']:
            return 0
        soup = BeautifulSoup(mailFields['html'])
        for img_tag in soup.find_all('img'):
            src_ip = extractip(img_tag.get('src'))
            if src_ip:
                return 1
        return 0
    
class RuleC8(MailClassificationRule):
    def __init__(self):
        self.rulename = "C8: More than one domain in URL"
        
    def apply_rule(self, mailFields):
        if not mailFields['html']:
            return 0
        soup = BeautifulSoup(mailFields['html'])
        for a_tag in soup.find_all('a'):
            href = extractdomain(a_tag.get('href'))
            if len(extractalldomains(href)) > 1:
                return 1 
        return 0
            

class RuleC11(MailClassificationRule):
    def __init__(self):
        self.rulename = "C11: Visible text in hyperlink contains no information about destination"
        
    def apply_rule(self, mailFields):
        if not mailFields['html']:
            return 0
        soup = BeautifulSoup(mailFields['html'])
        for a_tag in soup.find_all('a'):
            href = extractdomain(a_tag.get('href'))
            text = extractdomain(a_tag.get_text())
            if (text):
                if (href):
                    return 0 if text.lower() == href.lower else 1
                else:
                    return 1
        return 0
        


    
"""setup rules"""
rulelist = MailClassificationRuleList()
rulelist.add_rule(ContainsUrlRule())
rulelist.add_rule(ContainsImageAttachmentRule())
rulelist.add_rule(ContainsExecutableAttachmentRule())
rulelist.add_rule(ContainsDocumentAttachmentRule())
rulelist.add_rule(RuleC1())
rulelist.add_rule(RuleC2())
rulelist.add_rule(RuleC3())
rulelist.add_rule(RuleC5())
rulelist.add_rule(RuleC6())
rulelist.add_rule(RuleC7())
rulelist.add_rule(RuleC8())
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
    
    plot.xticks(arr + barwidth, map(lambda a: a[:a.index(':')], statmatrix[0]))

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
         
            
    
        

