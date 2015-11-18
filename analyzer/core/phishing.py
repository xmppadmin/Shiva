import re

from bs4 import BeautifulSoup
from string import split
import unicodedata


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


URL_REGEX_PATTERN = re.compile(ur'(?i)(https?:\/\/)?([\da-z@\.-]+)\.([a-z\.]{2,6})([\/\w \.-]*)*\/?')
URL_IP_PATTERN = re.compile(ur'(?:\d{1,3}\.){3}\d{1,3}')
URL_DOMAIN_PATTERN = re.compile(ur'[a-z0-9.\-]+[.][a-z]{2,4}')


#TODO load regexes from file
SUSPICIOUS_SUBJECT_REGEX_LIST = []
plain_regex = []
plain_regex.append('(?i)account')
plain_regex.append('(?i)update')
plain_regex.append('(?i)security')
plain_regex.append('(?i)secure')
plain_regex.append('(?i)ebay')
plain_regex.append('(?i)card')
plain_regex.append('(?i)bank')
plain_regex.append('(?i)verify')
plain_regex.append('(?i)valid')
plain_regex.append('(?i)visa')
plain_regex.append('(?i)confirm')
plain_regex.append('(?i)varovani')
plain_regex.append('(?i)nalehav')
plain_regex.append('(?i)dulez')
plain_regex.append('(?i)platn')
plain_regex.append('(?i)ukonceni')
plain_regex.append('(?i)\bend')
plain_regex.append('(?i)podezrel')
plain_regex.append('(?i)over')
plain_regex.append('(?i)naleh')
plain_regex.append('(?i)nezbyt')
plain_regex.append('(?i)webmail')
plain_regex.append('(?i)kone?c')



for current in plain_regex:
    SUSPICIOUS_SUBJECT_REGEX_LIST.append(re.compile(current))

COMMON_SPAM_SUBJECT_REGEX_LIST = []
plain_regex = []
plain_regex.append('(?i)conf\.')
plain_regex.append('(?i)conference')
plain_regex.append('(?i)transcript')
plain_regex.append('(?i)return')
plain_regex.append('(?i)scien')
plain_regex.append('(?i)nauc')
plain_regex.append('(?i)pouz')
plain_regex.append('(?i)posil')

for current in plain_regex:
    COMMON_SPAM_SUBJECT_REGEX_LIST.append(re.compile(current))

def extractdomain(url):
    """parse domain name from given url

    Keyword arguments:
    url - string
    """
    if not url:
        return ''
    
    m = re.match(URL_REGEX_PATTERN, url.strip())
    if m:
        m = re.search(URL_DOMAIN_PATTERN, url.strip())
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
    
    url1_splitted = url1.strip().split('.')
    url2_splitted = url2.strip().split('.')
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
    if not url:
        return urls
    
    for match in re.findall(URL_DOMAIN_PATTERN, url):
        for tld in TLD_LIST:
            if match.endswith('.' + tld):
                urls.append(re.sub('www\d{0,3}\.', '', match))
    return urls

def getfinalurls(url_info={}):
    """return list of urls from url_tuple. Unshortened Url is alwas prefered"""
    url_list = list()
    if not url_info:
        return url_list
    
    for current in url_info:
        url_list.append(current['raw_link'])
        if current['LongUrl']:
            url_list.append(current['LongUrl'])
    return url_list
        
def strip_accents(s):
    if isinstance(s, unicode):
        return ''.join(c for c in unicodedata.normalize('NFD', s) 
                   if unicodedata.category(c) != 'Mn')
        

    return ''.join(c for c in unicodedata.normalize('NFD', s.decode('utf8','replace')) 
                   if unicodedata.category(c) != 'Mn')



"""Class represents list of MailClassificationRules to be
   applied on mail
"""     
class MailClassificationRuleList(object):
    
    weight = 1
    
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
    
    def get_rules(self):
        return self.rulelist
    
    """
    retrieve names of all rules
    """
    def get_rule_names(self):
        result = []
        for rule in self.rulelist:
            result.append(rule.get_rule_description())
        return result
    """
    retrive vector of weights for rules in list
    """
    def get_vector_weigths(self):
        result = []
        for rule in self.rulelist:
            result.append(rule.weight)
        return result;
    
    


"""Generic classification rule"""
class MailClassificationRule(object):
    def __init__(self):
        self.description = "base_rule"
        self.weight = 1
    
    def get_rule_description(self):
        return self.description
    
    def get_rule_code(self):
        return self.code
    
    def get_rule_boost_factor(self):
        return self.weight
    
    def apply_rule(self, mailFields):
        return -1
    
    
    
    
class Rule1(MailClassificationRule):
    def __init__(self):
        self.code = 'S1'
        self.description = "sample_rule_1"
        self.weight = 1
            
    def apply_rule(self, mailFields):
        return 1
    
class Rule0(MailClassificationRule):
    def __init__(self):
        self.code = 'S0'
        self.description = "sample_rule_0"
        self.weight = 1
        
    def apply_rule(self, mailFields):
        return -1

class ContainsUrlRule(MailClassificationRule):
    def __init__(self):
        self.code = 'R1'
        self.description = "Email contains URL"
        self.weight = 14
        
    def apply_rule(self, mailFields):
        return 1 if len(mailFields['links']) > 0  else -1


class ContainsImageAttachmentRule(MailClassificationRule):
    def __init__(self):
        self.code = 'R2'
        self.description = "Email contains image"
        self.weight = 1
        
    def apply_rule(self, mailFields):
        if not mailFields.get('attachmentFileType'):
            return -1
        
        for suffix in mailFields['attachmentFileType']:
            if re.match(r".*(jpg|jpeg|png|gif|swf)$", suffix, re.IGNORECASE):
                return 1
        return -1

class ContainsExecutableAttachmentRule(MailClassificationRule):
    def __init__(self):
        self.code = 'R3'
        self.description = "Email contains executable attachment"
        self.weight = 2
        
    def apply_rule(self, mailFields):
        if not mailFields.get('attachmentFileType'):
            return -1
        for suffix in mailFields['attachmentFileType']:
            if re.match(r".*(sh|exe)$", suffix, re.IGNORECASE):
                return 1
        return -1

class ContainsDocumentAttachmentRule(MailClassificationRule):
    def __init__(self):
        self.code = 'R4'
        self.description = "Email contains document(doc,pdf)"
        self.weight = 1
        
    def apply_rule(self, mailFields):
        if not mailFields.get('attachmentFileType'):
            return -1
        for suffix in mailFields['attachmentFileType']:
            if re.match(r".*(doc|docx|pdf)$", suffix, re.IGNORECASE):
                return 1
        return -1

class HasShortenedUrl(MailClassificationRule):
    def __init__(self):
        self.code = 'R5'
        self.description = "At least one URL is shortened"
        self.weight = 36
        
    def apply_rule(self, mailFields):
        for url_info in mailFields['links']:
            if url_info['LongUrl']:
                return 1
        return -1

class PhischingHumanCheckRule(MailClassificationRule):
    def __init__(self):
        self.code = 'R6'
        self.description = "Marked as phishing by human"
        self.weight = 0
        
    def apply_rule(self, mailFields):
        if mailFields.get('phishingHumanCheck'):
            return 1
        return -1
        
class RuleC1(MailClassificationRule):
    def __init__(self):
        self.code = 'C1'
        self.description = "Hyperlink with visible URL, pointing to different URL"
        self.weight = 24
        
    def apply_rule(self, mailFields):
        if not 'html' in mailFields:
            return -1
        soup = BeautifulSoup(mailFields['html'], 'html.parser')
        for a_tag in soup.find_all('a'):
            href = extractdomain(a_tag.get('href'))
            text = extractdomain(a_tag.get_text())
            
            if not href or not text:
                continue
            
            if not samedomain(href, text):
                return 1 
        return -1
    
class RuleC2(MailClassificationRule):
    def __init__(self):
        self.code = 'C2'
        self.description = "Hyperlink with visible text pointing to IP based URL"
        self.weight = 80
        
    def apply_rule(self, mailFields):
        if not 'html' in mailFields:
            return -1
        soup = BeautifulSoup(mailFields['html'], 'html.parser')
        for a_tag in soup.find_all('a'):
            text = a_tag.get_text()
            if not text:
                continue
            
            if extractip(a_tag.get('href')):
                return 1
              
        return -1
    
class RuleC3(MailClassificationRule):
    def __init__(self):
        self.code = 'C3'
        self.description = "Email body in HTML format"
        self.weight = 11
        
    def apply_rule(self, mailFields):
        return 1 if mailFields['html'] else -1
    
class RuleC4(MailClassificationRule):
    def __init__(self):
        self.code = 'C4'
        self.description = "Too complicated URL"
        self.weight = 59
        
    def apply_rule(self, mailFields):
        if 'links' in mailFields:
            for link_info in mailFields['links']:
                if 'raw_link' in link_info and str(link_info['raw_link']).count('.') > 4:
                    return 1
        
        if not 'html' in mailFields:
            return -1
        
        soup = BeautifulSoup(mailFields['html'], 'html.parser')
        for a_tag in soup.find_all('a'):
            url = a_tag.get('href')
            if url and url.count('.') > 4:
                return 1
            
            url = a_tag.get_text()
            if url and url.count('.') > 4:
                return 1
        
        return -1
        
        

class RuleC5(MailClassificationRule):
    def __init__(self):
        self.code = 'C5'
        self.description = "Sender domain different from some URL in message body"
        self.weight = 15
        
    def apply_rule(self, mailFields):
        if not 'from' in mailFields or not 'links' in mailFields:
            return -1

        sender = mailFields['from'];
        sender_splitted = sender.split('@',2)
        if len(sender_splitted) < 2:
            return -1
        
        m = re.search(URL_DOMAIN_PATTERN, sender_splitted[1])
        if not m:
            return -1
        
        sender_domain = m.group()
        for url in getfinalurls(mailFields['links']):
            if not samedomain(sender_domain, url):
                return 1
        return -1

class RuleC6(MailClassificationRule):
    def __init__(self):
        self.code = 'C6'
        self.description = "Image with external domain different from URLs in email body"
        self.weight = 28
        
    def apply_rule(self, mailFields):
        if not 'html' in mailFields or not 'links' in mailFields:
            return -1
        
        domain_list = filter(lambda url: url, (map(extractdomain, getfinalurls(mailFields['links']))))
        soup = BeautifulSoup(mailFields['html'], 'html.parser')
        for img_tag in soup.find_all('img'):
            src_domain = extractdomain(img_tag.get('src'))
            if src_domain:
                for domain in domain_list:
                    if not samedomain(src_domain, domain):
                        return 1
        return -1

class RuleC7(MailClassificationRule):
    def __init__(self):
        self.code = 'C7'
        self.description = "Image source is IP address"
        self.weight = 2
        
    def apply_rule(self, mailFields):
        if not 'html' in mailFields:
            return -1
        soup = BeautifulSoup(mailFields['html'], 'html.parser')
        for img_tag in soup.find_all('img'):
            src_ip = extractip(img_tag.get('src'))
            if src_ip:
                return 1
        return -1
    
class RuleC8(MailClassificationRule):
    def __init__(self):
        self.code = 'C8'
        self.description = "More than one domain in URL"
        self.weight = 17
        
    def apply_rule(self, mailFields):
        if 'html' in mailFields:
            soup = BeautifulSoup(mailFields['html'], 'html.parser')
            for a_tag in soup.find_all('a'):
                if len(extractalldomains(a_tag.get('href'))) > 1:
                    return 1 
        
        if 'links' in mailFields:
            for link in getfinalurls(mailFields['links']):
                if len(extractalldomains(link)) > 1:
                    return 1
               
        return -1
            
class RuleC9(MailClassificationRule):
    def __init__(self):
        self.code = 'C9'
        self.description = "More than three subdomains in URL"
        self.weight = 1
        
    def apply_rule(self, mailFields):
        if 'html' in mailFields:
            soup = BeautifulSoup(mailFields['html'], 'html.parser')
            for a_tag in soup.find_all('a'):
                href = extractdomain(a_tag.get('href'))
                if href and not extractip(href) and len(split(extractdomain(href), '.')) > 4:
                    return 1
                
        if 'links' in mailFields:
            for link in getfinalurls(mailFields['links']):
                if not extractip(link) and len(split(extractdomain(link), '.')) > 4:
                    return 1
        
        return -1

class RuleC10(MailClassificationRule):
    def __init__(self):
        self.code = 'C10'
        self.description = "Hyperlink with image insted of visible text, image source is IP address"
        self.weight = 1
        
    def apply_rule(self, mailFields):
        if not 'html' in mailFields:
            return -1
        soup = BeautifulSoup(mailFields['html'], 'html.parser')
        for a_tag in soup.find_all('a'):
            for img in a_tag.find_all('img'):
                if extractip(img.get('src')):
                    return 1
        return -1

class RuleC11(MailClassificationRule):
    def __init__(self):
        self.code = 'C11'
        self.description = "Visible text in hyperlink contains no information about destination"
        self.weight = 13
        
    def apply_rule(self, mailFields):
        if not 'html' in mailFields:
            return -1
        soup = BeautifulSoup(mailFields['html'], 'html.parser')
        for a_tag in soup.find_all('a'):
            href = extractdomain(a_tag.get('href'))
            text_link = extractdomain(a_tag.get_text())
            
            if not text_link:
                return 1
            if href:
                if text_link.lower() != href.lower():
                    return 1
                
        return -1
    
class RuleA1(MailClassificationRule):
    def __init__(self):
        self.code = 'A1'
        self.description = "HTTPS in visible link, HTTP in real destination"
        self.weight = 1
    
    def apply_rule(self, mailFields):
        if not 'html' in mailFields:
            return -1
        
        soup = BeautifulSoup(mailFields['html'], 'html.parser')
        for a_tag in soup.find_all('a'):
            href = a_tag.get('href')
            text_link = a_tag.get_text()
            
            if not href or not text_link:
                continue

            if re.search('https:\/\/', href) and re.search('http:\/\/',text_link):
                return 1
        
        return -1


class RuleA2(MailClassificationRule):
    def __init__(self):
        self.code = 'A2'
        self.description = "URL contains username"
        self.weight = 1
        
    def apply_rule(self, mailFields):
        if 'links' in mailFields:
            for link_info in mailFields['links']:
                if link_info['raw_link'] and '@' in link_info['raw_link'] and link_info['raw_link'].startswith('http'):
                    return 1
        
        if not 'html' in mailFields:
            return -1
        
        soup = BeautifulSoup(mailFields['html'], 'html.parser')
        for a_tag in soup.find_all('a'):
            url = a_tag.get('href')
            if not url or url.startswith('mailto'):
                continue
            if '@' in url:
                return 1
            
            url = a_tag.get_text()
            if url and '@' in url:
                return 1
        return -1
    
    
class RuleA3(MailClassificationRule):
    def __init__(self):
        self.code = 'A3'
        self.description = 'Presence of suspicious headers'
        self.weight = 1
        
    def apply_rule(self, mailFields):
        if 'headers' not in mailFields:
            return -1
        
        content_type_regex = re.compile(ur'(?is)content.type.*?\)')
        boundary_regex  = re.compile('(?i)boundary.{1,40}qzsoft_directmail_seperator')

        for content in content_type_regex.findall(mailFields['headers']): 
            if boundary_regex.search(content):
                return 1
            
        return -1
    
class RuleA4(MailClassificationRule):
    def __init__(self):
        self.code = 'A4'
        self.weight = 173
        self.description = 'Common phishing keywords in subject '
        
    def apply_rule(self, mailFields):
        if 'subject' not in mailFields or not mailFields['subject']:
            return -1
        
        subject = strip_accents(mailFields['subject'])
        for pattern in SUSPICIOUS_SUBJECT_REGEX_LIST:
            if pattern.search(subject):
                return 1
        return -1

class RuleA5(MailClassificationRule):
    def __init__(self):
        self.code = 'A5'
        self.weight = -48
        self.description = 'Common spam keywords in subject'
         
    def apply_rule(self, mailFields):
        if 'subject' not in mailFields or not mailFields['subject']:
            return -1
        
        subject = strip_accents(mailFields['subject'])
        for pattern in COMMON_SPAM_SUBJECT_REGEX_LIST:
            if pattern.search(subject):
                return 1
        return -1
    
class RuleA6(MailClassificationRule):
    def __init__(self):
        self.code = 'A6'
        self.weight = 1
        self.description = 'Suspicious amount of redirections'
         
    def apply_rule(self, mailFields):
        if 'links' not in mailFields:
            return -1
        
        for link_info in mailFields['links']:
            if 'RedirectCount' in link_info and link_info['RedirectCount'] > 6:
                return 1
        return -1        
    
class RuleA7(MailClassificationRule):
    def __init__(self):
        self.code = 'A7'
        self.weight = 1
        self.description = 'Suspicious Alexa ranks in links'
         
    def apply_rule(self, mailFields):
        if 'links' not in mailFields:
            return -1
        
        rank_sum = 0
        rank_count = 0
        for link_info in mailFields['links']:
            if 'AlexaTrafficRank' in link_info and link_info['AlexaTrafficRank'] > 0:
                rank_sum += link_info['AlexaTrafficRank']
                rank_count += 1
                
        if rank_sum and rank_count > 0 and rank_sum / rank_count < 1000:
            return 1
            
        return -1        
        
class RuleA8(MailClassificationRule):
            
    def __init__(self):
        self.code = 'A8'
        self.weight = 1
        self.description = 'Blacklisted URL'
         
    def apply_rule(self, mailFields):
        
        if 'links' not in mailFields:
            return -1
        
        # assume every imported phishing email containing link was blacklisted
        # this makes this rule statisticaly significant, old phishing links are not
        # presented in databases anymore
        print mailFields['sensorID']
        print mailFields['links']
        if mailFields['links'] and re.match('.*phishingImport.*', mailFields['sensorID']):
            return 1

        return 1 if any(map(lambda a: a['InPhishTank'] if 'InPhishTank' in a else False, mailFields['links'])) else -1
            
            

        

rulelist = MailClassificationRuleList()
# rulelist.add_rule(PhischingHumanCheckRule())
# rulelist.add_rule(ContainsUrlRule())
# rulelist.add_rule(ContainsImageAttachmentRule())
# rulelist.add_rule(ContainsExecutableAttachmentRule())
# rulelist.add_rule(ContainsDocumentAttachmentRule())
rulelist.add_rule(HasShortenedUrl())
rulelist.add_rule(RuleC1())
rulelist.add_rule(RuleC2())
rulelist.add_rule(RuleC3())
rulelist.add_rule(RuleC4())
rulelist.add_rule(RuleC5())
rulelist.add_rule(RuleC6())
rulelist.add_rule(RuleC7())
rulelist.add_rule(RuleC8())
rulelist.add_rule(RuleC9())
rulelist.add_rule(RuleC10())
rulelist.add_rule(RuleC11())
rulelist.add_rule(RuleA1())
rulelist.add_rule(RuleA2())
rulelist.add_rule(RuleA3())
rulelist.add_rule(RuleA4())
rulelist.add_rule(RuleA5())
rulelist.add_rule(RuleA6())
rulelist.add_rule(RuleA7())
rulelist.add_rule(RuleA8())