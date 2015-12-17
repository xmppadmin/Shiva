"""
Module send email notification about phishing emails
"""

import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.message import MIMEMessage
from email.utils import formataddr
from email import message_from_file

import lamson.server
import backend_operations
from time import strftime


from mako.template import Template

def send_phishing_report(mailFields):
    
    report_from = lamson.server.shivaconf.get('analyzer', 'phishing_report_from')
    report_to = lamson.server.shivaconf.get('analyzer', 'phishing_report_to')
    domain_root = lamson.server.shivaconf.get('web', 'address') 
    
    smtphost = lamson.server.shivaconf.get('analyzer', 'relayhost')
    smtpport = lamson.server.shivaconf.get('analyzer', 'relayport')
    
    msg = MIMEMultipart('mixed')
    msg['Subject'] = "Automatic phishing detection report"
    msg['From'] = formataddr(('SHIVA honeypot', report_from,))
    msg['To'] = formataddr(('', report_to,))



    if not mailFields['s_id']:
        return

    raw_path = lamson.server.shivaconf.get('analyzer', 'rawspampath')
    phish_path = raw_path + 'phishing/'
    
    
    phish_file_name = ''
    from os import walk
    for _, _, filenames in walk(phish_path):
        for filename in filenames:
            if filename.startswith(mailFields['s_id']):
                phish_file_name = filename
                break
            
    if not phish_file_name:
        return
    
    
    links = backend_operations.get_permament_url_info_for_email(mailFields['s_id'])
    
    has_phishtank = any(map(lambda a: a['InPhishTank'],links))
    has_googlesba = any(map(lambda a: a['GoogleSafeBrowsingAPI'],links))

    detected = backend_operations.get_last_seen_date(mailFields['s_id'])
    if detected:
        detected_str = detected.strftime("%Y-%m-%d %H:%M:%S")
    else:
        detected_str = 'unknown'

    template_str = """
SHIVA honeypot: suspicious email was caught

Overview:
  Timestamp: ${detected_timestamp|h}
  Subject: ${phishing_subject}
  Sender: ${phishing_from}
  Recipient: ${phishing_to}
  Link: http://${web_iterface_url}/view_email?email_id=${email_id}
  
  % if in_phishtank == True:
    Links in PhishTank:
    % for link_info in links_info:
    % if link_info['InPhishTank'] == True:
      ${link_info['raw_link']}
    %endif
    % endfor
  % endif      

  % if in_googlesba == True:
    Dangerous links in Gogole Safe Browsing API:
    % for link_info in links_info:
    % if link_info['GoogleSafeBrowsingAPI'] == True:
      ${link_info['raw_link']}
    %endif
    % endfor
  % endif  

  
"""    
    template = Template(template_str, output_encoding='utf-8', encoding_errors='replace')

    text_message = template.render(phishing_to=mailFields['to'],
                                phishing_from=mailFields['from'],
                                phishing_subject=mailFields['subject'],
                                web_iterface_url=domain_root,
                                email_id=mailFields['s_id'],
                                in_phishtank=has_phishtank,
                                in_googlesba=has_googlesba,
                                links_info=links,
                                detected_timestamp=detected_str)
     

    textpart = MIMEText(text_message, 'plain', 'utf-8')
    textpart['Content-Transfer-Encoding: 8bit']
    
    phish_file = open(phish_path + phish_file_name, 'rb')
    
    rfc822part = MIMEMessage(message_from_file(phish_file))
    phish_file.close()
    
    rfc822part['Content-Description'] = 'Original Message'
    rfc822part['Content-Disposition'] = 'inline'
    msg.attach(textpart)
    msg.attach(rfc822part)

       
    try:
        smtpobj = smtplib.SMTP(smtphost, smtpport)
        smtpobj.sendmail(report_from, report_to, msg.as_string())
        print "\n\t[+] Phishing notification sent successfully"
    except smtplib.SMTPException:
        print "\n\t[!] Error: unable to send error phishing notification mail via Exim4"   
        
