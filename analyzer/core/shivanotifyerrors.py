'''
  __author__ = b0nd
  ver 1.0, 27th Oct, 2013
  
  Module sends notifications to developer/maintainer
  
'''
import shutil
import os
import smtplib
import ConfigParser
import server



## Error notification in case script confronts any issue
def notifydeveloper(msg):
    senderid = server.shivaconf.get('notification', 'sender')
    recipient = server.shivaconf.get('notification', 'recipient')
    smtphost = server.shivaconf.get('analyzer', 'relayhost')
    smtpport = server.shivaconf.get('analyzer', 'relayport')

    message = """From: SHIVA spamp0t <my.spamp0t@somedomain.com>
To: Developer <developer@somedomain.com>
MIME-Version: 1.0
Content-type: text/html
Subject: Master, SHIVA spamp0t confronted an issue
"""
    message += "Error Message:\n%s" % msg
    message += "you shall find sample in distorted directory"
    
    try:
        smtpobj = smtplib.SMTP(smtphost, smtpport)
        smtpobj.sendmail(senderid, recipient, message)
        print "\n\t[+] Error Notification Mail Sent Successfully"
    except smtplib.SMTPException:
        print "\n\t[!] Error: unable to send error notification mail via Exim4"
        
def send_phishing_report(mailFields):
    
    report_from = server.shivaconf.get('analyzer', 'phishing_report_from')
    report_to = server.shivaconf.get('analyzer', 'phishing_report_to')
    domain_root = server.shivaconf.get('web', 'address') 
    
    smtphost = server.shivaconf.get('analyzer', 'relayhost')
    smtpport = server.shivaconf.get('analyzer', 'relayport')

    message = """From: SHIVA honeypot <{0}>
To: {{1}}
MIME-Version: 1.0
Content-type: text/html
Subject: SHIVA honeypot: possible phishing found

SHIVA honeypot: possible phishing found

Details:
  Subject: {2}
  From: {3}
  To: {4}
  Link: http://{5}/view_email?email_id={6}
""".format(report_from, report_to, mailFields['subject'], mailFields['from'],mailFields['to'],domain_root,mailFields['s_id'])

    
    try:
        smtpobj = smtplib.SMTP(smtphost, smtpport)
        smtpobj.sendmail(report_from, report_to, message)
        print "\n\t[+] Phishing notification sent successfully"
    except smtplib.SMTPException:
        print "\n\t[!] Error: unable to send error phishing notification mail via Exim4"    
