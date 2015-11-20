
import smtplib
import lamson.server

from mako.template import Template

def send_phishing_report(mailFields):
    
    report_from = lamson.server.shivaconf.get('analyzer', 'phishing_report_from')
    report_to = lamson.server.shivaconf.get('analyzer', 'phishing_report_to')
    domain_root = lamson.server.shivaconf.get('web', 'address') 
    
    smtphost = lamson.server.shivaconf.get('analyzer', 'relayhost')
    smtpport = lamson.server.shivaconf.get('analyzer', 'relayport')


    template_str = """
From: SHIVA honeypot <${honeypot_email}>
To: ${recipient_email}
MIME-Version: 1.0
Content-Type: text/plain; charset=utf-8
Subject: SHIVA honeypot: possible phishing found

SHIVA honeypot: possible phishing found

Details:
  Subject: ${phishing_subject}
  From: ${phishing_from}
  To: ${phishing_to}
  Link: http://${web_iterface_url}/view_email?email_id=${email_id}
    
"""
    
    template = Template(template_str, output_encoding='utf-8', encoding_errors='replace')

    message = template.render(honeypot_email=report_from,
                                recipient_email=report_to,
                                phishing_subject=mailFields['subject'],
                                phishing_to=mailFields['to'],
                                phishing_from=mailFields['from'],
                                web_iterface_url=domain_root,
                                email_id=mailFields['s_id'])
     

       
    try:
        smtpobj = smtplib.SMTP(smtphost, smtpport)
        smtpobj.sendmail(report_from, report_to, message)
        print "\n\t[+] Phishing notification sent successfully"
    except smtplib.SMTPException:
        print "\n\t[!] Error: unable to send error phishing notification mail via Exim4"   