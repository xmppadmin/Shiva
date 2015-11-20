
import smtplib
import lamson.server


def send_phishing_report(mailFields):
    
    report_from = lamson.server.shivaconf.get('analyzer', 'phishing_report_from')
    report_to = lamson.server.shivaconf.get('analyzer', 'phishing_report_to')
    domain_root = lamson.server.shivaconf.get('web', 'address') 
    
    smtphost = lamson.server.shivaconf.get('analyzer', 'relayhost')
    smtpport = lamson.server.shivaconf.get('analyzer', 'relayport')

    message = """From: SHIVA honeypot <{0}>
To: {1}
MIME-Version: 1.0
Content-Type: text/plain; charset=utf-8
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