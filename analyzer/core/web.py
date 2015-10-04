from bs4 import BeautifulSoup
import cgi
import cherrypy
import datetime
import threading
import time

import server
import shivamaindb
import iohandler
import learning
import os
import logging
import subprocess


class WebServer():
    
    def __init__(self, in_params):
        self.startup_time = in_params['startup_time'] if in_params['startup_time'] else None 
        self.attachmentsPath = in_params['attachmentsPath']
        self.honypotLogFile = in_params['honeypot_log_file']
    
# index page    
    @cherrypy.expose
    def index(self):
        return self.index_template()
    
    def index_template(self):
        title='SHIVA honeypot: mainpage'
        overview_title = 'Overview of last 10 emails'
        overview_list=shivamaindb.get_overview()
        learning_overview_list=shivamaindb.get_learning_overview(10)
        return map(lambda a: a.decode('utf8','ignore'), (self.header_template(title),
                             self.headline_template(title),
                             self.statistics_template(),
                             self.overview_template(overview_list,title=overview_title,start=0,count=10), 
                             self.learning_template(learning_overview_list), 
                             self.footer_template())) 
# view email page
    @cherrypy.expose
    def view_email(self,email_id = ''):
        emails = shivamaindb.retrieve_by_ids([email_id])
        mailFields = []
        if emails:
            mailFields = emails[0]
        title='SHIVA honeypot: view email: ' + email_id;
        
        return map(lambda a: a.decode('utf8','ignore'), (self.header_template(title),
                             self.headline_template(title),
                             self.email_detail_template(mailFields), 
                             self.footer_template()))

    @cherrypy.expose
    def delete_email(self,email_id = ''):
        shivamaindb.delete_spam(email_id)
        
# go throught all emails
    @cherrypy.expose
    def list_emails(self,start=0,count=30):
        title='SHIVA honeypot: list emails'
        headline_title = 'SHIVA honeypot: list {0} emails starting from {1}'.format(count,start)
        overview_list=shivamaindb.get_overview(start,count)
        total = shivamaindb.get_mail_count()
        return map(lambda a: a.decode('utf8'), (self.header_template(title),
                            self.headline_template(headline=headline_title),
                            self.overview_template(overview_list=overview_list, title='', start=start, count=count),
                            self.view_list_navigation_template(start=int(start),count=int(count),total=total),
                            self.footer_template()))
        
# learning page
    @cherrypy.expose
    def learning(self):
        title='SHIVA honeypot: learning'
        headline_title = 'SHIVA honeypot: learning status'
        return map(lambda a: a.decode('utf8'), (self.header_template(title),
                            self.headline_template(headline=headline_title),
                            self.learning_template(shivamaindb.get_learning_overview()),
                            self.footer_template()))
        
#logs accessibility
    @cherrypy.expose
    def logs(self):
        title='SHIVA honeypot: log file view'
        headline_title = 'SHIVA honeypot: log file view'
        return map(lambda a: a.decode('utf8'), (self.header_template(title),
                            self.headline_template(headline=headline_title),
                            self.log_file_template(),
                            self.footer_template()))
        
 
# handle relearn
    @cherrypy.expose
    def mark_as_phishing(self,email_id = ''):
        shivamaindb.mark_as_phishing(email_id)     

    @cherrypy.expose
    def mark_as_spam(self,email_id = ''):
        shivamaindb.mark_as_spam(email_id)
        
    @cherrypy.expose
    def relearn(self):
        learning.learn()
        raise cherrypy.HTTPRedirect("/learning")
        
# API handler
    @cherrypy.expose
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    def api(self):
        if not hasattr(cherrypy.request, 'json'):
            return {'error': 'invalid document suplied'}
        data = cherrypy.request.json
        
        if (data.has_key('action')):
            return {'status': 'success' if iohandler.handle_api_request(data) else 'failure'}
        
        return {'error': 'unknown action'}
    
    def view_list_navigation_template(self,start,count,total):
        result = '<p>Nagivate:</p>'
        
        if start == 0:
            result += '<button><<</button>'
            result += '<button><</button>'
        else:
            result += '<a href="list_emails?start={0}&count={1}"><button><<</button></a>'.format(0,count)
            result += '<a href="list_emails?start={0}&count={1}"><button><</button></a>'.format((start - count) if (start - count) > 0 else 0,count)
            
        if start + count < total:
            result += '<a href="list_emails?start={0}&count={1}"><button>></button></a>'.format(start + count, count)
            result += '<a href="list_emails?start={0}&count={1}"><button>>></button></a>'.format(total - (total % count) , count)
        else:
            result += '<button>></button>'
            result += '<button>>></button>'
        
        return result        
    
    def statistics_template(self):
        uptime = time.time() - self.startup_time if self.startup_time else 0
        if uptime > 0:
            uptime_str = "{:.0f} days {:.0f} hours {:.0f} minutes {:.0f} seconds".format(uptime / 60 / 60 / 24, (uptime / 60 / 60) % 24, (uptime / 60) % 60, uptime % 60)
        else:
            uptime_str = 'unknown'
        return"""
            <h2>Runtime statistics</h2>
            <table>
                <tr><td>uptime</td><td>{0}</td></tr>
                <tr><td>email since startup</td><td>xxx</td></tr>
                <tr><td>emails in database</td><td>{1}</td></tr>
            </table>
        """.format(uptime_str,str(shivamaindb.get_mail_count()))
    
    def overview_template(self, overview_list, title, start=0, count=10):
        if not overview_list:
            return "<p>No emails found.</p>"
        
        result = "<h2>{}</h2>".format(title) if title else "";
        
        result += """
            <table>
            <thead>
              <tr>
                <td>Id</td>
                <td>Last seen</td>
                </td><td>Subject</td>
                </td><td>Shiva score</td>
                </td><td>Spamassassin score</td>
                </td><td>SensorID</td>
                </td><td>Status</td>
                </td><td>Actions</td>
              </tr>
            </thead>
            <tbody>
            """
        
        for current in overview_list:
            current_id = current['id']
            phishingStatus = current['derivedPhishingStatus']
            phishingStatusTag = '<font color="{0}">{1}</font>';
            if phishingStatus == True:
                phishingStatusTag = phishingStatusTag.format("red", "PHISHING")
            elif phishingStatus == False:
                phishingStatusTag = phishingStatusTag.format("green", "SPAM")
            else:
                phishingStatusTag = phishingStatusTag.format("black", "--")
            
            result += """<tr>
                  <td><a href=\"/view_email?email_id={0}\">{0}</a></td>
                  <td>{1}</td></td><td>{2}</td><td>{3}</td><td>{4}</td><td>{5}</td><td>{6}</td><td>{7}</td>
                </tr>""".format(current_id,
                                current['lastSeen'],
                                current['subject'].encode('utf8',errors='ignore'),
                                current['shivaScore'],
                                current['spamassassinScore'],
                                current['sensorID'],
                                phishingStatusTag,
                                self.prepare_actions_template(current_id, current['derivedPhishingStatus']))
        result += "</tbody></table>"
        return result
    
    def prepare_actions_template(self, email_id='', phishing_status=None):
        result = '<img src="/static/icons/delete.png" title="Delete email from honeypot." onclick="delete_email(\'' + email_id + '\')">'
        if phishing_status == True:
            result += '<img src="/static/icons/small_change_to_spam.png" title="Manually mark as spam."  onclick="mark_as_spam(\'' + email_id + '\')" >'
        elif phishing_status == False:
            result += '<img src="/static/icons/small_change_to_phishing.png" title="Manually mark as phishing." onclick="mark_as_phishing(\'' + email_id + '\')" >'
        else:
            result += '<img src="/static/icons/small_change_none.png" title="Marking not supported for imported emails.">'
        
        return result;
        
        
    
    def email_detail_template(self, mailFields):
        if not mailFields:
            return "<p>Email not found.</p>"
    
        result = "<table>"
        result += "<tr><td><b>{0}</b></td><td>{1}</td></tr>".format('Subject', mailFields['subject'].encode('utf8'))
        result += "<tr><td><b>{0}</b></td><td>{1}</td></tr>".format('From', mailFields['from'])
        result += "<tr><td><b>{0}</b></td><td>{1}</td></tr>".format('To', mailFields['to'])
        result += "<tr><td><b>{0}</b></td><td>{1}</td></tr>".format('Shiva score', mailFields['shivaScore'])
        result += "<tr><td><b>{0}</b></td><td>{1}</td></tr>".format('Spamassassin score', mailFields['spamassassinScore'])
        
        firstLink = True
        for link in mailFields['links']:
            result += "<tr><td><b>{0}</b></td><td><a href=\"{1}\">{1}</a>{2}</td></tr>".format('Links' if firstLink else '', link[0], '(' + link[1] + ')' if link[1] else '')
            firstLink = False
        
        if (mailFields['attachmentFilePath']):
            for i in range(0, len(mailFields['attachmentFilePath'])):
                index = mailFields['attachmentFilePath'][i].find(self.attachmentsPath)
                if index < 0:
                    continue
                result += "<tr><td><b>{0}</b></td><td><a href=\"attachments/{1}\">{2}</a></td></tr>".format('Attachments' if i == 0 else '', mailFields['attachmentFilePath'][i][index + len(self.attachmentsPath):], mailFields['attachmentFileName'][i])
            
        if mailFields['text']:
            firstLine = True
            for line in mailFields['text'].replace('\n','<br/>').split('<br/>'):
                result += "<tr><td><b>{0}</b></td><td>{1}</td></tr>".format('Plain text' if firstLine else '', line.encode('utf8'))
                firstLine = False
        
        
        if mailFields['html']:
            firstLine = True
            soup =  BeautifulSoup(mailFields['html'].encode('utf8'), "html.parser")
            for line in cgi.escape(soup.prettify('utf8'), quote=True).replace('&gt;','&gt;<br/>').split('<br/>'):
                result += "<tr><td><b>{0}</b></td><td>{1}</td></tr>".format('Html' if firstLine else '', line)
                firstLine = False
        
        result += "</table>"
        
        return result
    
    def learning_template(self,report_overview=[]):
        result = "<h2>Overview of last {} honeypot learning attempts</h2>".format(str(len(report_overview)))
        
        result += """
        <table>
            <thead>
              <tr>
                <td>Learning date</td>
                <td>Count of emails</td>
                </td><td>Shiva classifier status</td>
                </td><td>Spamassassin status</td>
              </tr>
            </thead>
            <tbody>
        """
        
        for current_report in report_overview:
            result += "<tr><td>{0}</td><td>{1}</td><td>{2}</td><td>{3}</td></tr>".format(
                str(current_report['learningDate']),
                str(current_report['learningMailCount']),
                current_report['shivaStatus'],
                current_report['spamassassinStatus'])
        
        result += "</tbody></table>"
        
        result += """<p><a href="/relearn">Relearn honeypot now</a></p>"""
        return result
        
        
    def log_file_template(self):
        result = "<table>"
        try:
            out = subprocess.check_output(['tail', '-n', '100', self.honypotLogFile])
            for o in out.splitlines():
                result += "<tr><td>" + o + "</td></tr>"
        except subprocess.CalledProcessError:
            pass
        
        
        result += """</table><p id="end_of_log"></p>"""
        return result;
        

    
    def header_template(self, title=''):
        return """<html>
        <head>
          <link href="/static/css/style.css" rel="stylesheet">
          <script type="text/javascript" src="/static/js/requests.js"></script>
          <title>""" + title + """</title>
        </head>
          <body>"""
     
    def headline_template(self, headline=''):
        return """<h1>""" + headline + """</h1>"""
         
    def footer_template(self):
        return """
            <hr>
            <footer>Quick navigation: <a href="/">Main page</a>&nbsp;<a href="/list_emails">List emails</a>&nbsp;<a href="/learning">Learning</a>&nbsp;<a href="/logs#end_of_log">Logs</a></footer>
            <foooter>Rendered: """ + datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + """</footer>
          </body>
        </html>"""
    
    
   
   
 
    
def prepare_http_server():
    staticRoot = os.path.dirname(os.path.realpath(__file__)) + "/../../../../../../"
    attachmentsPath = '/shiva/attachments'
    
    
    web_interface_address = '127.0.0.1'
    web_interface_port = '8080'
    web_bind_config = server.shivaconf.get('web', 'address')

    if web_bind_config:
        web_interface_address, web_interface_port = web_bind_config.split(':')
    
    in_params = {'startup_time' : time.time(), 'attachmentsPath' : attachmentsPath}
    cherrypy.config.update({'server.socket_host': web_interface_address,
                        'server.socket_port': int(web_interface_port),
                       })
    conf = {
        '/': {
            'tools.sessions.on': True,
            'tools.staticdir.root': staticRoot
        },
        '/static': {
            'tools.staticdir.on': True,
            'tools.staticdir.dir': './web/'
        },
        '/attachments': {
            'tools.staticdir.on': True,
            'tools.staticdir.dir': '.' + attachmentsPath
        },
        '/favicon.ico': {
            'tools.staticfile.on': True,
            'tools.staticfile.filename': staticRoot + 'web/favicon.png'
        }
    }
    
    log_dir = os.path.dirname(os.path.realpath(__file__)) + "/../../../../analyzer/logs/"
    if not os.path.isdir(log_dir):
        logging.warn("Logging directory doesn't exist, using /tmp/")
        log_dir = '/tmp/'
        
    access_log_path = log_dir + "web_access.log"
    error_log_path = log_dir + "web_error.log"
    
    if not os.path.exists(access_log_path):
        open(access_log_path, 'a').close()
    
    if not os.path.exists(error_log_path):
        open(error_log_path, 'a').close()    
    
    cherrypy.log.screen = False
    cherrypy.log.error_log.propagate = False
    cherrypy.log.access_log.propagate = False
    cherrypy.log.error_file = error_log_path
    cherrypy.log.access_file = access_log_path
    
    in_params['honeypot_log_file'] = log_dir + 'lamson.log'
    cherrypy.quickstart(WebServer(in_params),'/',conf)
    
def main():
    t = threading.Thread(target=prepare_http_server)
    t.start()
    
    
