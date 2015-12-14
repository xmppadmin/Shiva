import cherrypy 
import datetime
import threading
import time
import subprocess
import os


from mako.template import Template
from mako.lookup import TemplateLookup

import lamson.server

import backend_operations
import learning
import statistics

import logging



class WebServer():
    
    def __init__(self, in_params):
        self.startup_time = in_params['startup_time'] if in_params['startup_time'] else None 
        self.attachmentsPath = in_params['attachmentsPath']
        self.rawHtmlPath = in_params['rawHtmlPath']
        self.honypotLogFile = in_params['honeypot_log_file']
        self.template_lookup = TemplateLookup(directories=[in_params['templates_root']])
    
# index page    
    @cherrypy.expose
    def index(self):
        return self.index_template()
    
# view email page
    @cherrypy.expose
    def view_email(self,email_id = ''):
        return self.email_detail_template(email_id)
        
# go throught all emails
    @cherrypy.expose
    def list_emails(self,start=0,count=30):
        return self.list_emails_template(start, count)
            
# learning page
    @cherrypy.expose
    def learning(self):
        return self.learning_template(backend_operations.get_learning_overview())
        
# logs accessibility
    @cherrypy.expose
    def logs(self):
        return self.log_file_template()
# help page
    @cherrypy.expose
    def help(self):
        return self.help_template()        
 
# honeypot manipulation

    @cherrypy.expose
    def delete_email(self,email_id = ''):
        backend_operations.delete_spam(email_id)

    @cherrypy.expose
    def mark_as_phishing(self,email_id = ''):
        backend_operations.mark_as_phishing(email_id)     

    @cherrypy.expose
    def mark_as_spam(self,email_id = ''):
        backend_operations.mark_as_spam(email_id)
        
    @cherrypy.expose
    def relearn(self):
        learning.learn()
        raise cherrypy.HTTPRedirect("/stats")
    
    @cherrypy.expose
    def stats(self):
        statistics.generate_rules_graph(backend_operations.get_global_results_for_statistics(),
                                        title='Statistics of rules matching by email class',
                                        filename='global_rules_graph.png')
        statistics.generate_rules_graph(backend_operations.get_rule_results_for_statistics(),
                                        title='Statistics of rules matching by source of email',
                                        filename='source_rules_graph.png'
                                        )
#         statistics.generate_roc_graph((backend_operations.get_data_for_roc_curves())) 
        raise cherrypy.HTTPRedirect("/learning")
    




# templates ====================================================================    
    
    def index_template(self):
        title='SHIVA honeypot: mainpage'
        start = 0
        count = 10
        overview_list=backend_operations.get_overview(start,count)
        learning_overview_list=backend_operations.get_learning_overview(5)
        
        total_mails = backend_operations.get_mail_count()
        today_mails = backend_operations.get_mail_count_for_date(datetime.date.today(), datetime.date.today() + datetime.timedelta(days=1))
        
        uptime_str = 'uknown'
        uptime = time.time() - self.startup_time if self.startup_time else 0
        if uptime > 0:
            days, remainder = divmod(uptime, 24 * 60 * 60)
            hours, remainder = divmod(remainder, 60 * 60)
            minutes, _ = divmod(remainder, 60) 
            uptime_str = "{:.0f} days {:.0f} hours {:.0f} minutes".format(days,hours,minutes)
        
        
        template = Template('<%include file="index.html"/>', lookup=self.template_lookup, output_encoding='utf-8', encoding_errors='replace')
        return template.render(title=title, overview_list=overview_list, start=start,count=count,report_overview=learning_overview_list, uptime=uptime_str, total_mails=total_mails, today_mails=today_mails)
    
    
    
    def overview_template(self, overview_list, title, start=0, count=10):
        template = Template('<%include file="overview.html"/>', lookup=self.template_lookup, output_encoding='utf-8', encoding_errors='replace')
        return template.render(headline=title, title=title, overview_list=overview_list, start=start, count=count)
        
    
    def email_detail_template(self, email_id=''):
        title='SHIVA honeypot: view email'
        
        emails = backend_operations.retrieve_by_ids([email_id])
        
        # display error message and terminate
        if not emails:
            template = Template('<%include file="view_email.html"/>', lookup=self.template_lookup, output_encoding='utf-8', encoding_errors='replace')
            return template.render(title=title)
        
        mailFields = emails[0]
        
        
        
        if mailFields:        
            # store html content to static file if it doesn't exist
            staticHtmlFile = self.rawHtmlPath + '/' + email_id 
    
            if not os.path.exists(staticHtmlFile):
                f = open(staticHtmlFile, 'w')
                if f:
                    f.write(mailFields['html'].encode('utf8'))
                    f.close()
                else:
                    staticHtmlFile = ''
        
        email_result = backend_operations.get_results_of_email(mailFields['s_id'])
        template = Template('<%include file="view_email.html"/>', lookup=self.template_lookup, output_encoding='utf-8', encoding_errors='replace')
        return template.render(title=title, email_result=email_result, mailFields=mailFields, attachmentsPath=self.attachmentsPath,staticHtmlFile=staticHtmlFile)
        
    
    def learning_template(self,report_overview=[]):
        template = Template('<%include file="learning.html"/>', lookup=self.template_lookup, output_encoding='utf-8', encoding_errors='replace')
        return template.render(title='SHIVA honeypot: learning',report_overview=report_overview)
        
        
    def log_file_template(self):
        log_lines = []
        try:
            out = subprocess.check_output(['tail', '-n', '100', self.honypotLogFile])
            for o in out.splitlines():
                log_lines.append(o)
        except subprocess.CalledProcessError:
            pass

        template = Template('<%include file="logs.html"/>', lookup=self.template_lookup)
        return template.render(headline="SHIVA honeypot: log file view", title="SHIVA honeypot: log file view", rows=log_lines)
 
    
    def list_emails_template(self,start=0,count=30):
        title='SHIVA honeypot: list emails'
        headline_title = 'SHIVA honeypot: list {0} emails starting from {1}'.format(start,count)
        
        overview_list=backend_operations.get_overview(start,count)
        total = backend_operations.get_mail_count()

        template = Template('<%include file="list_emails.html"/>', lookup=self.template_lookup)
        return template.render(headline=headline_title, title=title, overview_list=overview_list, total=int(total), start=int(start), count=int(count))
     
    def help_template(self,report_overview=[]):
        template = Template('<%include file="help.html"/>', lookup=self.template_lookup, output_encoding='utf-8', encoding_errors='replace')
        return template.render(title='SHIVA honeypot: help') 
     
     
def error_page_401(status, message, traceback, version):
    return '<html><head><meta charset="UTF-8"></head><body><h1><b>401 UNAUTHORIZED ACCESS</b></h1></body></html>'   
     
# configuration ================================================================

def prepare_http_server():
    staticRoot = os.path.dirname(os.path.realpath(__file__)) + "/../../../../../../../"
    attachmentsPath = '/shiva/attachments'
    rawHtmlPath = '/shiva/raw_html'
    
    
    web_interface_address = '127.0.0.1'
    web_interface_port = '8080'
    web_bind_config = lamson.server.shivaconf.get('web', 'address')
    auth_login = lamson.server.shivaconf.get('web','username')
    auth_pass = lamson.server.shivaconf.get('web','password')

    if web_bind_config:
        web_interface_address, web_interface_port = web_bind_config.split(':')
    
    in_params = {'startup_time' : time.time(),
                 'attachmentsPath' : attachmentsPath,
                 'rawHtmlPath' : staticRoot + rawHtmlPath,
                 'templates_root' : staticRoot + 'web/templates/'
                 }
    cherrypy.config.update({'server.socket_host': web_interface_address,
                        'server.socket_port': int(web_interface_port),
                       })
    cherrypy.config.update({'error_page.401': error_page_401})

    checkpassword = cherrypy.lib.auth_basic.checkpassword_dict({auth_login : auth_pass,})
    
    conf = {
        '/': {
            'tools.sessions.on': True,
            'tools.staticdir.root': staticRoot,
            'tools.auth_basic.on': True,
            'tools.auth_basic.realm': 'web interface',
            'tools.auth_basic.checkpassword': checkpassword,
        },
        '/static': {
            'tools.staticdir.on': True,
            'tools.staticdir.dir': './web/'
        },
        '/attachments': {
            'tools.staticdir.on': True,
            'tools.staticdir.dir': '.' + attachmentsPath
        },
        '/raw_html': {
            'tools.staticdir.on': True,
            'tools.staticdir.dir': '.' + rawHtmlPath
        },
        
        '/favicon.ico': {
            'tools.staticfile.on': True,
            'tools.staticfile.filename': staticRoot + 'web/favicon.png'
        }
    }
    
    log_dir = os.path.dirname(os.path.realpath(__file__)) + "/../../../../../analyzer/logs/"
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
    
    cherrypy._cprequest.Response.timeout = 600
    
    in_params['honeypot_log_file'] = log_dir + 'lamson.log'
    cherrypy.quickstart(WebServer(in_params),'/',conf)
    
def main():
    """ Start web server in new thread"""
    t = threading.Thread(target=prepare_http_server)
    t.start()
    
    
