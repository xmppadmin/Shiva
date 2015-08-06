import time
import string
import datetime
import threading

import cherrypy

import cgi
from bs4 import BeautifulSoup

import shivamaindb
from base64 import decode

class WebServer():
    
    def __init__(self, in_params):
        self.startup_time = in_params['startup_time'] if in_params['startup_time'] else None 
    
# index page    
    @cherrypy.expose
    def index(self):
        return self.index_template()
    
    def index_template(self):
        title='SHIVA honeypot: mainpage'
        overview_title = 'Overview of last 10 emails'
        return string.join((self.header_template(title),
                             self.headline_template(title),
                             self.statistics_template(),
                             self.overview_template(overview_list=shivamaindb.get_overview(),title=overview_title,start=0,count=10), 
                             self.footer_template())) 
# view email page
    @cherrypy.expose
    def view_email(self,email_id = ''):
        emails = shivamaindb.retrieve_by_ids([email_id])
        mailFields = []
        if emails:
            mailFields = emails[0]
        title='SHIVA honeypot: view email: ' + email_id;
        
        return map(lambda a: a.decode('utf8'), (self.header_template(title),
                             self.headline_template(title),
                             self.email_detail_template(mailFields), 
                             self.footer_template()))

    
        
# go throught all emails
    @cherrypy.expose
    def list_emails(self,start=0,count=30):
        title='SHIVA honeypot: list emails'
        headline_title = 'SHIVA honeypot: list {0} emails starting from {1}'.format(count,start)
        overview_list=shivamaindb.get_overview(start,count)
        return string.join((self.header_template(title),
                            self.headline_template(headline=headline_title),
                            self.overview_template(overview_list=overview_list, title='', start=start, count=count),
                            self.view_list_navigation_template(start=int(start),count=int(count),total=500),
                            self.footer_template()))
        
        
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
            uptime_str = "{:.0f} days {:.0f} hours {:.0f} minutes {:.0f} seconds".format(uptime / 60 / 60 / 24, uptime / 60 / 60, uptime / 60, uptime % 60)
        else:
            uptime_str = 'unknown'
        return"""
            <h2>Runtime statistics</h2>
            <table>
                <tr><td>uptime</td><td>{}</td></tr>
                <tr><td>email since startup</td><td>xxx</td></tr>
                <tr><td>emails in database</td><td>xxx</td></tr>
            </table>
        """.format(uptime_str)
    
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
              </tr>
            </thead>
            <tbody>
            """
        for current in overview_list:
            result += """<tr>
                  <td><a href=\"/view_email?email_id={0}\">{0}</a></td>
                  <td>{1}</td></td><td>{2}</td><td>{3}</td><td>{4}</td>
                </tr>""".format(current['id'],current['lastSeen'],current['subject'],current['shivaScore'],current['spamassassinScore'])
        result += "</tbody></table>"
        return result
    
    def email_detail_template(self, mailFields):
        if not mailFields:
            return "<p>Email not found.</p>"
    
        result = "<table>"
        result += "<tr><td><b>{0}</b></td><td>{1}</td></tr>".format('Subject', mailFields['subject'])
        result += "<tr><td><b>{0}</b></td><td>{1}</td></tr>".format('From', mailFields['from'])
        result += "<tr><td><b>{0}</b></td><td>{1}</td></tr>".format('To', mailFields['to'])
        result += "<tr><td><b>{0}</b></td><td>{1}</td></tr>".format('Shiva score', mailFields['shivaScore'])
        result += "<tr><td><b>{0}</b></td><td>{1}</td></tr>".format('Spamassassin score', mailFields['spamassassinScore'])
        
        firstLink = True
        for link in mailFields['links']:
            result += "<tr><td><b>{0}</b></td><td><a href=\"{1}\">{1}</a>{2}</td></tr>".format('Links' if firstLink else '', link[0], '(' + link[1] + ')' if link[1] else '')
            firstLink = False
            
        if mailFields['text']:
            firstLine = True
            for line in mailFields['text'].replace('\n','<br/>').split('<br/>'):
                result += "<tr><td><b>{0}</b></td><td>{1}</td></tr>".format('Plain text' if firstLine else '', line)
                firstLine = False
        
        
        if mailFields['html']:
            firstLine = True
            soup =  BeautifulSoup(mailFields['html'].decode('utf8'))
            for line in cgi.escape(soup.prettify('utf8'), quote=True).replace('&gt;','&gt;<br/>').split('<br/>'):
                result += "<tr><td><b>{0}</b></td><td>{1}</td></tr>".format('Html' if firstLine else '', line)
                firstLine = False
        
        result += "</table>"
        
        return result
    
    def header_template(self, title=''):
        return """<html>
        <head>
          <link href="/static/style.css" rel="stylesheet">
          <title>""" + title + """</title>
        </head>
          <body>"""
     
    def headline_template(self, headline=''):
        return """<h1>""" + headline + """</h1>"""
         
    def footer_template(self):
        return """
            <hr>
            <footer>Quick navigation: <a href="/">Main page</a></footer><a href="/list_emails">List emails</a></footer>
            <foooter>Rendered: """ + datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + """</footer>
          </body>
        </html>"""
    
    
   
   
 
    
def prepare_http_server():
    in_params = {'startup_time' : time.time()}
    cherrypy.config.update({'server.socket_host': '192.168.57.20',
                        'server.socket_port': 8080,
                       })
    conf = {
        '/': {
            'tools.sessions.on': True,
            'tools.staticdir.root': '/home/user/shiva/web/'
        },
        '/static': {
            'tools.staticdir.on': True,
            'tools.staticdir.dir': './css'
        }
    }
    cherrypy.quickstart(WebServer(in_params),'/',conf)
    
def main():
    t = threading.Thread(target=prepare_http_server)
    t.start()
    
    