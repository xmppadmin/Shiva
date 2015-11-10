'''
Created on Oct 22, 2015

@author: mertam
'''


import unittest
import phishing


class TestHelperMethods(unittest.TestCase):

    def test_extract_ip(self):
        assert '1.2.3.4' == phishing.extractip('http://1.2.3.4:8080/aaa')
        assert '' == phishing.extractip('http://1.2.3.4.cz:8080/aaa')
        assert '' == phishing.extractip('http://1.2.3.:8080/aaa')
        assert '' == phishing.extractip('http://1.2.asd.aa.:8080/aaa')
        assert '' == phishing.extractip('http://1.2.asd.aa.:8080/aaa')
        assert '' == phishing.extractip('http://aaa.aaa.aa/12.3.4.5')
          
    def test_extract_domain(self):
        assert 'aaa.bbb.cc' == phishing.extractdomain('http://aaa.bbb.cc')
        assert 'aaa.bbb.cc' == phishing.extractdomain('http://aaa.bbb.cc?something=4')
        assert 'aaa.bbb.cc' == phishing.extractdomain('https://aaa.bbb.cc')
        assert 'aaa.bbb.cc' == phishing.extractdomain('http://www.aaa.bbb.cc')
        assert 'aaa.bbb.cc' == phishing.extractdomain('https://www.aaa.bbb.cc')
        assert 'aaa.bbb.cc' == phishing.extractdomain('https://xxxx@www.aaa.bbb.cc')
        assert 'aaa.bbb.cc' == phishing.extractdomain('https://xxxx@www.aaa.bbb.cc:1234/eee.cc')
        assert 'aaa.bbb.cc' == phishing.extractdomain('www.aaa.bbb.cc:1234/eee.cc')
        assert 'aaa.bbb.cc' == phishing.extractdomain('aaa.bbb.cc:1234/eee.cc')
        assert 'aaa.bbb.cc' == phishing.extractdomain('eeee@aaa.bbb.cc:1234/eee.cc')
 
    def test_extract_all_domains(self):
        assert ['aaaa.bbb.com', 'qqqq.eeee.org'] == phishing.extractalldomains('aaaa.bbb.com/qqqq.eeee.org')
        assert ['aaaa.bbb.com', 'qqqq.eeee.org'] == phishing.extractalldomains('aaaa.bbb.com/qqqq.eeee.org?something=0')
        assert ['aaaa.bbb.com', 'qqqq.eeee.org'] == phishing.extractalldomains('aaaa.bbb.com:1234/qqqq.eeee.org')
        assert ['aaaa.bbb.com', 'qqqq.eeee.org'] == phishing.extractalldomains('http://aaaa.bbb.com:1234/qqqq.eeee.org')
        assert ['aaaa.bbb.com', 'qqqq.eeee.org'] == phishing.extractalldomains('http://aaaa.bbb.com:1234/rrrr/qqqq.eeee.org')
        assert ['aaaa.bbb.com', 'qqqq.eeee.org'] == phishing.extractalldomains('http://aaaa.bbb.com:1234/rrrr/qqqq.eeee.org/tttt')
        assert ['aaaa.bbb.com', 'qqqq.eeee.org'] == phishing.extractalldomains('http://www.aaaa.bbb.com:1234/rrrr/qqqq.eeee.org/tttt')
        assert ['qqqq.eeee.org'] == phishing.extractalldomains('http://1.2.3.4:1234/rrrr/qqqq.eeee.org/tttt')
        assert ['aaaa.bbb.com', 'qqqq.eeee.org'] == phishing.extractalldomains('http://www.aaaa.bbb.com:8080/some/path/something.php?something=4&url=qqqq.eeee.org')
         
    def test_same_domain(self):
        assert phishing.samedomain('aaa.bbb.com', 'aaa.bbb.com')
        assert phishing.samedomain('aaa.bbb.com', 'bbb.com')
        assert not phishing.samedomain('aaa.bbb.com', 'bbbb.com')
          

class TestRules(unittest.TestCase):
    def test_rule_c1(self):
        from phishing import RuleC1
        rule = RuleC1()
     
        mail_body_html = """
        <body>
          <a href="http://www.something.interesting.com/something/even/more/interesting.cgi">
            something interesting
          </a>
        <body>
        """
        mailFields = {}
        mailFields['html'] = mail_body_html
        self.rule_assert_not(rule.apply_rule(mailFields))
         
        mail_body_html = """
        <body>
          <a href="http://www.something.interesting.com/something/even/more/interesting.cgi">
            something.interesting.com
          </a>
        <body>
        """
        mailFields = {}
        mailFields['html'] = mail_body_html
        assert 0 > rule.apply_rule(mailFields)
         
        mail_body_html = """
        <body>
          <a href="http://www.something.interesting.com/something/even/more/interesting.cgi">
            interesting.com
          </a>
        <body>
        """
        mailFields = {}
        mailFields['html'] = mail_body_html
        self.rule_assert_not(rule.apply_rule(mailFields))
 
        mail_body_html = """
        <body>
          <a href="http://www.something.interesting.com/something/even/more/interesting.cgi">
            something.boring.com
          </a>
        <body>
        """
        mailFields = {}
        mailFields['html'] = mail_body_html
        self.rule_assert(rule.apply_rule(mailFields))
         
                 
    def test_rule_c2(self):
        from phishing import RuleC2
        rule = RuleC2()
         
        mail_body_html = """
        <body>
          <a href="http://127.0.0.1/something/interesting.php">
            something.boring.com
          </a>
        <body>
        """
        mailFields = {}
        mailFields['html'] = mail_body_html
        self.rule_assert(rule.apply_rule(mailFields))   
         
        mail_body_html = """
        <body>
          <a href="http://www.aaa.bbb.com/something/interesting.php">
            something.boring.com
          </a>
        <body>
        """
        mailFields = {}
        mailFields['html'] = mail_body_html
        self.rule_assert_not(rule.apply_rule(mailFields))    
        
    def test_rule_c4(self):
        from phishing import RuleC4
        rule = RuleC4()
        
        mail_body_html = """
        <body>
          <a href="http://some.site.com/something/interesting.php">
            something.boring.com
          </a>
        <body>
        """
        mailFields = {}
        mailFields['html'] = mail_body_html
        self.rule_assert_not(rule.apply_rule(mailFields))
        
        mail_body_html = """
        <body>
          <a href="http://some.way.too.complicated.site.com/something/interesting.php">
            something.boring.com
          </a>
        <body>
        """
        mailFields = {}
        mailFields['html'] = mail_body_html
        self.rule_assert(rule.apply_rule(mailFields))
         
    def test_rule_c5(self):
        from phishing import RuleC5
        rule = RuleC5()
         
        mailFields = {}
        mailFields['from'] = 'sender@bbb.com'
        link1 = {'raw_link' : 'aaaa.bbb.com', 'LongUrl' : '', 'RedirectCount' : -1, 'AlexaTrafficRank' : -1, 'InPhishTank' : False}
        mailFields['links'] = [link1]
        self.rule_assert_not(rule.apply_rule(mailFields))    
         
        mailFields = {}
        mailFields['from'] = 'sender@bbb.com'
        link1 = {'raw_link' : 'aaaa.bbb.com', 'LongUrl' : '', 'RedirectCount' : -1, 'AlexaTrafficRank' : -1, 'InPhishTank' : False}
        link2 = {'raw_link' : 'eeee.ccc.com', 'LongUrl' : '', 'RedirectCount' : -1, 'AlexaTrafficRank' : -1, 'InPhishTank' : False}
        mailFields['links'] = [link1, link2]
        self.rule_assert(rule.apply_rule(mailFields))
 
     
    def test_rule_c6(self):
        from phishing import RuleC6
        rule = RuleC6()
         
        mail_body_html = """
        <body>
          <img src="http://aaaa.bbb.com:80/some/interesting/image.png"/>
        <body>
        """
        mailFields = {}
        mailFields['html'] = mail_body_html
        link1 = {'raw_link' : 'aaaa.bbb.com', 'LongUrl' : '', 'RedirectCount' : -1, 'AlexaTrafficRank' : -1, 'InPhishTank' : False}
        link2 = {'raw_link' : 'eeee.bbb.com', 'LongUrl' : '', 'RedirectCount' : -1, 'AlexaTrafficRank' : -1, 'InPhishTank' : False}
        mailFields['links'] = [link1,link2]
        self.rule_assert_not(rule.apply_rule(mailFields))
         
        mail_body_html = """
        <body>
          <img src="http://aaaa.bbb.com:80/some/interesting/image.png"/>
        <body>
        """
        mailFields = {}
        mailFields['html'] = mail_body_html
        link1 = {'raw_link' : 'aaaa.bbb.com', 'LongUrl' : '', 'RedirectCount' : -1, 'AlexaTrafficRank' : -1, 'InPhishTank' : False}
        link2 = {'raw_link' : 'eeeee.ccccccc.com', 'LongUrl' : '', 'RedirectCount' : -1, 'AlexaTrafficRank' : -1, 'InPhishTank' : False}
        mailFields['links'] = [link1,link2]
        self.rule_assert(rule.apply_rule(mailFields))
          
    def test_rule_c7(self):
        from phishing import RuleC7
        rule = RuleC7()
         
        mail_body_html = """
        <body>
          <img src="http://1.2.3.4:80/some/interesting/image.png"/>
        <body>
        """
        mailFields = {}
        mailFields['html'] = mail_body_html
        self.rule_assert(rule.apply_rule(mailFields))
          
        mail_body_html = """
        <body>
          <img src="http://something.somewhere.com/some/interesting/image.png"/>
        <body>
        """
        mailFields = {}
        mailFields['html'] = mail_body_html
        self.rule_assert_not(rule.apply_rule(mailFields))
         
     
    def test_rule_c8(self):
        from phishing import RuleC8
        rule = RuleC8()
         
        mail_body_html = """
        <body>
          <a href="http://www.aaaa.aaaa.com:8080/bbbb.ggggg.org?something=4">qwer</a>
        <body>
        """
        mailFields = {}
        mailFields['html'] = mail_body_html
        mailFields['links'] = []
        self.rule_assert(rule.apply_rule(mailFields))
         
         
        mail_body_html = """
        <body>
          <a href="http://www.aaaa.aaaa.com:8080/some/path/something.php?something=4&url=bbbb.ggggg.org">qwer</a>
        <body>
        """
        mailFields = {}
        mailFields['html'] = mail_body_html
        mailFields['links'] = []
        self.rule_assert(rule.apply_rule(mailFields))
         
        mail_body_html = """
        <body>
          <a href="http://www.aaaa.aaaa.com:8080/some/path/service.aspx?something=4">qwer</a>
        <body>
        """
        mailFields = {}
        mailFields['html'] = mail_body_html
        mailFields['links'] = []
        self.rule_assert_not(rule.apply_rule(mailFields))
         
        mailFields = {}
        mailFields['html'] = ''
        link1 = {'raw_link' : 'wwww.asdf.qwer.edu:/lkqewr/qwer/qwer/?eer=324&bbbb.ggggg.org', 'LongUrl' : '', 'RedirectCount' : -1, 'AlexaTrafficRank' : -1, 'InPhishTank' : False}
        mailFields['links'] = [link1]
        rule = RuleC8()
        self.rule_assert(rule.apply_rule(mailFields))
         
    def test_rule_c9(self):
        from phishing import RuleC9
        rule = RuleC9()
         
        mail_body_html = """
        <body>
          <a href="http://www.aaaa.aaaa.eeee.com">aaaa</a>
        <body>
        """
        mailFields = {}
        mailFields['html'] = mail_body_html
        mailFields['links'] = []
        self.rule_assert_not(rule.apply_rule(mailFields))
         
        mail_body_html = """
        <body>
          <a href="http://www.aaaa.aaaa.eee.eeeee.com">aaaa</a>
        <body>
        """
        mailFields = {}
        mailFields['html'] = mail_body_html
        mailFields['links'] = []
        self.rule_assert(rule.apply_rule(mailFields))
         
        mailFields = {}
        mailFields['html'] = ''
        link1 = {'raw_link' : 'http://www.aaaa.aaaa.eee.com', 'LongUrl' : '', 'RedirectCount' : -1, 'AlexaTrafficRank' : -1, 'InPhishTank' : False}
        mailFields['links'] = [link1]
        rule = RuleC9()
        self.rule_assert_not(rule.apply_rule(mailFields))
         
        mailFields = {}
        mailFields['html'] = ''
        link1 = {'raw_link' : 'http://www.aaaa.aaaa.eee.eeee.com', 'LongUrl' : '', 'RedirectCount' : -1, 'AlexaTrafficRank' : -1, 'InPhishTank' : False}
        mailFields['links'] = [link1]
        assert rule.apply_rule(mailFields)
         
     
    def test_rule_c10(self):
        from phishing import RuleC10
        rule = RuleC10()
         
        mail_body_html = """
        <body>
          <a href="http://www.aaaa.aaaa.eeee.com">aaaa</a>
        <body>
        """
        mailFields = {}
        mailFields['html'] = mail_body_html
        mailFields['links'] = []
        self.rule_assert_not(rule.apply_rule(mailFields))
         
        mail_body_html = """
        <body>
          <a href="http://www.aaaa.aaaa.eeee.com">
              <img src="1.3.4.5/images/image.gif" />
          </a>
        <body>
        """
        mailFields = {}
        mailFields['html'] = mail_body_html
        mailFields['links'] = []
        assert rule.apply_rule(mailFields)
    
    
    def test_rule_c11(self):
        from phishing import RuleC11
        rule = RuleC11()
        
        mail_body_html = """
        <body>
          <a href="http://www.aaaa.aaaa.eeee.com">aaaa.aaaa.eeee.com</a>
        <body>
        """
        mailFields = {}
        mailFields['html'] = mail_body_html
        mailFields['links'] = []
        self.rule_assert_not(rule.apply_rule(mailFields))
        
        mail_body_html = """
        <body>
          <a href="http://www.aaaa.aaaa.eeee.com">click here</a>
        <body>
        """
        mailFields = {}
        mailFields['html'] = mail_body_html
        mailFields['links'] = []
        self.rule_assert(rule.apply_rule(mailFields))
        
        
    def test_rule_a1(self):
        from phishing import RuleA1
        rule = RuleA1()
         
        mail_body_html = """
        <body>
          <a href="https://www.some.site.com">http://www.some.site.com</a>
        <body>
        """
        mailFields = {}
        mailFields['html'] = mail_body_html
        mailFields['links'] = []
        self.rule_assert(rule.apply_rule(mailFields))
        
        mail_body_html = """
        <body>
          <a href="http://www.some.site.com">http://www.some.site.com</a>
        <body>
        """
        mailFields = {}
        mailFields['html'] = mail_body_html
        mailFields['links'] = []
        self.rule_assert_not(rule.apply_rule(mailFields))

        
    def test_rule_a2(self):
        from phishing import RuleA2
        rule = RuleA2()
         
        mail_body_html = """
        <body>
          <a href="http://www.some.site.com">http://user@some.site.com</a>
        <body>
        """
        mailFields = {}
        mailFields['html'] = mail_body_html
        mailFields['links'] = []
        assert rule.apply_rule(mailFields)
        
        mailFields = {}
        mailFields['html'] = ''
        link1 = {'raw_link' : 'http://aaaaa.asdf@asdf.sdf.org', 'LongUrl' : '', 'RedirectCount' : -1, 'AlexaTrafficRank' : -1, 'InPhishTank' : False}
        mailFields['links'] = [link1]
        self.rule_assert(rule.apply_rule(mailFields))
        
        mailFields = {}
        mailFields['html'] = ''
        link1 = {'raw_link' : 'asdf@aaaaa.asdf.sdf.org', 'LongUrl' : '', 'RedirectCount' : -1, 'AlexaTrafficRank' : -1, 'InPhishTank' : False}
        mailFields['links'] = [link1]
        self.rule_assert_not(rule.apply_rule(mailFields))
        
        mailFields = {}
        mailFields['html'] = ''
        link1 = {'raw_link' : 'http://aaaaa.asdf.sdf.org', 'LongUrl' : '', 'RedirectCount' : -1, 'AlexaTrafficRank' : -1, 'InPhishTank' : False}
        mailFields['links'] = [link1]
        self.rule_assert_not(rule.apply_rule(mailFields))
        
    def test_rule_a3(self):
        from phishing import RuleA3
        rule = RuleA3()
        
        headers = """
        (Content-Type, multipart/alternative; charset="UTF-8";
            boundary=qzsoft_directmail_seperator")
        (MIME-Version, 1.0)
        (Date, Thu, 15 Oct 2015 14:41:48 +0300)
        (From, "International Scientific Events" <marketing@scientificevents.info>)
        (Message-Id, <0000000000000000000000000@mail.rrrrrrrrrrrrrr.oooo>)
        (Received, from rrrrrrrrrrrrrr.oooo (rrrrrrrrrrrrrr.oooo [1.2.3.4])
         by zzzz.xxx.yyyy.cz (8.14.4/8.14.4/Debian-4) with ESMTP id t9FDw1Rm047553
         for <xxx@xxx.yyyy.cz>; Thu, 15 Oct 2015 15:59:05 +0200)
        (Reply-To, xxx@gmail.com)
        (Subject, Conference Invitation 2016)
        (To, xxx@xxx.yyy.cz)
        (X-Filter-Version, 1.15 (minas))
        (X-Greylist, IP, sender and recipient auto-whitelisted, not delayed by
         milter-greylist-4.3.9 (minas.ics.muni.cz [1.2.3.4]);
         Thu, 15 Oct 2015 15:59:06 +0200 (CEST))
        (X-Mailer-Lid, 63, 64, 65, 67, 68, 17, 69, 18, 70, 71, 72, 16, 73, 15, 19, 74, 
         75, 76, 77, 78, 12, 79)
        (X-Mailer-Recptid, 774174)
        (X-Mailer-Sent-By, 1)
        (X-Mailer-Sid, 14)
        (X-Muni-Envelope-From,qqqqqq@ooooo.cc)
        (X-Muni-Spam-Testip, 1.2.3.4)
        (X-Virus-Scanned, clamav-milter 0.98.7 at xxxx)
        (X-Virus-Status, Clean)
        """
        mailFields = {}
        mailFields['headers'] = headers
        self.rule_assert(rule.apply_rule(mailFields))
        
    def test_rule_a4(self):
        from phishing import RuleA4
        rule = RuleA4()
        
        subject = 'PayPal Notification: Account Review'
        mailFields = {}
        mailFields['subject'] = subject
        self.rule_assert(rule.apply_rule(mailFields))
        
        subject = 'Protect your VISA card'
        mailFields = {}
        mailFields['subject'] = subject
        self.rule_assert(rule.apply_rule(mailFields))
        
        subject = 'Update your account'
        mailFields = {}
        mailFields['subject'] = subject
        self.rule_assert(rule.apply_rule(mailFields))
        
        subject = 'RegionsNET? Security Notice ID - Identity Confirmation Request'
        mailFields = {}
        mailFields['subject'] = subject
        self.rule_assert(rule.apply_rule(mailFields))
        
        subject = 'username, Participation Confirmation #32-157336252'
        mailFields = {}
        mailFields['subject'] = subject
        self.rule_assert(rule.apply_rule(mailFields))
        
        subject = 'eBay Deals, starting from $1'
        mailFields = {}
        mailFields['subject'] = subject
        self.rule_assert(rule.apply_rule(mailFields))
        
        subject = 'Returned mail: see transcript for details'
        mailFields = {}
        mailFields['subject'] = subject
        self.rule_assert_not(rule.apply_rule(mailFields))
        
        subject = 'The 12th International Conference on Knowledge, Economy and Management'
        mailFields = {}
        mailFields['subject'] = subject
        self.rule_assert_not(rule.apply_rule(mailFields))
        
        
    def test_rule_a5(self):
        from phishing import RuleA5
        rule = RuleA5()
        
        subject = 'PayPal Notification: Account Review'
        mailFields = {}
        mailFields['subject'] = subject
        self.rule_assert_not(rule.apply_rule(mailFields))
        
        subject = 'Protect your VISA card'
        mailFields = {}
        mailFields['subject'] = subject
        self.rule_assert_not(rule.apply_rule(mailFields))
        
        subject = 'Update your account'
        mailFields = {}
        mailFields['subject'] = subject
        self.rule_assert_not(rule.apply_rule(mailFields))
        
        subject = 'RegionsNET? Security Notice ID - Identity Confirmation Request'
        mailFields = {}
        mailFields['subject'] = subject
        self.rule_assert_not(rule.apply_rule(mailFields))
        
        subject = 'username, Participation Confirmation #32-157336252'
        mailFields = {}
        mailFields['subject'] = subject
        self.rule_assert_not(rule.apply_rule(mailFields))
        
        subject = 'eBay Deals, starting from $1'
        mailFields = {}
        mailFields['subject'] = subject
        self.rule_assert_not(rule.apply_rule(mailFields))
        
        subject = 'Returned mail: see transcript for details'
        mailFields = {}
        mailFields['subject'] = subject
        self.rule_assert(rule.apply_rule(mailFields))
        
        subject = 'The 12th International Conference on Knowledge, Economy and Management'
        mailFields = {}
        mailFields['subject'] = subject
        self.rule_assert(rule.apply_rule(mailFields))
        
        subject = 'International Scientific Events 2015, Bulgaria'
        mailFields = {}
        mailFields['subject'] = subject
        self.rule_assert(rule.apply_rule(mailFields))
        
        
    def test_rule_a6(self):
        from phishing import RuleA6
        rule = RuleA6()
        
        mailFields = {}
        link1 = {'raw_link' : 'http://aaaaa.asdf.sdf.org', 'LongUrl' : '', 'RedirectCount' : -1, 'AlexaTrafficRank' : -1, 'InPhishTank' : False}
        mailFields['links'] = [link1]
        self.rule_assert_not(rule.apply_rule(mailFields)) 
        
        mailFields = {}
        link1 = {'raw_link' : 'http://aaaaa.asdf.sdf.org', 'LongUrl' : '', 'RedirectCount' : 7, 'AlexaTrafficRank' : -1, 'InPhishTank' : False}
        mailFields['links'] = [link1]
        self.rule_assert_not(rule.apply_rule(mailFields)) 
    
    def rule_assert(self,result):
        assert result > 0
    
    def rule_assert_not(self,result):
        assert result < 0
        
if __name__ == "__main__":
    unittest.main()
