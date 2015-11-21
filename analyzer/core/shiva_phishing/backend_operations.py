"""
  This module is responsible for backend operations
"""
import os

import lamson.server
import lamson.shivadbconfig
import logging
import MySQLdb as mdb




def retrieve(limit, offset):
    """
    retrieve spam from database
    limit - integer, how many records should be retrieved
    offset - integer, offset to start from
    """

    fetchidsquery = "SELECT `id` FROM `spam` ORDER BY `id` LIMIT %s OFFSET %s"
    
    try:
        mainDb = lamson.shivadbconfig.dbconnectmain()
        mainDb.execute(fetchidsquery,(int(limit),int(offset),))
        
        ids = mainDb.fetchall()
        return retrieve_by_ids(map(lambda a: a[0], ids if ids else []))
    
    except mdb.Error, e:
        logging.error(e)
        
    return []

def retrieve_by_ids(email_ids = []):
    """
    return sparse mailField dictionary suitable
    for phishing detectkon with minor modifications {
        'links': list of link_info dictionaries, SEE get_permament_url_info_for_email,store_permament_url_info_for_email,
        'phishingHumanCheck': True/False/None
        'derivedPhishingStatus': True/False/None
        'shivaScore': float (0.0,1.0), -1 if email was imported,
        'spamassassinScore': float (0.0,1.0), -1 if email was imported,
        'blacklisted': True/False 
        }
    """
    
    resultlist = []
    try:
        for current_id in email_ids:
            mailFields = {'s_id':'', 'ssdeep':'', 'to':'', 'from':'', 'text':'', 'html':'', 'subject':'', 'headers':'', 'sourceIP':'', 'sensorID':'', 'firstSeen':'', 'relayCounter':'', 'relayTime':'', 'count':0, 'len':'', 'inlineFileName':[], 'inlineFilePath':[], 'inlineFileMd5':[], 'attachmentFileName':[], 'attachmentFilePath':[], 'attachmentFileMd5':[], 'attachmentFileType':[], 'links':[],  'date': '' }
            
            """fetch basic spam information from database"""
            spamquery = "SELECT `from`,`subject`,`to`,`textMessage`,`htmlMessage`,`totalCounter`,`ssdeep`,`headers`,`length`,`phishingHumanCheck`,`shivaScore`,`spamassassinScore`,`blacklisted` FROM `spam` WHERE `id` = %s "
            mailFields['s_id'] = current_id
            
            mainDb = lamson.shivadbconfig.dbconnectmain()
            mainDb.execute(spamquery,(current_id,))

            current_record = mainDb.fetchone()
            if not current_record: 
                continue
            
            mailFields['from'] = current_record[0] 
            mailFields['subject'] = current_record[1]
            mailFields['to'] = current_record[2]
            mailFields['text'] = current_record[3]
            mailFields['html'] = current_record[4]
            mailFields['totalCounter'] = current_record[5]
            mailFields['ssdeep'] = current_record[6]
            mailFields['headers'] = current_record[7]
            mailFields['len'] = current_record[8]
            mailFields['phishingHumanCheck'] = current_record[9]
            mailFields['shivaScore'] = current_record[10]
            mailFields['spamassassinScore'] = current_record[11]
            mailFields['blacklisted'] = current_record[12]
            
            """fetch sensors information"""
            sensorquery = 'select sensorID from sensor_spam ss inner join sensor s on s.id = ss.sensor_id where spam_id = %s limit 1'
            mainDb.execute(sensorquery,(current_id,))
            sensor = mainDb.fetchone()
            if sensor:
                mailFields['sensorID'] = sensor[0]
            
            """fetch links for current spam"""            
            mailFields['links'] = get_permament_url_info_for_email(current_id)

            
            """fetch attachments for current spam"""
            attachmentsquery = "SELECT `attachment_file_name`,`attachment_file_path`,`attachment_file_type` FROM `attachment` WHERE `spam_id` = %s"
            mainDb.execute(attachmentsquery,(current_id,));
            attachments = mainDb.fetchall()
            for row in attachments:
                mailFields['attachmentFileName'].append(row[0]) 
                mailFields['attachmentFilePath'].append(row[1])
                mailFields['attachmentFileType'].append(row[2])
            
            
            resultlist.append(mailFields)
        return resultlist
    except mdb.Error, e:
        logging.error(e)
    
    return resultlist
    
    
def get_overview(start=0,limit=10):
    """
    retrieve sequention of emails from database
    usable from overview purposes
    
    start : position to start on
    limit : maximal count of emails to return
    
    return [
      {'id':,'firstSeen':,'lastSeen':,'subject':,'shivaScore':,'spamassassinScore':,'sensorID':,'derivedPhishingStatus':,'phishingHumanCheck':, 'blacklisted':}
    ]
    """
    
    overview_list = []
    try:
        overview_query = "SELECT `id`,`firstSeen`,`lastSeen`,`subject`,`shivaScore`,`spamassassinScore`,`sensorID`,`derivedPhishingStatus`,`phishingHumanCheck`, `blacklisted` from `spam_overview_view` LIMIT %s OFFSET %s "
        
        mainDb = lamson.shivadbconfig.dbconnectmain()
        mainDb.execute(overview_query,(int(limit),int(start),))
        result = mainDb.fetchall()
        
        for record in result:
            overview_list.append({'id':record[0], 'firstSeen':record[1], 'lastSeen':record[2], 'subject':record[3], 'shivaScore':record[4], 'spamassassinScore':record[5], 'sensorID':record[6], 'derivedPhishingStatus':record[7], 'phishingHumanCheck':record[8], 'blacklisted':record[9]})
        
        
    except mdb.Error, e:
        logging.error(e)
        
    return overview_list
    
def get_mail_count():
    """
    return count of emails in database
    """
    query = "SELECT COUNT(*) FROM spam"
    
    result = 0
    try:
        mainDb = lamson.shivadbconfig.dbconnectmain()
        mainDb.execute(query)
        result = mainDb.fetchone()[0]
    except mdb.Error, e:
        logging.error(e)
        
    return result


def get_mail_count_for_date(from_datetime,to_datetime):
    """
    return count of emails betwwn given dates
    
    from_datetime : start date
    to_datetime : end date
    """
    query = "select count(*) from sdate where lastSeen between %s and %s";
    
    result = 0
    try:
        mainDb = lamson.shivadbconfig.dbconnectmain()
        mainDb.execute(query,(from_datetime,to_datetime,))
        result = mainDb.fetchone()[0]
    except mdb.Error, e:
        logging.error(e)
        
    return result
    

def delete_spam(email_id=''):
    """
    delete email from database and remove all related files
    
    email_id: identifier of email
    """
    if not email_id:
        return
    
    delete_queries = []
    
    check_query = "SELECT * FROM `spam` WHERE id =  '{}'".format(email_id);
    mainDb = lamson.shivadbconfig.dbconnectmain()
    
    mainDb.execute(check_query)
    if not mainDb.fetchone():
        return
    
    delete_queries.append("DELETE FROM attachment WHERE spam_id = '{}'".format(email_id))
    atachments_query = "SELECT date_id FROM sdate_spam WHERE spam_id = '{}'".format(email_id)
    mainDb.execute(atachments_query)
    records = mainDb.fetchall()
    if records:
        for record in records:
            __silent_remove_file(str(record[0]))
            
    rawspampath = lamson.server.shivaconf.get('analyzer', 'rawspampath')
    for subdir in ('phishing/', 'spam/'):
        from os import listdir
        from os.path import isfile, join
        path = rawspampath + subdir
        files = [ f for f in listdir(path) if isfile(join(path,f)) and f.startswith(email_id) ]
        for file_to_delete in files:
            __silent_remove_file(path + file_to_delete)
            
    delete_queries.append("DELETE FROM inline WHERE spam_id = '{}'".format(email_id))
    delete_queries.append("DELETE FROM links WHERE spam_id = '{}'".format(email_id))
    delete_queries.append("DELETE FROM relay WHERE spam_id = '{}'".format(email_id))
    
    ips_query = "SELECT ip_id FROM ip_spam WHERE spam_id = '{}'".format(email_id)
    delete_queries.append("DELETE FROM ip_spam WHERE spam_id = '{}'".format(email_id))
    mainDb.execute(ips_query)
    records = mainDb.fetchall()
    if records:
        for record in records:
            delete_queries.append("DELETE FROM ip WHERE id = '{}'".format(str(record[0])))
    

    dates_query = "SELECT date_id FROM sdate_spam WHERE spam_id = '{}'".format(email_id)
    delete_queries.append("DELETE FROM sdate_spam WHERE spam_id = '{}'".format(email_id))
    mainDb.execute(dates_query)
    records = mainDb.fetchall()
    if records:
        for record in records:
            delete_queries.append("DELETE FROM sdate WHERE id = '{}'".format(str(record[0])))
    
    
    sensors_query = "SELECT sensor_id FROM sensor_spam WHERE spam_id = '{}'".format(email_id)
    delete_queries.append("DELETE FROM sensor_spam WHERE spam_id = '{}'".format(email_id))
    mainDb.execute(sensors_query)
    records = mainDb.fetchall()
    if records:
        for record in records:
            delete_queries.append("DELETE FROM sensor WHERE id = '{}'".format(str(record[0])))
    

    delete_queries.append("DELETE FROM spam WHERE id = '{}'".format(email_id))
    for query in delete_queries:
        try:
            mainDb.execute(query)
        except mdb.Error, e:
            logging.error(e)
            return
        
    logging.info("Email with email_id '{}' was successfully deleted from honeypot".format(email_id))
           

def mark_as_phishing(email_id=''):
    """
    mark email with given id as phishing
    
    edits email details in database and physicaly moves email file from spam folder to phising folder
     
    email_id: identifier of email
    """
    
    if get_derived_phishing_status(email_id):
        logging.info("Atempt to re-mark email with id '{}' as phishing, nothing to do".format(email_id))
        return
    
    logging.info("Manually marking email with id '{}' as phishing.".format(email_id))
    
    update_query = "update spam set derivedPhishingStatus = True, phishingHumanCheck = True where id = %s"
    try:
        mainDb = lamson.shivadbconfig.dbconnectmain()
        mainDb.execute(update_query,(email_id,))
    except mdb.Error, e:
        logging.error(e)
        return
    
    __move_mail_by_id(email_id, False)
    
    
    
    
def mark_as_spam(email_id=''):
    """
    mark email with given id as spam
    
    edits email details in database and physicaly moves email file from phishing folder to spam folder
     
    email_id: identifier of email
    """
    
    if get_derived_phishing_status(email_id) == False:
        logging.info("Atempt to re-mark email with id '{}' as spam, nothing to do".format(email_id))
        return
    
    logging.info("Manually marking email with id '{}' as spam.".format(email_id))
    
    update_query = "update spam set derivedPhishingStatus = False, phishingHumanCheck = False where id = %s"
    try:
        mainDb = lamson.shivadbconfig.dbconnectmain()
        mainDb.execute(update_query,(email_id,))
    except mdb.Error, e:
        logging.error(e)
    
    __move_mail_by_id(email_id, True)
    
def __move_mail_by_id(email_id='',spam_to_pshishing=True):
    """
    move email from one folder to other
    """
    rawspampath = lamson.server.shivaconf.get('analyzer', 'rawspampath')
    phish_path = rawspampath + 'phishing/'
    spam_path = rawspampath + 'spam/'
    
    to_path = spam_path if spam_to_pshishing else phish_path
    from_path = phish_path if spam_to_pshishing else spam_path
    

    files_to_move = list()
    from os import walk,rename
    for _, _, filenames in walk(from_path):
        for filename in filenames:
            if filename.startswith(email_id):
                files_to_move.append(filename)
    
             
    for filename in files_to_move:
        rename(from_path + filename, to_path + filename)
    
    
def get_derived_phishing_status(email_id=''):
    """ 
    return True if email with given id was classified as phishing,
    False if it was classified as spam
    None if if information isn't available (imported emails).
    """
    
    if not email_id:
        return None
    
    query = 'SELECT derivedPhishingStatus FROM spam WHERE id = \'{}\''.format(email_id)
    try:
        mainDb = lamson.shivadbconfig.dbconnectmain()
        mainDb.execute(query)
    except mdb.Error, e:
        logging.error(e)
        return None
    
    result = mainDb.fetchone()[0]
    if result == True:
        return True
    if result == False:
        return False
    return None
    

def save_learning_report(classifier_status=False,spamassassin_status=False,shiva_threshreshold=.5,sa_threshold=.5):
    """ 
    store report of honeypot learning into database
    """

    report_classifier = "success" if classifier_status else "failure"
    report_spamassassin = "success" if spamassassin_status else "failure"
    
    query = "insert into `learningreport` (`learningDate`,`learningMailCount`,`spamassassinStatus`,`shivaStatus`, `shiva_threshold`, `sa_threshold`) values ( NOW(), (select count(*) from spam), %s , %s , %s , %s)"
    
    try:
        mainDb = lamson.shivadbconfig.dbconnectmain()
        mainDb.execute(query,(report_spamassassin,report_classifier,shiva_threshreshold,sa_threshold,))
    except mdb.Error, e:
        logging.error(e)
        
    
def get_learning_overview(limit=10):
    """
    get overview of recent honeypot learning reports
    """
    
    overview_list = []
    query = 'select learningDate,learningMailCount,spamassassinStatus,shivaStatus,shiva_threshold,sa_threshold from learningreport order by learningDate desc limit %s'
    
    try:
        mainDb = lamson.shivadbconfig.dbconnectmain()
        mainDb.execute(query,(int(limit),))
        
        result = mainDb.fetchall()
        for record in result:
            overview_list.append({'learningDate':record[0], 'learningMailCount':record[1], 'spamassassinStatus':record[2], 'shivaStatus':record[3], 'shiva_threshold': record[4], 'sa_threshold':record[5]})
        
    except mdb.Error, e:
        logging.error(e)
        
    return overview_list
    

def __silent_remove_file(filename):
    try:
        os.remove(filename)
    except OSError:
        pass  

def store_computed_results(computed_results=[],used_rules=[]):
    """
    store results of given given rulen into database
    
    length of of computed_results and used_rules must be same
    computed_results =
      list[
        {'spamId': string, 'code': string, 'result': int}
      ]
    used_results =  
      list[
       {'code': string , 'boost': int, 'description': string }
      ]
    """
    
    if len(computed_results) != len(used_rules):
            logging.error('shivamaindb:store_computed_results: Mismatch between results and rules')
            return

    try:
        mainDb = lamson.shivadbconfig.dbconnectmain()
        for i in range(0,len(computed_results)):
            rule_query = "select `id`,`boost` from rules where `code` = %s";
            
            mainDb.execute(rule_query,(used_rules[i]['code'],))
            result = mainDb.fetchone()
            if not result:
                # store new rule into DB
                mainDb.execute('insert into rules(code, boost, description) values (%s, %s, %s)',(used_rules[i]['code'], used_rules[i]['boost'], used_rules[i]['description']))
                mainDb.execute(rule_query,(used_rules[i]['code'],))
                rule_id = str(mainDb.fetchone()[0])
            else:
                rule_id = str(result[0])
                
                # update boost in database if nescessary
                if result[1] != used_rules[i]['boost']:
                    mainDb.execute('update rules set boost = %s where id = %s', (result[0],int(used_rules[i]['boost'])))

            query1 = 'delete from learningresults where ruleId = %s and spamId = %s'
            query2 = 'insert into learningresults(ruleId,spamId,result) values(%s, %s, %s)'
            
            mainDb.execute(query1,(rule_id, computed_results[i]['spamId']),)
            mainDb.execute(query2,(rule_id, computed_results[i]['spamId'], str(computed_results[i]['result']),))
            
            
    except mdb.Error, e:
        logging.error(e)
    
    return

def get_rule_results_for_statistics(): 
    """ 
    get aggreagated results of rules application by sensor
    return {_rule_codes:['r1', 'r2' , 'r3']
            _total_sensor1 = 10,
            _total_sensor2 = 4,
            sensor1 : [1, 0, 1],
            sensor2 : [0, 0, 1],
            }
    """
    result = {}
    try:
        mainDb = lamson.shivadbconfig.dbconnectmain()
        
        query = ('select code,sensorID,result from rules_overview_view')
        mainDb.execute(query)
        raw_result = mainDb.fetchall()
        
        all_rules = sorted(set(map(lambda a: a[0], raw_result)))
        all_sensors = sorted(set(map(lambda a: a[1], raw_result)))
          
        for sensor in all_sensors:
            result[sensor] = [0] * len(all_rules)
        
        result['_rule_codes'] = all_rules
        for current_result in raw_result:
            current_sensor = current_result[1]
            current_rule = current_result[0]
            result[current_sensor][all_rules.index(current_rule)] = int(current_result[2])
            
        query = ('SELECT se.sensorID,count(se.sensorID) FROM spam s INNER JOIN sensor_spam sse on s.id = sse.spam_id INNER JOIN sensor se on sse.sensor_id = se.id  GROUP BY se.sensorID')
        mainDb.execute(query)
        raw_result = mainDb.fetchall()
        
        for current_result in raw_result:
            result['_total_' + current_result[0]] = int(current_result[1])
        
        
    except mdb.Error, e:
        logging.error(e)
    
    return result
        
def get_data_for_roc_curves():
    """
    returns tuples (shivaScore, spamassassinScore, derivedStatus)
    for all emails having scores >= 0 (all emails that wern't imported)
    """
    
    result = []
    try:
        mainDb = lamson.shivadbconfig.dbconnectmain()
        query = 'SELECT shivaScore,spamassassinScore,derivedPhishingStatus FROM spam WHERE shivaScore >= 0 and spamassassinScore >= 0;'
        
        mainDb.execute(query)
        result = mainDb.fetchall()
        
    except mdb.Error, e:
        logging.error(e)
    
    return result

def get_results_of_email(email_id=''):
    """
    returns dictionary:
     {
       derivedStatus: True/False/None,
       humanCheck: True/False/None ,
       rules: [(code: string, description: string, result: int, boost: int)+]
     }
   
    array
    """
    
    result = {}
    try:
        mainDb = lamson.shivadbconfig.dbconnectmain()
        
        query = "SELECT derivedPhishingStatus,phishingHumanCheck FROM spam WHERE id = %s"
        mainDb.execute(query,(email_id,))
        
        status = mainDb.fetchone()
        if status:
            result['derivedStatus'] = {1: True, 0: False, None: None} [status[0]]
            result['humanCheck'] = {1: True, 0: False, None: None} [status[1]]
        
        query = "SELECT r.code,r.description,r.boost,lr.result FROM learningresults lr INNER JOIN rules r ON lr.ruleId = r.id WHERE lr.spamId = %s ORDER BY lr.ruleId"
        mainDb.execute(query,(email_id,))
        
        rules_resutls = []
        for current in mainDb.fetchall():
            rules_resutls.append({'code': current[0], 'description': current[1], 'boost': current[2],'result':current[3]})
        
        result['rules'] = rules_resutls
        
    except mdb.Error, e:
        logging.error(e)  

    return result

def get_email_ids():
    """
    return list of all email ids in database
    """
    try:
        mainDb = lamson.shivadbconfig.dbconnectmain()
        
        query = "SELECT id from spam;"
        mainDb.execute(query)
        
        return map(lambda a: a[0], mainDb.fetchall())
        
    except mdb.Error, e:
        logging.error(e)
    
    return []

def check_stored_rules_results_integrity():
    """
    performs integrity check on stored rules results in database
    results are integral IFF for every email and every rule in database
    exists computed result of rule application
    
    In other words, if at least one email is missing some rule result,
    database is in inconsistent state and can't be used for learning
    without deep relearn
    """
    try:
        mainDb = lamson.shivadbconfig.dbconnectmain()
        
        query = "SELECT IF((select count(*) from ruleresults_integrity_check_view) > 0,0,1)"
        mainDb.execute(query)
        
        result = mainDb.fetchone()
        return False if not result or result[0] != 1L else True
        
    except mdb.Error, e:
        logging.error(e)
    
    return False

def init_deep_relearn():
    """
    prepares database into state allowing deep relearn
    all stored results are deleted
    """
    
    try:
        mainDb = lamson.shivadbconfig.dbconnectmain()
        
        query = "truncate table learningresults"
        mainDb.execute(query)
        
        query = "truncate table rules"
        mainDb.execute(query)
        
    except mdb.Error, e:
        logging.error(e)
    
    
def get_permament_url_info(link=''):
    """
    returns stored infomation about URL
    """    
    try:
        mainDb = lamson.shivadbconfig.dbconnectmain()
        query = 'select longHyperLink,redirectCount,googlePageRank,alexaTrafficRank,inPhishTank from permamentlinkdetails where hyperLink = %s'
        
        mainDb.execute(query,(link,))
        result = mainDb.fetchone();
        
        if result:
            url_data = {}
            url_data['raw_link'] = link.replace('|', '').replace(' ','')      
            url_data['LongUrl'] = result[0]
            url_data['RedirectCount'] = result[1]
            url_data['GooglePageRank'] = result[2]
            url_data['AlexaTrafficRank'] = result[3]
            url_data['InPhishTank'] = result[4]
            return url_data
            
    except mdb.Error, e:
        logging.error(e)
        
    
    return {}

def get_permament_url_info_for_email(email_id=''):
    """
    return list of url_info
    """    

    result = []
    
    try:
        mainDb = lamson.shivadbconfig.dbconnectmain()
        query = 'select hyperLink from links where spam_id= %s;'
        
        mainDb.execute(query,(email_id,))
        links = mainDb.fetchall()
        
        for current in links:
            current_info = get_permament_url_info(current[0])
            if current_info:
                result.append(current_info)
            
    except mdb.Error, e:
        logging.error(e)
        
    return result


def store_permament_url_info(url_data={}):
    """
    stores pemament URL info 
    url_data={
        raw_link:''
        GooglePageRank=''
        RedirectCount=''
        LongUrl=''
        AlexaTrafficRank=''
        InPhishTank=''
    }
    """
    
    if not url_data or 'raw_link' not in url_data:
        return

    try:
        mainDb = lamson.shivadbconfig.dbconnectmain()
        
        query = 'insert into permamentlinkdetails (hyperLink,longHyperLink,redirectCount,googlePageRank,alexaTrafficRank,inPhishTank,date) values (%s , %s , %s , %s , %s , %s ,NOW())'
        mainDb.execute(query,(
                              str(url_data['raw_link']).replace('|', ''),
                              str(url_data['LongUrl']) if url_data['LongUrl'] else None,
                              int(url_data['RedirectCount']),
                              int(url_data['GooglePageRank']),
                              int(url_data['AlexaTrafficRank']),
                              '1' if url_data['InPhishTank'] else '0'
                              ))
    except mdb.Error, e:
        logging.error(e)
        
        
def get_detection_results_for_thresholds():
    """
    prepare results for threasholds computations
    returns tuple (sshivaScore, spamassassinScore, derivedPhishingStatus, phishingHumanCheck)
    """
    
    result = []
    try:
        mainDb = lamson.shivadbconfig.dbconnectmain()
        
        query = 'select  shivaScore, spamassassinScore, derivedPhishingStatus, phishingHumanCheck from email_classification_view'
        mainDb.execute(query)
        
        for current in mainDb.fetchall():
            result.append(current)
    except mdb.Error, e:
        logging.error(e)
        
    return result

def get_current_detection_thresholds():
    """
    get threshlolds from learning
    """
    
    try:
        query = 'select shiva_threshold, sa_threshold from learningreport order by learningDate desc limit 1'
        
        mainDb = lamson.shivadbconfig.dbconnectmain()
        mainDb.execute(query)
        
        result = mainDb.fetchone()
        if result:
            logging.info('THESHOLDS: ' + str(result))
            return result
    except mdb.Error, e:
        logging.error(e)
        
    return (0.5,0.5,)

