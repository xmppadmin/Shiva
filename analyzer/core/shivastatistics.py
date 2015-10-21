
import logging

import matplotlib.pyplot as plot
import numpy as np


import shivamaindb


from phishing import rulelist


    
    

    

def generate_statistics(filterType="none"):
    """
    apply all MailClassificationRules from rulelist on
    each mail in the database
    """  
    
    statmatrixunique = prepare_matrix(filterType,matrixType='statistics')
    output_graphs(statmatrixunique, unique=True, filterType=filterType)
  

def prepare_matrix(filterType="none", matrixType="none"):
    """ 
    filterType = ('none','phish','spam')
        none - all emails in databse will be used
        phish - only emails marked as 'phishing' will be used
        spam - only spam emails will be used (not marked as 'phishing')
    
    matrixType = ('none','learning','statistics')
        none - return n*m matrix containing raw results only
        learning - return (n+1)*m matrix, first row contains 
                   vector of weights used for learning
        statistics - return (n+1)*m matrix, first row contains 
                   vector of strings describing rules
    
    
    apply phishing rules on all emails in database
    and prepare matrix from results for further processing
    """
    
    statmatrixunique = []
    
    if matrixType == 'statistics':
        statmatrixunique.append(rulelist.get_rule_names())
    elif matrixType == 'learning':
        statmatrixunique.append(rulelist.get_vector_weigths())
        
    recordcount = 0
    while True:
        
        records = shivamaindb.retrieve(10, recordcount, filterType)
        if len(records) == 0 :
            break
        for record in records:
            recordcount += 1
            recordresult = process_single_record(record)
            statmatrixunique.append(recordresult)
    
    return statmatrixunique

    

def process_single_record(mailFields):
    
    used_rules = []
    computed_results = []
    result = []
    for rule in rulelist.get_rules():
        rule_result = rule.apply_rule(mailFields)
        result.append(rule_result)
        used_rules.append({'code': rule.get_rule_code(), 'description': rule.get_rule_description()})
        computed_results.append({'spamId': mailFields['s_id'], 'code': rule.get_rule_code(), 'result': rule_result})
        
        
    shivamaindb.store_computed_results(computed_results,used_rules)
    return result

def output_graphs(statmatrix, unique=False, filterType="none"):
    aggregated = aggregate_statistics(statmatrix)
    arr = np.arange(len(statmatrix[0]))
    barwidth = 0.35
    bars = plot.bar(arr, aggregated)
    
    plot.xticks(arr + barwidth, map(lambda a: a[:a.index(':')], statmatrix[0]))

    colors = 'rgkymcb'
    for i in range(0,len(arr)):
        bars[i].set_color(colors[i % 7])
        
    """TODO load settings from configuration files"""

    legend = plot.legend(bars, statmatrix[0], loc='upper center', bbox_to_anchor=(0.5,-0.1))
    title =  'SHIVA honeypot - statistics of ' + str(len(statmatrix) -1)
    outfile = 'plot'
    if unique:
        outfile += '-unique'
        title += ' unique '
    if filterType == "spam":
        title += ' SPAM'
        outfile += '-spam'
    elif filterType == "phish":
        title += ' PHISHING'
        outfile += '-phishing'
    else:
        title += ' ALL'
        outfile += '-all'
    title += ' emails'
    outfile += '.png'
    plot.title(title)
    plot.savefig(outfile, bbox_extra_artists=(legend,), bbox_inches='tight')
    plot.close()
    
def aggregate_statistics(statmatrix):
    aggregated = list();
    for i in range(0,len(statmatrix[0])):
        aggregated.append(0);
    
    for row in range(1, len(statmatrix)):
        for column in range(0, len(statmatrix[i])):
            aggregated[column] += statmatrix[row][column]
    
    return aggregated


def generate_rules_graph(data={}):
        
    color_list = 'rgbcmyk'
    color_index = 0
    rule_codes = data['_rule_codes']   

    for sensor, rule_vals in data.iteritems():
        if sensor.startswith('_rule') or sensor.startswith('_total'):
            continue
        current_color = color_list[color_index % 7]
        color_index += 1
        sensor_total = data['_total_' + sensor]
        plot.plot(np.arange(len(rule_vals)) + 0.5, map(lambda a: (a / float(sensor_total)) * 100, rule_vals), 
                label=sensor + ' ({})'.format(sensor_total), 
                linestyle='-',
                linewidth=0.8,
                color=current_color,
                markerfacecolor=current_color,
                markersize=12, 
                marker='o', 
                antialiased=True)
    
    plot.xticks(np.arange(len(rule_codes)) + 0.5, rule_codes)
    plot.legend(loc='upper center', bbox_to_anchor=(0.5,-0.2))
    
    
    plot.grid(True)
    plot.xlabel('Rules',fontsize=18)
    plot.ylabel('Percentage of matching rules',fontsize=18)
    plot.title("Statistics of rules matching by source of email\n", fontsize=20)
    
    plot.savefig('../../../web/images/rules_graph.png', bbox_inches='tight')
    plot.close()

         
            
    
        

