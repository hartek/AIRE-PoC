import json
import math

from django.shortcuts import render

from django.contrib.auth.decorators import login_required

from airprofiling.classes.elkControler import ElasticSearcher
import airprofiling.conf.elkConfiguration as ELK_CONFIGURATION
elkControler = ElasticSearcher(ELK_CONFIGURATION)


OS_DICTIONARY = {
    'ios':'apple',
    'android':'android',
    'windows':'windows'
}

@login_required
def view(request):

    data = getElementsOfList(request)
    context_table = getContextOfTableFromResults(request, data)
    context = {
        'idPage': "list",
        'title_icon': "fa-list",
        'title': 'Listado de capturas',
        'subtitle': 'Listado con los pcaps capturados',
    }
    context.update(context_table)

    return render(request, 'list.html', context)


def getElementsOfList(request):
    
    query = {
        "sort": [
            { "@timestamp" : {"order" : "asc"}}
        ],
        "query": {
            "has_parent": {
                "parent_type" : "devices"
            }
        }
    }

    """
    init_date = request.GET.get("init_date", "")
    end_date = request.GET.get("end_date", "")

    if len(init_date) or len(end_date):
        query["query"]["@timestamp"] = {"format":"yyyy-mm-dd"}
        if len(init_date):
            query["query"]["@timestamp"]['gte'] = init_date
        if len(end_date):
            query["query"]["@timestamp"]['lte'] = end_date
    """
    query = json.dumps(query)


    results = elkControler.makeQuery(query, doc_type = "target")
    return results


def getContextOfTableFromResults(request, results):
    context = {}

    
    context['targets'] = []
    for target in results['hits']:
        target_data = target.get('_source')
        timestamp = target_data.get('@timestamp')
        target_tpl = {
            'ID': target.get('_id'),
            'MAC': target_data.get('mac'),
            'DEVICE': target_data.get('brand','-') + ' ' + target_data.get('device',''),
            'DATE': elkControler.parseEpochToDatetime(timestamp),
            'OS': OS_DICTIONARY.get(target_data.get('os_family').lower()),
            'OS_TITLE': target_data.get('os_family', '') + ' ' + target_data.get('os_version', ''), 
            'OS_VERSION': target_data.get('os_version'),
            'N_APPS': len(target_data.get('apps')),
            'N_WEBPAGES': len(target_data.get('webpages')),
            'N_IPS': len(target_data.get('ip_addr')),
            'BROWSER': target_data.get('browsers')[0].get('family'),
            'BROWSER_VERSION': target_data.get('browsers')[0].get('version'),
        }
        context['targets'].append(target_tpl)

    return context

def getHtmlOfTableFromResults(request, results):
    context = getContextOfTableFromResults(request, results)
    html = render(request, 'list_panels/table.html', context)