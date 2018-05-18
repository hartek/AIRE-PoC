from django.shortcuts import render

from django.contrib.auth.decorators import login_required

# CONFIGURACION DEL SERVIDOR CON ELASTICSEARCH Y KIBANA
from airprofiling.classes.elkControler import ElasticSearcher
import airprofiling.conf.elkConfiguration as ELK_CONFIGURATION
elkControler = ElasticSearcher(ELK_CONFIGURATION)

import json

@login_required
def view(request):

    devicesAnalyzed = getDevicesAnalyzedLastMonth()
    packetsAnalyzed = getPacketsAnalyzedLastMonth()
    context = {
        'title': 'Dashboard',
        'idPage': 'dashboard',
        'subtitle': '',
        'kibana_host': ELK_CONFIGURATION.HOST,
        'kibana_port': ELK_CONFIGURATION.KIBANA_PORT,
        'devicesAnalyzed': devicesAnalyzed,
        'packetsAnalyzed': packetsAnalyzed,
    }

    return render(request, 'dashboard.html', context)


def getDevicesAnalyzedLastMonth():
    query = { "query": {"match_all": { } } }
    query = json.dumps(query)
    results = elkControler.countResultsOfQuery(query, doc_type = "target")
    return results['count']


def getPacketsAnalyzedLastMonth():
    query = { "query": {"match_all": { } } }
    query = json.dumps(query)
    results = elkControler.countResultsOfQuery(query, doc_type = "pcap")
    return results['count']