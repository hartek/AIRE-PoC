import json

from django.contrib.auth.decorators import login_required
from django.shortcuts import render

from airprofiling.classes.elkControler import ElasticSearcher
import airprofiling.conf.elkConfiguration as ELK_CONFIGURATION
elkControler = ElasticSearcher(ELK_CONFIGURATION)

from airprofiling.panels.search import getFilterElements

@login_required
def view(request, idTarget):

    data = getElementsOfDetail(request, idTarget)
    context_target = getContextOfDeviceFromData(request, data)
    context_tl_filter_apps = getCOntextOfAppsFilter(request, idTarget)
    context_tl_filter_wp = getCOntextOfWebpagesFilter(request, idTarget)

    previous_page = request.META.get("HTTP_REFERER")
    if previous_page and '/list' in previous_page:
        previous_page = 'list'  
    elif previous_page and '/search' in previous_page:
        previous_page = 'searcher'

    context = {
        'idTarget': idTarget,
        'idPage': 'detail',
        'previous_page': previous_page,
        'title': 'Detalle de pcaps',
        'subtitle': 'Detalle con la información de una captura',
        'kibana_host': ELK_CONFIGURATION.HOST,
        'kibana_port': ELK_CONFIGURATION.KIBANA_PORT,
        'apps_filters': context_tl_filter_apps,
        'webpages_filters': context_tl_filter_wp,
    }
    
    context.update(data.get('_source'))
    #context['apps'] = data.get('_source').get('apps'),
    context.update({'webpages':transformWebsiteData(data.get('_source').get('webpages'))}),
    context.update({'apps':transformAppsData(data.get('_source').get('apps'))}),
    context.update(context_target)

    return render(request, 'detail.html', context)


def getElementsOfDetail(request, idTarget):

    query = {"query":{ "ids":{ "values": [ idTarget ] } } }
    results = elkControler.makeQuery(query, doc_type="target")
    if results.get('total',0) > 0:
        data = results.get('hits')[0]
    else:
        data = {}
    return data


def getContextOfDeviceFromData(request, data):
    idParent = data.get('_parent')
    data = data.get('_source')
    parent_data = getDeviceData(idParent)
    device_data = parent_data.get('_source', {}).get('device_data',{})

    features_c = device_data.get('features_c')
    if features_c:
        features_c = features_c.split("\r\n")

    features = device_data.get('features')
    if features:
        features = features.split(", ")

    os = data.get('os_family')
    if os is not None:
        os += " {}".format(data.get('os_version', ''))
    else:
        os = device_data.get('os')

    browsers = data.get('browsers')
    if browsers is not None:
        browser = "{} {}".format(browsers[0].get('family'), browsers[0].get('version'))
    else:
        browser = device_data.get('browser')

    context_mobile = {
        'name':data.get('name'),
        'email':data.get('email'),
        'telephone':data.get('telephone'),

        'device_status':device_data.get('status'),
        'device_size':device_data.get('size'),
        'device_3g_bands':device_data.get('_3g_bands'),
        'device_4g_bands':device_data.get('_4g_bands'),
        'device_dimensions':device_data.get('dimensions'),
        'device_weight':device_data.get('weight'),
        'device_sensors':device_data.get('sensors'),
        'device_resolution':device_data.get('resolution'),
        'device_os':device_data.get('os'),
        'device_features_c':features_c,
        'device_features':features,
        'device_internal':device_data.get('internal'),
        'device_cpu':device_data.get('cpu'),
        'device_chipset':device_data.get('chipset'),
        'device_video':device_data.get('video'),
        'device_name':device_data.get('DeviceName'),
        'device_messaging':device_data.get('messaging'),
        'device_wlan':device_data.get('wlan'),

        'device_browser':browser,
        'device_os': os,
        'device_brand': data.get('brand', device_data.get('Brand')),
        'device_model': data.get('device', device_data.get('DeviceName')),
    }

    return context_mobile


def getDeviceData(idParent):
    data = elkControler.getFromElasticsearch(idParent, doc_type = "devices")
    return data

def transformWebsiteData(websiteData):
    data = []
    for website in websiteData:
        categories = []
        uri_data = []
        protocols = []
        for uri in website.get('uri',{}):
            proto = uri.get("protocol").upper()
            if proto and proto not in protocols:
                protocols.append(proto) 

            for category in uri.get('type'):
                if category not in categories:
                    categories.append(category)

            uri_data.append({
                'fullurl':uri['fullurl'],
                'uri':uri['uri'],
                'times_visited':len(uri['time'])
            })

        data.append({
            'protocol' : ', '.join(protocols),
            'url' : website.get('url', '-'),
            'types' : ', '.join(categories),
            'uri' : uri_data
        })

    return data


def transformAppsData(appsData):
    data = []
    discovered_dic = {
        'DNS' : "Reconocimiento del DNS (reverse lookup)",
        'URL_HTTP' : "Reconocimiento del dominio (en HTTP)",
        'URL_HTTPS' : "Reconocimiento del dominio (en HTTPS)",
        'UserAgent' : "Identificación del User Agent",
    }
    for app in appsData:    
        
        data.append({
            'name' : app.get('name'),
            'time' : app.get('time'),
            'discovered' : [ discovered_dic.get(method, method) for method in app.get('discovered', []) ],
        })

    return data

def getCOntextOfAppsFilter(request, idTarget):
    return getFilterElements('apps.name', 'target', id=idTarget)

def getCOntextOfWebpagesFilter(request, idTarget):
    return getFilterElements('webpages.url', 'target', id=idTarget)
