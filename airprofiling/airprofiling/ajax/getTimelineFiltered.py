from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from django.template import Context, loader

from airprofiling.classes.elkControler import ElasticSearcher
import airprofiling.conf.elkConfiguration as ELK_CONFIGURATION
elkControler = ElasticSearcher(ELK_CONFIGURATION)

@login_required
def view(request, idTarget):
    html = getHtmlOfTimeline(request, idTarget)
    data = {"status":"OK", "html":html}
    return JsonResponse(data)


def getHtmlOfTimeline(request, idTarget):
    timeline_data = getDataOfTimeline(request, idTarget)
    context_table = getContextOfTimeline(request, timeline_data)
    tpl = loader.get_template('detail_panels/timeline_data.html')
    return tpl.render(context_table)


def getContextOfTimeline(request, data):
    format_date = "%Y-%m-%d"
    init_date = elkControler.parseDatetimeToEpoch(request.GET.get('init_date'), format_date)
    end_date = elkControler.parseDatetimeToEpoch(request.GET.get('end_date'), format_date)

    timedata = processAppDataOfTimeline(data.get('apps', {}))
    timedata += processWebpageDataOfTimeline(data.get('webpages', {}))

    timeline = orderAndBeautifyTimeline(timedata, init_date, end_date)
    return {'timeline': timeline}    


def getDataOfTimeline(request, idTarget):
    apps = request.GET.get('apps', 'all')
    webpages = request.GET.get('webpages', 'all')
    search_term = request.GET.get('search_term', '')

    query = {
        "_source" : ["apps", "webpages"],
        "query": {
            "bool": {
                "must" : [
                    {
                        "term": {
                            "_id" : idTarget
                        }
                    }
                ]
            }
        }
    }

    inner_hits_apps = False
    if apps not in ["all", 'none'] or len(search_term) > 0:
        query_apps = getQueryInternByPath(search_term, "apps.name", apps, "apps", ["apps.name"])
        query['query']['bool']['must'].append(query_apps)
        inner_hits_apps = True
        
    inner_hits_webpages = False
    if webpages not in ["all", 'none'] or len(search_term) > 0:
        query_webpages = getQueryInternByPath(search_term, "webpages.url", webpages, "webpages", ["webpages.url", "webpages.uri.uri", "webpages.uri.type"])
        query['query']['bool']['must'].append(query_webpages)
        inner_hits_webpages = True
    
    results = elkControler.makeQuery(query, doc_type = "target", ignore=[404, 400])

    apps_data = getResultsOfQueryByType(results, 'apps', apps, inner_hits_apps)
    webpages_data = getResultsOfQueryByType(results, 'webpages', webpages, inner_hits_webpages)

    return {'webpages' : webpages_data, 'apps' : apps_data}
    


def getQueryInternByPath( search_term, filter_field, filter_term, path, fields):
        query_intern = []
        if len(filter_term) > 0 and filter_term not in ["all", 'none']:
            query_intern.append( { "term" : { filter_field : filter_term } } )

        if len(search_term) > 0:
            query_intern.append( getSearchTermQuery(search_term, fields) )

        return {
            "nested" : {
                "path" : path, 
                "query" : { 
                    "bool" : {
                        "must" : query_intern
                    }
                },
                "inner_hits" : {}
            }
        }


def getSearchTermQuery(search_term, fields = []):
    return {"query_string" : { 
                "query" : "*{}*".format(search_term),
                "fields" : fields 
                } 
            } 
             

def getResultsOfQueryByType(results, type, value, isInner = False):
    if isInner:
        return getInnerHitsFromResults(results, type)
    elif value == 'none':
        return []
    else:            
        return results['hits'][0]['_source'].get(type, {})


def getInnerHitsFromResults(data, path):
    if len(data['hits']) == 0: return []
    data_hits = data['hits'][0].get('inner_hits',{}).get(path, {}).get('hits', {}).get('hits', [])
    return [ data_hit.get('_source') for data_hit in data_hits ]

def processAppDataOfTimeline(apps):
    timedata = []
    for app_data in apps:
        app_name = app_data.get('name')
        header = "Conexión de la aplicación {}".format(app_name)
        body = ''
        app_time_cache = []
        for app_time in app_data.get('time',{}):
            if int(app_time/1000) in app_time_cache: continue
            app_time_cache.append(int(app_time/1000))
            timedata.append({
                'type': "app",
                'app_name': app_name,
                'header': header,
                'body': body,
                'time': app_time
            })

    return timedata


def processWebpageDataOfTimeline(webpages):
    timedata = []
    for webpage in webpages:
        for uri in webpage.get('uri',{}):
            web_time_cache = []
            for web_time in uri.get('time',{}):
                if int(web_time/1000) in web_time_cache: continue
                web_time_cache.append(int(web_time/1000))
                url = "{}://{}".format(uri.get('protocol',''), webpage.get('url'))
                if len(uri.get('type',[])):
                    categorias = "Categorizado como: <b>{}</b>".format(','.join(uri.get('type',[])))
                else:
                    categorias = ""
                timedata.append({
                    'type': "{}".format(uri.get('protocol')),
                    'url': "{}".format(webpage.get('url')),
                    'fullurl': "{}".format(uri.get('fullurl')),
                    'uri': "{}".format(uri.get('uri')),
                    'categorias': ','.join(uri.get('type',[])),
                    'time': web_time
                    #'header': 'Conexión con el dominio <a target="_blank" href="{0}">{0}</a>'.format(url),
                    #'body': "Se ha realiado una conexión con <a target='_blank' href='{0}{1}'>{0}{1}</a><br/>{2}".format(url, uri.get('uri',''), categorias),
                })
    return timedata


def orderAndBeautifyTimeline(timedata, init_date = None, end_date = None):
    # Ordena la lista
    from operator import itemgetter
    timeline = sorted(timedata, key=itemgetter('time'), reverse=True) #reverse=True

    final_timeline = []
    i = 0
    for timeline_elem in timeline:
        if init_date and timeline_elem['time'] < init_date: 
                continue
        if end_date and timeline_elem['time'] > end_date: 
                continue
        
        if i%2 == 1:
            timeline_elem['class'] = 'timeline-inverted'
        i += 1

        if timeline_elem['type'] != 'app':
            timeline_elem['url_dic'] = "{}://{}".format(timeline_elem['type'], timeline_elem['url'])
            timeline_elem['uri_dic'] = "{}{}".format(timeline_elem['url_dic'], timeline_elem['uri'])[0:100]
            timeline_elem['uri_dic_text'] = (timeline_elem['uri_dic'][:75] + '..') if len(timeline_elem['uri_dic']) > 75 else timeline_elem['uri_dic']

        timeline_elem['time'] = elkControler.parseEpochToDatetime(timeline_elem['time'],format="%Y/%m/%d %H:%M:%S")
        final_timeline.append(timeline_elem)
    
    return final_timeline