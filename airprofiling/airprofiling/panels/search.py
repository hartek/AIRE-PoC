import json
from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from django.template import Context, loader

from airprofiling.classes.elkControler import ElasticSearcher
import airprofiling.conf.elkConfiguration as ELK_CONFIGURATION
elkControler = ElasticSearcher(ELK_CONFIGURATION)

from airprofiling.panels.list import getContextOfTableFromResults, OS_DICTIONARY

@login_required
def view(request, search_term = ''):

    data = getElementsOfList(request, search_term)
    context_table = getContextOfTableFromResults(request, data)
    context_filters = getContextOfFilters(request, search_term)

    context = {
        'idPage': "searcher",
        'title_icon': "fa-search",
        'title': 'Búscador',
    }
    context.update(context_table)
    context.update(context_filters)

    return render(request, 'search.html', context)


def getContextOfFilters(request, search_term = ''):
    init_date = request.GET.get("init_date", "")
    end_date = request.GET.get("end_date", "")
    search_term = request.GET.get("search_term", search_term)
    if not search_term: search_term = ''
    apps = request.GET.get("apps", "")
    os = request.GET.get("os", "")
    brand = request.GET.get("brand", "")
    browser = request.GET.get("browser", "")

    apps_filters = [
        {'title':"Todos", "value":'*', "fa":''}
    ]
    apps_filters += getAppsFromElk(request)

    brand_filters = [
        {'title':"Todos", "value":'*', "fa":''}
    ]
    brand_filters += getBrandsFromElk(request)

    browser_filters = [
        {'title':"Todos", "value":'*', "fa":''}
    ]
    browser_filters += getBrowsersFromElk(request)
        
    os_filters = [
        {"title":"Todos", "value":'*', "fa":''}
    ]
    os_filters += getOsFromElk(request)
    for filter_data in os_filters:
        filter_data['fa'] = OS_DICTIONARY.get(filter_data['value'].lower)

    context_filters = {
        'os_filters' : os_filters,
        'apps_filters' : apps_filters,
        'brand_filters' : brand_filters,
        'browser_filters' : browser_filters,
        #
        'search_term' : search_term,
        'init_date' : init_date,
        'end_date' : end_date,
        'apps' : apps,
        'os' : os,
        'brand' : brand,
        'browser' : browser,
    }
    return context_filters


def getAppsFromElk(request):
    return getFilterElements('apps.name', 'target')


def getBrandsFromElk(request):
    return getFilterElements('brand', 'devices')


def getBrowsersFromElk(request):
    return getFilterElements('browsers.family', 'target')

def getOsFromElk(request):
    return getFilterElements('os_family', 'target')


def getFilterElements(field, doc_type, id=None, order="asc"):
    elements = elkControler.getListOfUniqueElements(field, doc_type, order=order, id=id)
    
    filter_data = []
    for element in elements:
        filter_data.append({
            'title':element,
            'value':element,
            'fa':''
        })
    return filter_data


def getElementsOfList(request, search_term = ''):
    query = {
        "sort": [
            { "@timestamp" : {"order" : "asc"}}
        ]
    }

    init_date = request.GET.get("init_date", "")
    end_date = request.GET.get("end_date", "")
    
    search_term = request.GET.get("search_term", search_term)
    if not search_term: search_term = ''

    apps = request.GET.get("apps", "")
    browser = request.GET.get("browser", "")
    os = request.GET.get("os", "")
    brand = request.GET.get("brand", "")


    if haveFilters(request):
        if "query" not in query: query["query"] = {}
        query["query"]["bool"] = {}
        filters_query = []

        if len(search_term) > 0:
            filters_query.append(
                {"match" : { "_all" : search_term } }
            )

        if len(apps):
            filters_query.append(
                {"term" : { "apps.name" : apps } }
            )

        if len(os):
            filters_query.append(
                { "term" : { "os_family" : os } }
            )

        if len(browser):
            filters_query.append(
                { "term" : { "browser.family" : browser } }
            )
        
        if len(brand):
            filters_query.append(
                { "term" : { "brand" : brand } }
            )

        if len(init_date) > 0 or len(end_date) > 0:
            query_range = { "range" : { "@timestamp" : {}} }
            if len(init_date) > 0:
                query_range["range"]["@timestamp"]['gte'] = init_date
            if len(end_date) > 0:
                query_range["range"]["@timestamp"]['lte'] = end_date

            filters_query.append(query_range)

        query['query']['bool']['must'] = filters_query    

    query = json.dumps(query)

    results = elkControler.makeQuery(query, doc_type = "target")

    return results


def haveFilters(request):
    init_date = request.GET.get("init_date", "")
    end_date = request.GET.get("end_date", "")
    search_term = request.GET.get("search_term", "")
    apps = request.GET.get("apps", "")
    os = request.GET.get("os", "")
    brand = request.GET.get("brand", "")
    browser = request.GET.get("browser", "")

    length = len(init_date) + len(end_date) + len(search_term) + len(apps) + len(os) + len(brand) + len(browser)
    return length > 0


def getHtmlOfTable(request):
    data = getElementsOfList(request)
    context_table = getContextOfTableFromResults(request, data)
    tpl = loader.get_template('search_panels/table.html')
    return tpl.render(context_table)