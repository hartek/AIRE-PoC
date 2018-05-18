#!/usr/bin/env python3
from elasticsearch import Elasticsearch, RequestsHttpConnection
import json
from datetime import datetime

class ElasticSearcher(object):
    def __init__(self, ConfigData):
        self._HOST = ConfigData.HOST
        self._PORT = ConfigData.ELASTIC_PORT
        self._INDEX = ConfigData.INDEX

        # Inicializa las clases auxiliares
        self.elasticsearch = Elasticsearch(
            hosts=[{'host': self._HOST , 'port': int(self._PORT)}],
            connection_class=RequestsHttpConnection
        )


    def getFromElasticsearch(self, id, doc_type=None, routing=None, ignore = []):
        data = self.elasticsearch.get(index=self._INDEX, doc_type=doc_type, id=id, routing=routing, ignore=ignore)
        try:
            if data['found'] == False:
                return None
        except KeyError:
            raise Exception(data)
        return data


    def makeQuery(self, query, doc_type = None, filter_path=[], ignore = []):
        response = self.elasticsearch.search(index=self._INDEX, doc_type=doc_type, body=query, filter_path=filter_path, ignore = [])
        return response['hits']


    def getListOfUniqueElements(self, field, doc_type, order = "asc", id = None):

        query = {
            "size" : 0,
            "aggs" : {
                "unique_elements" : {
                    "terms" : {
                        "field" : field,
                        "order": { "_term" : order }
                    }
                }
            }
        }
        if id:
            query["query"] = { "ids" : { "values" : [id]} }

        query = json.dumps(query)
        response = self.elasticsearch.search(index=self._INDEX, doc_type=doc_type, body=query)

        results = []
        for bucket in response['aggregations']['unique_elements']['buckets']:
            results.append(bucket.get('key',''))

        return results


    def countResultsOfQuery(self, query, doc_type = None, filter_path=[]):
        response = self.elasticsearch.count(index=self._INDEX, doc_type=doc_type, body=query, filter_path=filter_path)
        return response


    def createDocument(self, id, data, doc_type, parent_id=None):
        query = json.dumps(data)
        response = self.elasticsearch.index(index=self._INDEX, op_type='index', doc_type=doc_type, id=id, body=query, parent=parent_id)
        return response['_id']


    def updateDocument(self, id, data, doc_type, parent_id=None):
        query = json.dumps({"doc":data})
        response = self.elasticsearch.update(index=self._INDEX, doc_type=doc_type, id=id, body=query, parent=parent_id)
        return response['_id']


    def parseEpochToDatetime(self, epoch_mills, format="%Y-%m-%d %H:%M:%S"):
        if not epoch_mills: return ''
        timestamp = epoch_mills / 1000.0
        return datetime.fromtimestamp(timestamp).strftime(format)


    def parseDatetimeToEpoch(self, date, format="%Y-%m-%d %H:%M:%S.%f"):
        if not date: return date
        return int(datetime.strptime(date, format).timestamp() * 1000)
