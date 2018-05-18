#!/usr/bin/env python3
import logging
import requests
import json

class RestApiControler(object):

    def __init__(self, ConfigFile):
        self._HOST = ConfigFile.HOST
        self._PORT = ConfigFile.PORT
        self._URI = ConfigFile.URI
        self._URI_DOWNLOAD = ConfigFile.URI_DOWNLOAD
        self._URI_UPLOAD = ConfigFile.URI_UPLOAD
        self._AUTHTOKEN = ConfigFile.AUTHTOKEN
        self._URL_REQUEST = "http://{}:{}{}".format( self._HOST, self._PORT, self._URI )
        logging.basicConfig(level=logging.INFO)


    def setDefaultHeaders(self):
        self.uri = ''
        self.payload = {}
        self.headers = {"Authorization":"Token {}".format(self._AUTHTOKEN)}


    def getAllData(self):
        self.setDefaultHeaders()
        return self._makeGetRequest()


    def getNotParsedData(self):
        """
        Obtiene los datos no parseados.
        """
        self.setDefaultHeaders()
        self.uri = "?status=0"
        return self._makeGetRequest()


    def getParsedData(self):
        """
        Obtiene los datos no analizados
        """
        self.setDefaultHeaders()
        self.uri = "?status=1"
        return self._makeGetRequest()


    def getAnalyzedData(self):
        """
        Obtiene los datos analizados
        """
        self.setDefaultHeaders()
        self.uri = "?status=2"
        return self._makeGetRequest()


    def getDataWithErrors(self):
        """
        Obtiene los datos analizados
        """
        self.setDefaultHeaders()
        self.uri = "?status=-1"
        return self._makeGetRequest()


    def getPcapData(self, id):
        """
        Descarga el archivo.
        """
        self.setDefaultHeaders()
        self.uri=self._URI_DOWNLOAD + "/{}".format(id)
        return self._makeGetRequest(stream = True)


    def _makeGetRequest(self, stream = False, url = ""):
        if url is not None:
            url = self._URL_REQUEST + self.uri

        logging.debug('Making request to: {} width headers "{}" and payload "{}"'.format(url, self.headers, self.payload))
        response = requests.get(url, data=self.payload, headers=self.headers, stream = stream)

        if response.status_code != 200:
            response.raise_for_status()

        if stream:
            ret = self._returnDataResponse(response)
        else:
            ret = self._returnJsonResponse(response)

        return ret


    def setFileAsError(self, id):
        """
        Actualiza un registro con el estado -1
        """
        self.headers['Content-Type'] = 'application/json'
        self.uri = "update/error/{}/".format(id)

        return self._makePostRequest()


    def uploadParsedJson(self, id, json_data):
        """
        Actualiza un registro de la api (identificado por el id), actualizando el estado y subiendo el json.
        """
        self.setDefaultHeaders()
        self.headers['Content-Type'] = 'application/json'
        self.uri = "update/parsed/{}/".format(id)

        parsed_data = json.dumps(json_data)
        data = {
            "parsed_json" : parsed_data,
        }
        self.payload = data
        logging.debug('Subiendo archivo parseado de longitud {} a : {} width headers "{}" and payload "{}"'.format(len(json.dumps(json_data)), self.uri, self.headers, self.payload))

        return self._makePostRequest()


    def uploadAnalyzedJson(self, id, json_data):
        """
        Actualiza un registro de la api subiendo un array con los datos enviados a ELK
        """
        self.setDefaultHeaders()
        self.headers['Content-Type'] = 'application/json'
        self.uri = "update/analyzed/{}/".format(id)
        data = {
            'analyzed_json' : json_data,
        }
        self.payload = data

        return self._makePostRequest()



    def _makePostRequest(self):
        url = self._URL_REQUEST + self.uri

        logging.debug('Making request to: {} width headers "{}" and payload "{}"'.format(url, self.headers, self.payload))

        response = requests.post(url, json=self.payload, headers=self.headers, verify=False)
        if response.status_code != 200:
            response.raise_for_status()

        return response.json()


    def _returnDataResponse(self, response):
        response.raw.decode_content = True
        return response.raw


    def _returnJsonResponse(self, response):

        if response.status_code != 200:
            response.raise_for_status()
        """
        data = response.json()['results']

        # si tiene más de una página, obtiene el resto
        if response.json()['next']:
            url = response.json()['next']
            data_next = self._makeGetRequest(url = url)
            data.concat(data.next)
        """
        data = response.json()
        return data

