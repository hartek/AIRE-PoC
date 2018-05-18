#!/usr/bin/env python3
import os
import sys
import json
import logging
import operator
sys.path.append(os.path.abspath(os.path.dirname(__file__))+'/../../airprofiling')

from airprofiling.classes.elkControler import ElasticSearcher
from classes.pcapAnalyzer import PcapAnalyzer

from elasticsearch import Elasticsearch, RequestsHttpConnection

FORMAT = '%(asctime)s %(levelname)s %(message)s'
logging.basicConfig(format=FORMAT)
logger = logging.getLogger('analizePcapData')
logger.setLevel(logging.INFO)


class AnalyzerElasticControler(ElasticSearcher):

    def __init__(self, ConfigurationData, Tokens):
        super(AnalyzerElasticControler, self).__init__(ConfigurationData)

        # Inicializa las clases auxiliares
        self.analyzer = PcapAnalyzer(Tokens)
        self._unsetData()


    def analizeJson(self, parsed_json):
        """
        Debe de darle valor a los datos, y guardarlo
        """
        parsed_json = json.loads(parsed_json)
        self._unsetData()

        # 1. Fija los datos del target.
        self.setTargetData(parsed_json)

        # 2. Analiza los User Agents para extraer la información relevante.
        self.analyzeUserAgentsData(parsed_json)

        # 3. Saca la información de las ips que pueda.
        self.extractGeoIpInformation(parsed_json)

        # 4. Analiza las webpages para sacar los tipos
        self.extractWebpagesInformation(parsed_json)

        # 5. Crea el archivo con los datos técnicos de las capturas
        self.extractTechnicalInfoFromJson(parsed_json)


    def _unsetData(self):
        self.device = {'ID':None, 'data':{}}
        self.target = {'ID':None, '_parent':None, 'data':{}}
        self.pcap = {'ID':None, '_parent':None, 'data':{}}
        self._browserUserAgents = []
        self._appsUserAgents = {}
        self._cached_ip_data = []


    def setTargetData(self, parsed_json):
        self.mac_data = {
            'mac' : self.analyzer.getTargetMac(parsed_json),
            'mac_ap' : parsed_json.get('mac_ap')
        }

        query = {"query":{ "ids":{ "values": [ self.mac_data['mac'] ] } } }
        results = self.makeQuery(query, doc_type="target")
        if results.get('total',0) > 0:
            data = results.get('hits')[0]
        else:
            data = {}

        self.initializeTargetWithElasticData(data, parsed_json)


    def initializeTargetWithElasticData(self, target_data, parsed_json):
        self.target['ID'] = target_data.get('_id', None)
        self.target['_parent'] = target_data.get('_parent', None)
        self.target['data'] = {
            # TODO: Están mal las fechas
            '@timestamp' : target_data.get('@timestamp'),
            'last_timestamp' : target_data.get('last_timestamp'),
            'device' : target_data.get('device',''),
            'brand' : target_data.get('brand',''),
            'mac' : target_data.get('mac', self.mac_data['mac']),
            'mac_ap' : target_data.get('mac_ap', self.mac_data['mac_ap']),
            'email' : target_data.get('email',''),
            'telephone' : target_data.get('telephone',''),
            'os_family' : target_data.get('os_family',''),
            'os_version' : target_data.get('os_version',''),

            'ip_addr' : target_data.get('ip_addr',[]),
            'browsers' : target_data.get('browsers', []),
            'webpages' : target_data.get('webpages', []),
            'apps' : target_data.get('apps', []),
            'user_agents' : target_data.get('user_agents', []),
        }
        # Añade las fechas
        self.setTimestampData(parsed_json)

        # Carga información del dispositivo padre
        device_parent = self.loadDeviceFromElastic(target_data.get('_parent', None))
        self.device['ID'] = device_parent.get('_id')
        self.device['data'] = {
            'brand' : device_parent.get('brand', ''),
            'device' : device_parent.get('device', ''),
            'vendor' : device_parent.get('vendor', ''),
            'image' : device_parent.get('image', ''),
            'is_tablet' : device_parent.get('is_tablet', False),
            'is_mobile' : device_parent.get('is_mobile', False),
            'is_pc' : device_parent.get('is_pc', False),
            'device_data' : device_parent.get('device_data', {})
        }


        # Carga información de la captura
        pcap_id = self.getPcapId()
        pcap_data = self.loadPcapDataFromElastic(pcap_id, )
        self.pcap['ID'] = pcap_data.get('_id')
        self.pcap['_parent'] = pcap_data.get('_parent')
        self.pcap['data'] = {
            'init_time' : device_parent.get('init_time', ''),
            'end_time' : device_parent.get('end_time', ''),
            'mac' : device_parent.get('mac', ''),
            'mac_ap' : device_parent.get('mac_ap', ''),
            'size' : device_parent.get('size'),
            'tcp_size' : device_parent.get('tcp_size'),
            'udp_size' : device_parent.get('udp_size'),
            'network_sizes' : device_parent.get('network_sizes', []),
            'transport_sizes' : device_parent.get('transport_sizes', []),
            'protocol' : device_parent.get('protocol', []),
        }



    def getPcapId(self):
        return self.target['data']['mac'].replace(':','') + str(self.target['data']['@timestamp'])


    def loadDeviceFromElastic(self, device_id):
        if not device_id:
            return {}
        data = self.getFromElasticsearch(device_id, doc_type='devices', ignore=[400, 404])
        if not data: return {}
        return data


    def loadPcapDataFromElastic(self, pcap_id):
        if not pcap_id:
            return {}
        data = self.getFromElasticsearch(pcap_id, doc_type='pcap', routing="target", ignore=[400, 404])
        if not data: return {}
        return data

    ###
    # Fechas
    ###

    def setTimestampData(self, parsed_json):
        timestamp = parsed_json.get('first_timestamp')
        last_timestamp = parsed_json.get('last_timestamp')
        format_timestamp = "%Y-%m-%d %H:%M:%S.%f"
        self.target['data']['@timestamp'] = self.parseDatetimeToEpoch(timestamp, format=format_timestamp)
        self.target['data']['last_timestamp'] = self.parseDatetimeToEpoch(last_timestamp, format=format_timestamp)

    ###
    # User Agent
    ###
    def analyzeUserAgentsData(self, parsed_json):

        user_agents = self.analyzer.getUserAgentsFromJson(parsed_json)

        device_model = ''
        search_device_data = True
        if self.device.get('data'):
            device_model = self.device.get('data').get('device')
            if len(self.device.get('data').get('device_data')) > 0:
                search_device_data = False

        for user_agent in user_agents:
            ua_data_extracted = self.analyzer.analyzeUserAgent(user_agent, device_model, search_device_data)

            self.processUserAgentExtractedData(ua_data_extracted)
            # Si ha encontrado datos, que no lo vuelva a buscar
            if self.device.get('data'):
                device_model = self.device.get('data').get('devic', '')
                if len(device_model) > 0 and len(self.device.get('data').get('device_data', {})) > 0:
                    search_device_data = False


    def processUserAgentExtractedData(self, data_ua):
        user_agent = data_ua.get('original_string')
        if user_agent not in self.target['data']['user_agents']:

            self.setBooleanValueToDevice('is_tablet', data_ua.get('is_tablet'))
            self.setBooleanValueToDevice('is_pc', data_ua.get('is_pc'))
            self.setBooleanValueToDevice('is_mobile', data_ua.get('is_mobile'))

            if len(data_ua.get('os_family','')) > 0 and data_ua.get('os_family') != 'Other' and len(data_ua.get('os_version_string','')) > 0 and data_ua.get('os_version_string') != 'Other':
                self.setStringValueToTarget('os_family', data_ua.get('os_family'))
                self.setStringValueToTarget('os_version', data_ua.get('os_version_string'))

            self.setStringValueToDevice('device_family', data_ua.get('device_family'))
            self.setStringValueToDevice('device_version', data_ua.get('device_version_string'))
            self.setStringValueToDevice('brand', data_ua.get('device_brand'))
            self.setStringValueToDevice('device', data_ua.get('device_model'))

            detected_app = data_ua.get('detected_app')
            if not detected_app or detected_app == "Other" or data_ua.get('is_browser'):
                browser_family = data_ua.get('browser_family')
                browser_version = data_ua.get('browser_version_string')
                if browser_family != 'okhttp' and len(browser_family) > 0:
                    self.setBrowserData(browser_family, browser_version)
                    if user_agent not in self._browserUserAgents:
                        self._browserUserAgents.append(user_agent)

                    if detected_app and user_agent not in self._appsUserAgents:
                        self._appsUserAgents[user_agent] = detected_app
                    self.setDetectedApp(detected_app)

            else:
                if user_agent not in self._appsUserAgents:
                    self._appsUserAgents[user_agent] = detected_app
                self.setDetectedApp(detected_app)

            self.setDeviceData(data_ua.get('device_data',{}))
            self.storeUserAgent(user_agent)


    def setBooleanValueToDevice(self, key, data):
        if self.device['data'].get(key) == False and data == True:
            self.device['data'][key] = data


    def setStringValueToTarget(self, key, data):
        value = self.target['data'].get(key)

        if data is None or len(data) == 0 or data == 'Other':
            return

        if not value or len(value) == 0:
            if key == 'os_version':
                # FIXME: Ñapa para evitar problemas con el versionado. corregir alguna vez.
                if not self.isStringVersionOfOs(data): return
                if len(self.target['data'][key]) and self.target['data'][key] > data: return
            self.target['data'][key] = data

    def isStringVersionOfOs(self, data):
        data = data.split('.')
        data = int(data[0])
        return data <= 9

    def setStringValueToDevice(self, key, data):
        old_value = self.device['data'].get(key)

        if data is None or len(data) == 0 or data == 'Other':
            return

        if not old_value or len(old_value) == 0:
            self.device['data'][key] = data
            if key in self.target['data']:
                self.setStringValueToTarget(key, data)


    def setBrowserData(self, family, version):
        # TODO: okhttp?
        if family is None or len(family) == 0 or family == 'Other':
            return

        browsers = self.target['data'].get('browsers',{})

        i = 0
        for browser in browsers:
            if browser['family'] == family:
                if browser['version'] != version:
                    self.target['data']['browsers'][i]['version'] = version
                return
            i += 1

        self.target['data']['browsers'].append({
            'family': family,
            'version': version
        })


    def setDetectedApp(self, detected_app):
        if detected_app is None or len(detected_app) == 0 or detected_app == 'Other':
            return

        apps = self.target['data'].get('apps',{})

        i = 0
        for app in apps:
            if app["name"] == detected_app:
                # Si la detectó de otra forma, lo enriquece
                if "UserAgent" not in app['discovered']:
                    self.target['data']['apps'][i]['discovered'].append("UserAgent")
                return
            i+=1

        self.target['data']['apps'].append({
            'name': detected_app,
            'time': [],
            'discovered': ['UserAgent']
        })


    def setDeviceData(self, device_data):
        if not device_data or len(device_data) == 0:
            return

        self.device['data']['device_data'] = device_data


    def storeUserAgent(self, ua):
        if not ua or len(ua) == 0 or ua in self.target['data']['user_agents']:
            return

        self.target['data']['user_agents'].append(ua)


    def extractGeoIpInformation(self, parsed_json):
        ips_data = self.analyzer.analizeIpsFromJson(parsed_json)

        for ip_data in ips_data:
            if not self.isIpGeoDataInTarget(ip_data):
                self.addIpDataToTarget(ip_data)

    ###
    # IpData
    ###
    def isIpGeoDataInTarget(self, ip_data):
        # Generate a cache to optimize the comparasions
        if not self._cached_ip_data:
            self._cached_ip_data = self.generateCachedIpData()

        return self.getHashOfIpData(ip_data) in self._cached_ip_data


    def generateCachedIpData(self):
        return [self.getHashOfIpData(ip_data) for ip_data in self.target['data'].get('ip_addr')]


    def getHashOfIpData(self, ip_data):
        return "{}{}{}".format(ip_data.get('protocol',''), ip_data.get('ip',''), ip_data.get('count',-1))


    def addIpDataToTarget(self, ip_data):
        self.target['data'].get('ip_addr').append(ip_data)
        self._cached_ip_data.append(self.getHashOfIpData(ip_data))


    ###
    # WebpageInformation
    ###
    def extractWebpagesInformation(self, parsed_json):
        protocols = parsed_json.get("protocols", {})
        for protocol_data in protocols:
            proto_name = protocol_data.get("proto_name")
            sites = protocol_data.get('visits', {})
            self.processWebsites(proto_name, sites)


    def processWebsites(self, proto_name, sites):
        if proto_name not in ('http', 'https'): return
        for url, uris in sites.items():
            if proto_name == 'http':
                self.processHttpWebsite(url, uris)
            elif proto_name == 'https':
                self.processHttpsWebsite(url, uris)
            #    logger.info('URL: {}. Metadata: {}'.format(uri, metadata))
                #time = metadata[0]
                #ua = metadata[1]
                #if ua not in self._browserUserAgents: continue


    def processHttpWebsite(self, url, uris):
        app_data = None
        url_index = None

        # Trabaja en indices para ahorrar costes de recorrer datos
        for uri, connection_data in uris.items():
            uri_index = None

            typeHttpWebsite = self.getTypeHttpWebsite(url, uri, connection_data)
            if typeHttpWebsite == 'webpage':
                # Obtiene el indice de la url
                try:
                    url_index = self.getIndexOfUrlData(url)
                except IndexError:
                    url_index = self.createNewUrlData(url)

                # Obtiene el indice de la uri
                try:
                    uri_index = self.getIndexOfUriDataInUrlRegister(url_index, uri)
                except IndexError:
                    uri_index = self.createNewUriDataInUrlRegister(url_index, uri)

                for metadata in connection_data:
                    time = metadata[0]
                    self.setUriDataMetaInfo(url_index, uri_index, time)

            elif typeHttpWebsite in ['app', 'app_detected']:
                # Localiza el idx de la app
                ua = connection_data[0][1]
                app = self._appsUserAgents[ua]

                self.logAppDataByWebsite(app, connection_data, typeHttpWebsite)

            else:
                logger.debug('Encontrada cosa raruna: {}{} : {}'.format(url, uri, connection_data))
                return


    def getTypeHttpWebsite(self, url, uri, connection_data):

        ua = connection_data[0][1]
        if ua in self._browserUserAgents:
            return 'webpage'
        elif ua in self._appsUserAgents.keys():
            return 'app'
        else:
            app = self.analyzer.identifyAppByUrl(url, uri)
            if app:
                self._appsUserAgents[ua] = app
                return 'app_detected'


    def getIndexOfUrlData(self, url):
        index = 0
        for url_data in self.target['data'].get('webpages'):
            if url == url_data.get('url'):
                return index
            index += 1

        raise IndexError()


    def createNewUrlData(self, url):
        self.target['data']['webpages'].append({
            'url' : url,
            'uri' : []
        })
        return len(self.target['data']['webpages']) - 1


    def getIndexOfUriDataInUrlRegister(self, url_index, uri):
        index = 0
        for uri_data in self.target['data']['webpages'][url_index].get('uri'):
            if uri == uri_data.get('uri'):
                return index
            index += 1

        raise IndexError()


    def createNewUriDataInUrlRegister(self, url_index, uri):
        url = self.target['data']['webpages'][url_index]['url']
        types = self.analyzer.getTaxonomyOfWebpage(url, uri)
        self.target['data']['webpages'][url_index]['uri'].append({
            'uri' : uri,
            'fullurl' : url + uri,
            'type' : types[:2],
            'protocol' : "http",
            'time' : []
        })
        return len(self.target['data']['webpages'][url_index]['uri']) - 1


    def setUriDataMetaInfo(self, url_index, uri_index, time):
        elasticTime = self.parseDatetimeToEpoch(time)
        try:
            if elasticTime not in self.target['data']['webpages'][url_index]['uri'][uri_index]['time']:
                self.target['data']['webpages'][url_index]['uri'][uri_index]['time'].append(elasticTime)
        except IndexError:
            logger.error("{} : {}".format(uri_index, self.target['data']['webpages'][url_index]))
            raise


    def logAppDataByWebsite(self, app, connection_data, typeCreated = 'app'):
        try:
            app_index = self.getIndexOfApp(app)
        except IndexError:
            app_index = self.createNewAppDataByUrlMethod(app)

        if typeCreated == 'app_detected':
            if 'URL' not in self.target['data']['apps'][app_index]['discovered']:
                self.target['data']['apps'][app_index]['discovered'].append('URL')
        elif typeCreated == 'app_detected_https':
            if 'URL_HTTPS' not in self.target['data']['apps'][app_index]['discovered']:
                self.target['data']['apps'][app_index]['discovered'].append('URL_HTTPS')

        # Una vez hecho esto, añadimos las visitas
        for metadata in connection_data:
            if type(metadata) == list:
                time = metadata[0]
            else:
                time = metadata
            self.setAppMetaInfo(app_index, time)


    def getIndexOfApp(self, app):
        index = 0
        for app_data in self.target['data'].get('apps'):
            if app == app_data.get('name'):
                return index
            index += 1

        raise IndexError()


    def createNewAppDataByUrlMethod(self, app):
        appToAppend = {
            'name':app,
            'time':[],
            'discovered':[]
        }

        self.target['data']['apps'].append(appToAppend)
        return len(self.target['data']['apps']) - 1


    def setAppMetaInfo(self, app_index, time):
        elasticTime = self.parseDatetimeToEpoch(time)
        if elasticTime not in self.target['data']['apps'][app_index]['time']:
            self.target['data']['apps'][app_index]['time'].append(elasticTime)


    def processHttpsWebsite(self, url, connection_data):
        app = self.analyzer.identifyAppByUrl(url, '')
        if app:
            self.logAppDataByWebsite(app, connection_data, 'app_detected_https')



    ###
    # Extract Technical Info
    ###
    def extractTechnicalInfoFromJson(self, parsed_json):

        self.pcap['data']['init_time'] = self.target['data']['@timestamp']
        self.pcap['data']['end_time'] = self.target['data']['last_timestamp']
        self.pcap['data']['mac'] = self.target['data']['mac']
        self.pcap['data']['mac_ap'] = self.target['data']['mac_ap']
        #
        self.pcap['data']['size'] = parsed_json.get('total_size',0)
        self.pcap['data']['packet_amount'] = parsed_json.get('packet_amount',0)
        self.pcap['data']['tcp_size'] = parsed_json.get('transport_sizes',{}).get('tcp', 0)
        self.pcap['data']['udp_size'] = parsed_json.get('transport_sizes',{}).get('udp', 0)

        for protocol, size in parsed_json.get('network_sizes',{}).items():
            self.pcap['data']['network_sizes'].append({'protocol':protocol, 'size':size})

        for port, size in parsed_json.get('tcp_protocol_sizes',{}).items():
            self.pcap['data']['transport_sizes'].append({'protocol':"tcp", "port":port, 'size':size})

        for port, size in parsed_json.get('udp_protocol_sizes',{}).items():
            self.pcap['data']['transport_sizes'].append({'protocol':"udp", "port":port, 'size':size})

        for protocol in parsed_json.get('protocols', {}):
            protocol_ips = []
            for ip, size in protocol.get('proto_ips',{}).items():
                protocol_ips.append(ip)
            self.pcap['data']['protocol'].append({'name':protocol.get('proto_name'), 'ips':protocol_ips})

    ###
    # Upload Data to Splunk
    ###
    def uploadData(self):
        device_id = self.uploadDeviceData()
        target_id = self.uploadTargetData(device_id)
        pcap_id = self.uploadPcapData(target_id)


    def uploadDeviceData(self):
        id = self.device.get('ID')
        if not id:
            create = True
            id = self.device['data'].get('device')
        if id:
            existentDeviceData = self.getFromElasticsearch(id, doc_type='devices', ignore=[400, 404])
            if existentDeviceData is None:
                create = True
            else:
                create = False

        if create:
            id = self.device['data'].get('device', self.getRandomKey())
            idElastic = self.createDocument(id, self.device['data'], 'devices')
        else:
            idElastic = self.updateDocument(id, self.device['data'], 'devices')

        return idElastic


    def getRandomKey(self):
        import uuid
        return uuid.uuid4().hex


    def uploadTargetData(self, device_id):
        self.target['_parent'] = device_id

        if not self.target['ID']:
            idElastic = self.createDocument(self.target['data'].get('mac'), self.target['data'], 'target', parent_id=self.target['_parent'])
        else:
            idElastic = self.updateDocument(self.target['ID'], self.target['data'], 'target', parent_id=self.target['_parent'])

        return idElastic


    def uploadPcapData(self, target_id):
        self.pcap['_parent'] = target_id

        query = {"query":{ "ids":{ "values": [ self.getPcapId() ] } } }
        results = self.makeQuery(query, doc_type="pcap")
        if results.get('total',0) > 0:
            idElastic = self.updateDocument(self.getPcapId(), self.pcap['data'], 'pcap', parent_id=self.pcap['_parent'])
        else:
            idElastic = self.createDocument(self.getPcapId(), self.pcap['data'], 'pcap', parent_id=self.pcap['_parent'])

        return idElastic


    def getJsonToStore(self):
        """
        Devuelve las llamadas que haría a ELK en forma de json.
        """
        data = {
            'device' : self.device,
            'target' : self.target,
            'pcap' : self.pcap
        }
        return json.dumps(data)
