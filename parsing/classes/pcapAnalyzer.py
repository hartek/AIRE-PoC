#!/usr/bin/env python3

import os
import sys
import json
import logging

from .analyzers import *
from classes.fonAPI import FonApi
sys.path.append(os.path.abspath(
    os.path.dirname(__file__)) + '/..')
import conf.tokens as TOKENS

FORMAT = '%(asctime)s %(levelname)s %(message)s'
logging.basicConfig(format=FORMAT)
logger = logging.getLogger('analizePcapData')
logger.setLevel(logging.INFO)

class PcapAnalyzer(object):

    def __init__(self, Tokens):
        self.analyzer_dns = AnalyzerDNS()
        self.analyzer_url = AnalyzerURL(Tokens.AWS_ACCESS_KEY, Tokens.AWS_SECRET_KEY)
        self.analyzer_ua = AnalyzerUserAgent()
        self.analyzer_geoip = AnalyzerGeoIP()

        self.fonApi = FonApi(Tokens.FONO_API_TOKEN)


    def getTargetMac(self, json_data):
        mac_ap = json_data.get('mac_ap')

        target_mac = ''
        max_count = -1
        for mac_register, count in json_data.get('macs').items():
            if count > max_count:
                if mac_register != mac_ap:
                    target_mac = mac_register
                    max_count = count

        assert target_mac != mac_ap
        return target_mac


    def getUserAgentsFromJson(self, json_data):
        protocols = json_data.get('protocols')
        for protocol in protocols:
            if protocol.get('proto_name') == 'http':
                return protocol.get('user_agents')
        return {}


    def analyzeUserAgent(self, user_agent, device_model = '', search_device_data = False):
        ua_data = self.analyzer_ua.parse_useragent(user_agent)
        ua_data = json.loads(ua_data)

        if device_model == '' and ua_data.get("device_model"):

            device_model = ua_data.get("device_brand")
            model = ua_data.get("device_model")
            if model == "G7-L01": model = "G7"
            device_model += " " + model

        if len(device_model) > 0 and search_device_data:
            device_data = self.getDeviceData(device_model)
            if len(device_data):
                ua_data['device_data'] = device_data

        return ua_data


    def analizeIpsFromJson(self, json_data):
        ips = []
        for protocol in json_data['protocols']:
            proto_name = protocol['proto_name']
            # Sólo mirar HTTP, HTTPS, XMP, STUN
            if proto_name.upper() in ['HTTP', 'HTTPS', 'XMPP', 'STUN']:
                ips += self.getGeoIpOfList(protocol['proto_ips'], proto_name)
        return ips


    def getGeoIpOfList(self, ip_list, protocol_name):
        results = []
        cached_data = []
        for ip, count in ip_list.items():
            if ip in cached_data: continue
            geoip = self.getGeoIp(ip)
            info_ip = {
                "protocol":protocol_name,
                "ip":ip,
                "count":count
            }
            label_tags_dic = {'as_number' : 'description', 'coordinades':'geoip'}
            for label in ['as_number', 'country', 'city', 'coordinades']:
                if geoip.get(label):
                    if label == 'coordinades':
                        # Le damos la vuelta para que sea LAT,LONG
                        geoip[label] = [float('%.8f'%(coord)) for coord in geoip.get(label)[::-1]]
                    info_ip[label_tags_dic.get(label, label)] = geoip.get(label)

            results.append(info_ip)
            cached_data.append(ip)

        return results


    def getGeoIp(self, ip):
        return json.loads(self.analyzer_geoip.parse_geoip(ip))


    def extractDetectedApps(self, json_data):
        user_agents = self.getUserAgentsFromJson(json_data)
        apps_detected = []
        # Identifica apps por UA
        for ua in user_agents:
            app = self.analyzer_ua.detect_app_ua(ua)
            if app not in apps_detected:
                apps_detected.push(app)

        # Identifica apps por ip
        for protocol in json_data['protocols']:
            proto_name = protocol['proto_name']
            apps_list = self.getAppsOfIpList(proto_name, protocol['proto_ips'])
            for app in apps_list:
                if app not in apps_detected:
                    apps_detected.push(app)

        return apps_detected


    def getAppsOfIpList(self, protocol_name, ip_list):
        apps_detected = []
        for ip in ip_list:
            # TODO: Parsear sólo apps?
            app = self.analyzer_geoip.parse_geoip(ip)
            if app and app not in apps_detected:
                apps_detected.push(app)

        return apps_detected


    def getDeviceData(self, model):
        phone = self.fonApi.getdevice(model)
        logger.debug("Device Data for device {}: {}".format(model, phone))
        type_res = type(phone)
        if type_res == str:
            return {}
        elif type_res == list:
            return phone[0]
        return phone


    def getTaxonomyOfWebpage(self, url, uri):
        fullurl = url + uri
        return self.analyzer_url.get_thematics_awis(fullurl)


    def identifyAppByUrl(self, url, uri):
        fullurl = url + uri
        return self.analyzer_url.detect_app_url(fullurl)
