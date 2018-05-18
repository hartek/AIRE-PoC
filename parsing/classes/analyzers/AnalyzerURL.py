import json
import requests
import base64
import hmac
import datetime
import hashlib
import os
from bs4 import BeautifulSoup
from urllib.parse import urlencode, quote
import xml.etree.ElementTree as ET

myfile_path = os.path.abspath(os.path.dirname(__file__))

class AnalyzerURL(object):
	def __init__(self, access_key, secret_key):
		self.app_url_dict = self.load_json()
		self.detected_apps = {}
		# Initialize Aylien SDK
		self.AWSAccessKeyId = access_key
		self.AWSSecretKey=secret_key

	def load_json(self):
		json_data = open(myfile_path + "/data_files/domain.json").read()
		data = json.loads(json_data)
		return data['app_domain']

	def detect_app_url(self, target_url):
		for app,app_url_lst in self.app_url_dict.items():
			for app_url_str in app_url_lst:
				if app_url_str in target_url:
					if app in self.detected_apps:
						self.detected_apps[app] += 1
					else:
						self.detected_apps[app] = 1
					return app

	# Source: https://docs.aws.amazon.com/es_es/general/latest/gr/sigv4-signed-request-examples.html
	def get_thematics_awis(self, target_url):
		method = 'GET'
		service = 'awis'
		host = 'awis.us-west-1.amazonaws.com'
		region = 'us-west-1'
		endpoint = 'https://awis.amazonaws.com/api'
		request_params = {
			'Action': "UrlInfo",
			'Url': target_url,
			'ResponseGroup': "Categories"
		}
		request_parameters = urlencode([(key, request_params[key]) for key in sorted(request_params.keys())])
		#print(request_parameters)
		def sign(key, msg):
			return hmac.new(key, msg.encode('utf-8'), hashlib.sha256).digest()

		def getSignatureKey(key, dateStamp, regionName, serviceName):
			kDate = sign(('AWS4' + key).encode('utf-8'), dateStamp)
			kRegion = sign(kDate, regionName)
			kService = sign(kRegion, serviceName)
			kSigning = sign(kService, 'aws4_request')
			return kSigning

		access_key = self.AWSAccessKeyId
		secret_key = self.AWSSecretKey
		if access_key is None or secret_key is None:
			print('No access key is available.')
			sys.exit()

		t = datetime.datetime.utcnow()
		amzdate = t.strftime('%Y%m%dT%H%M%SZ')
		datestamp = t.strftime('%Y%m%d') 

		canonical_uri = '/api' 
		canonical_querystring = request_parameters
		canonical_headers = 'host:' + host + '\n' + 'x-amz-date:' + amzdate + '\n'
		signed_headers = 'host;x-amz-date'
		payload_hash = hashlib.sha256("".encode('utf-8')).hexdigest()
		canonical_request = method + '\n' + canonical_uri + '\n' + canonical_querystring + '\n' + canonical_headers + '\n' + signed_headers + '\n' + payload_hash

		algorithm = 'AWS4-HMAC-SHA256'
		credential_scope = datestamp + '/' + region + '/' + service + '/' + 'aws4_request'
		string_to_sign = algorithm + '\n' +  amzdate + '\n' +  credential_scope + '\n' +  hashlib.sha256(canonical_request.encode("utf-8")).hexdigest()

		signing_key = getSignatureKey(secret_key, datestamp, region, service)
		signature = hmac.new(signing_key, (string_to_sign).encode('utf-8'), hashlib.sha256).hexdigest()
		authorization_header = algorithm + ' ' + 'Credential=' + access_key + '/' + credential_scope + ', ' +  'SignedHeaders=' + signed_headers + ', ' + 'Signature=' + signature

		headers = {'X-Amz-Date':amzdate, 'Authorization':authorization_header, 'Content-Type': 'application/xml', 'Accept': 'application/xml'}

		request_url = endpoint + '?' + canonical_querystring
		r = requests.get(request_url, headers=headers)

		#print("---RESPONSE---")
		response= r.text#.encode('ISO-8859-1').decode("utf-8")
		#print(response)

		root = ET.fromstring(response)
		categories = []
		for element in root.iter("{http://awis.amazonaws.com/doc/2005-07-11}Title"):
			categories.append(element.text)
		#print(categories)
		return categories
