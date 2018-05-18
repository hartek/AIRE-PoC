import GeoIP
import json
import os
myfile_path = os.path.abspath(os.path.dirname(__file__))
class AnalyzerGeoIP(object):
	def __init__(self):
		self.app_geoip_dict = self.load_json()
		self.detected_apps = {}

	def load_json(self):
		json_data = open(myfile_path + "/data_files/geoip.json").read()
		data = json.loads(json_data)
		if len(data) == 0:
			raise IOError("File data_files/geoip.json not found")
		return data['app_geoip']

	def parse_geoip(self, target_ip):
		dict_output =  {}
		gi_as = GeoIP.open(myfile_path+"/../../geoip/GeoIPASNum.dat", GeoIP.GEOIP_STANDARD)
		gi_city = GeoIP.open(myfile_path+"/../../geoip/GeoLiteCity.dat", GeoIP.GEOIP_STANDARD)

		as_no = gi_as.org_by_addr(target_ip)

		city_record = gi_city.record_by_addr(target_ip)
		if city_record is None:
			return json.dumps({"original_ip" : target_ip})
		city = city_record.get('city')
		country = city_record.get('country_name')
		coordinades = (city_record['latitude'], city_record['longitude'])

		dict_output['detected_app'] = ""
		dict_output['as_number'] = ""

		if as_no != None:
			detected_app = self.detect_app_geoip(as_no)
			dict_output['detected_app'] = detected_app
			dict_output['as_number'] = as_no

		dict_output['city'] = city
		dict_output['country'] = country
		dict_output['coordinades'] = coordinades
		dict_output['original_ip'] = target_ip

		return json.dumps(dict_output)

	def detect_app_geoip(self, as_no):
		for app,app_geoip_lst in self.app_geoip_dict.items():
			for app_geoip_str in app_geoip_lst:
				try:
					if app_geoip_str in as_no:
						if app in self.detected_apps:
							self.detected_apps[app] += 1
					else:
						self.detected_apps[app] = 1
					return app
				except:
					raise Exception(as_no)

