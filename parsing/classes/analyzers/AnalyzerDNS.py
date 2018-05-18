import json
import os
myfile_path = os.path.abspath(os.path.dirname(__file__))
class AnalyzerDNS(object):
	def __init__(self):
		self.app_dns_dict = self.load_json()
		self.detected_apps = {}

	def load_json(self):
		json_data = open(myfile_path + "/data_files/domain.json").read()
		data = json.loads(json_data)
		return data['app_domain']

	def detect_app_dns(self, target_domain):

		for app,app_dns_lst in self.app_dns_dict.items():
			for app_dns_str in app_dns_lst:
				if app_dns_str in target_domain:
					if app in self.detected_apps:
						self.detected_apps[app] += 1
					else:
						self.detected_apps[app] = 1
					return app

