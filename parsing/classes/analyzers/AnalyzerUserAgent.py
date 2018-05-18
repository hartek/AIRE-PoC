import json, user_agents, os
myfile_path = os.path.abspath(os.path.dirname(__file__))

class AnalyzerUserAgent(object):
	def __init__(self):
		self.app_ua_dict = self.load_json()
		self.detected_apps = {}

	def load_json(self):
		json_data = open(myfile_path + "/data_files/user_agent.json").read()
		data = json.loads(json_data)
		return data['app_ua']

	def parse_useragent(self, ua_string):

		user_agent = user_agents.parse(ua_string)
		detected_app = self.detect_app_ua(ua_string)
		dict_browsers = ['Firefox', 'Safari', 'Chrome', 'Opera', 'AndroidBrowser', 'TorBrowser', 'Netscape']
		dict_output = {}

		dict_output['browser_family'] = user_agent.browser.family
		dict_output['browser_version_string'] = user_agent.browser.version_string
		dict_output['os_family'] = user_agent.os.family
		dict_output['os_version_string'] = user_agent.browser.version_string
		dict_output['device_family'] = user_agent.device.family
		dict_output['device_brand'] = user_agent.device.brand
		dict_output['device_model'] = user_agent.device.model
		dict_output['is_pc'] = user_agent.is_pc
		dict_output['is_mobile'] = user_agent.is_mobile
		dict_output['is_tablet'] = user_agent.is_tablet
		dict_output['detected_app'] = detected_app
		dict_output['original_string'] = ua_string
		dict_output['is_okhttp'] = 'okhttp' in ua_string

		extend_browser_data = self.detect_browser_ua(ua_string)
		if not extend_browser_data.get('browser'):
			dict_output['browser_family'] = ''
		else:
			dict_output['browser_family'] = extend_browser_data.get('browser').get('name')

		extend_browser_data = self.detect_browser_ua(ua_string)
		if not extend_browser_data.get('browser'):
			dict_output['browser_family'] = ''
		else:
			dict_output['browser_family'] = extend_browser_data.get('browser').get('name')


		if dict_output['detected_app'] in dict_browsers:
			dict_output['is_browser'] = True
		else:
			dict_output['is_browser'] = False

		return json.dumps(dict_output)


	def detect_app_ua(self, ua):

		for app,app_ua_lst in self.app_ua_dict.items():
			for app_ua_str in app_ua_lst:
				if app_ua_str in ua:
					if app in self.detected_apps:
						self.detected_apps[app] += 1
					else:
						self.detected_apps[app] = 1
					return app


	def detect_browser_ua(self, ua):
		import httpagentparser
		data = httpagentparser.detect(ua)
		return data
