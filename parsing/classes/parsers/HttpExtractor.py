import dpkt, json, datetime
from .ProtocolExtractor import ProtocolExtractor

class HttpExtractor(ProtocolExtractor):
	def __init__(self, tcp_streams):
		ports = (80, 8080, 8000)
		super(HttpExtractor, self).__init__(tcp_streams, ports, "http")

		# HTTP specific
		self.requests = []
		self.responses = []
		self.user_agents = {}
		self.visits = {}

		self.parse_http_streams()


	def dict_out(self):
		output =  {}
		output['proto_name'] = "http"
		output['proto_ips'] = self.proto_ips
		output['user_agents'] = self.user_agents
		output['visits'] = self.visits
		return output


	def parse_http_streams(self):
		for stream in self.proto_streams:
			http_data = b''
			for ts,pkt in stream.pkt_list:
				eth = dpkt.ethernet.Ethernet(pkt)
				http_data = eth.data.data.data
				try:
					request = dpkt.http.Request(http_data)
				except:
					continue

				self.requests.append(request)

				if 'user-agent' in request.headers:
					user_agent = request.headers['user-agent']
					if user_agent and user_agent in self.user_agents:
    						self.user_agents[user_agent] += 1
					else:
						self.user_agents[user_agent] = 1
				else:
					pass

				if 'host' in request.headers:
					host = request.headers['host']
					if not host in self.visits:
    						self.visits[host] = {}
				else:
					pass

				if request.uri:
					uri = request.uri
					if not uri in self.visits[host]:
						self.visits[host][uri] = []
				else:
					pass

				timestamp = str(datetime.datetime.utcfromtimestamp(ts))
				self.visits[host][uri].append((timestamp,user_agent))
