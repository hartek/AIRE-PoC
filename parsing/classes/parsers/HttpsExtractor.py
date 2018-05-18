import dpkt, json, datetime
from . import ProtocolExtractor

class HttpsExtractor(ProtocolExtractor):
	def __init__(self, tcp_streams, resolved_domains):
		super().__init__(tcp_streams, (443,), "https")

		# HTTPS specific
		self.resolved_domains = resolved_domains
		self.visits = {}

		self.parse_https_streams()


	def dict_out(self):
		output =  {}
		output['proto_name'] = "https"
		output['proto_ips'] = self.proto_ips
		output['visits'] = self.visits
		return output

	def resolve_ip(self, stream):
		srv_ip = stream.srv_ip
		for host,ips in self.resolved_domains['A'].items():
			if srv_ip in ips:
				return host
		return srv_ip


	def parse_https_streams(self):
		for stream in self.proto_streams:
			host = self.resolve_ip(stream)
			timestamp = str(datetime.datetime.utcfromtimestamp(stream.pkt_list[0][0]))
			if host in self.visits:
				self.visits[host].append(timestamp)
			else:
				self.visits[host] = [timestamp,]