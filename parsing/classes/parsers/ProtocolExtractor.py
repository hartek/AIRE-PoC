import dpkt, json

class ProtocolExtractor(object):

	def __init__(self, tcp_streams, port_tuple, proto_name):
		self.proto_streams = []
		self.proto_ips = {}
		self.port_tuple = port_tuple
		self.proto_name = proto_name

		self.extract_proto(tcp_streams)
		self.parse_proto_streams()


	def dict_out(self):
		output =  {}
		output['proto_name'] = self.proto_name
		output['proto_ips'] = self.proto_ips
		return output

	def extract_proto(self, tcp_streams):
		for id_key,stream in tcp_streams.items():
			if stream.srv_port in self.port_tuple:
				self.proto_streams.append(stream)

	def parse_proto_streams(self):
		for stream in self.proto_streams:
			srv_ip = stream.srv_ip
			size = 0
			for ts,pkt in stream.pkt_list:
				eth = dpkt.ethernet.Ethernet(pkt)
				size += len(pkt)
			if srv_ip in self.proto_ips:
				self.proto_ips[srv_ip] += size
			else:
				self.proto_ips[srv_ip] = size


