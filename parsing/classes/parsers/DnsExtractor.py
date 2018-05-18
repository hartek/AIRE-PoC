import dpkt, json, socket
from . import ProtocolExtractor

class DnsExtractor(ProtocolExtractor):

	def __init__(self, udp_streams):
		super().__init__(udp_streams, (53,), "dns")

		# DNS specific
		self.resolved_domains = {
			"CNAME": {},
			"A": {},
		}

		self.parse_dns_streams()

	def get_resolved(self):
		return self.resolved_domains

	def dict_out(self):
		output =  {}
		output['proto_name'] = "dns"
		output['proto_ips'] = self.proto_ips
		output['resolved_domains'] = self.resolved_domains
		return output

	def parse_dns_streams(self):
		for stream in self.proto_streams:
			dns_data = b''
			for ts,pkt in stream.pkt_list:
				eth = dpkt.ethernet.Ethernet(pkt)
				dns_data = eth.data.data.data

				try:
					dns = dpkt.dns.DNS(dns_data)
					# Get correct resolved names to DNS queries
					if dns.qr != dpkt.dns.DNS_R: continue
					if dns.opcode != dpkt.dns.DNS_QUERY: continue
					if dns.rcode != dpkt.dns.DNS_RCODE_NOERR: continue
					if len(dns.an) < 1: continue

					for answer in dns.an:
						if answer.type == dpkt.dns.DNS_CNAME:
							if answer.name in self.resolved_domains['CNAME']:
								if answer.cname not in self.resolved_domains['CNAME'][answer.name]:
									self.resolved_domains['CNAME'][answer.name].append(answer.cname)
							else:
								self.resolved_domains['CNAME'][answer.name] = [answer.cname]

						elif answer.type == dpkt.dns.DNS_A:
							if answer.name in self.resolved_domains['A']:
								if answer.rdata not in self.resolved_domains['A'][answer.name]:
									self.resolved_domains['A'][answer.name].append(socket.inet_ntoa(answer.rdata))
							else:
								self.resolved_domains['A'][answer.name] = [socket.inet_ntoa(answer.rdata)]

				except Exception as ex:
					print(ex)
