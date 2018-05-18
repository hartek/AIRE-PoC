import subprocess
import dpkt
import json
import datetime

from socket import inet_ntop, AF_INET
from netaddr import IPNetwork, IPAddress
from classes.parsers import *

class PcapParser:
	MAC_AP = "74:da:38:8d:bb:24"
	CLIENT_IP_RANGES = [
		"0.0.0.0/8",
		"10.0.0.0/8",
		"127.0.0.0/8",
		"128.0.0.0/8",
		"169.254.0.0/12",
		"172.16.0.0/12",
		"191.255.0.0/16",
		"192.0.0.0/24",
		"192.168.0.0/16",
		"223.255.255.0/24"
	]

	def __init__(self, pcap):
		self.target_pcap = pcap

		self.total_size = 0
		self.network_sizes = {'ip': 0, 'other' : 0}
		self.transport_sizes = {'tcp': 0, 'udp': 0, 'other': 0}

		self.first_timestamp = ''
		self.last_timestamp = ''
		self.packet_amount = 0

		self.macs = {}

		self.tcp_protocol_sizes = {}
		self.udp_protocol_sizes = {}

		self.tcp_streams = {}
		self.udp_streams = {}

		self.clientIps = {}
		self.serverIps = {}

		self.http_analyzer = None
		self.xmpp_analyzer = None

	def mac_addr(self,address):
		return ':'.join('%02x' % dpkt.compat.compat_ord(b) for b in address)

	def inet_to_str(self, inet):
		return inet_ntop(AF_INET, inet)

	def pkt_to_stream(self, stream_dict, pkt, ts):
		eth = dpkt.ethernet.Ethernet(pkt)
		ip = eth.data
		tcp = ip.data
		(src_ip, dst_ip) = (self.inet_to_str(ip.src), self.inet_to_str(ip.dst))
		(src_port, dst_port) = (tcp.sport, tcp.dport)
		id_key_1 = (src_ip, src_port, dst_ip, dst_port)
		id_key_2 = (dst_ip, dst_port, src_ip, src_port)

		srv_ip = self.get_server_ip(src_ip, src_port, dst_ip, dst_port, len(pkt), self.clientIps, self.serverIps)

		if id_key_1 in stream_dict:
			stream_dict[id_key_1].add_pkt(ts, pkt)
			return stream_dict[id_key_1]
		elif id_key_2 in stream_dict:
			stream_dict[id_key_2].add_pkt(ts, pkt)
			return stream_dict[id_key_2]
		else:
			if srv_ip is src_ip:
				new_strm = Stream(src_ip, src_port, dst_ip, dst_port)
				new_strm.add_pkt(ts, pkt)
			else:
				new_strm = Stream(dst_ip, dst_port, src_ip, src_port)
				new_strm.add_pkt(ts, pkt)
			stream_dict[id_key_1] = new_strm
			return new_strm
			#print("Added key: %s:%s\t\t\t%s:%s" % id_key_1)


	def is_private(self, ip):
		for subnet in self.CLIENT_IP_RANGES:
			if IPAddress(ip) in IPNetwork(subnet):
				#print("%s is private" % ip)
				return True
			else:
				pass
		#print("%s is public" % ip)
		return False


	def get_server_ip(self, src_ip, src_port, dst_ip, dst_port, pkt_size, clientIps, serverIps):
		if src_ip in clientIps:
			if dst_ip not in serverIps:
				serverIps[dst_ip] = pkt_size
			else:
				serverIps[dst_ip] += pkt_size
			clientIps[src_ip] += pkt_size
			return dst_ip
		elif dst_ip in clientIps:
			if src_ip not in serverIps:
				serverIps[src_ip] = pkt_size
			else:
				serverIps[src_ip] += pkt_size
			clientIps[dst_ip] += pkt_size
			return src_ip

		elif src_ip in serverIps:
			if dst_ip not in clientIps:
				clientIps[dst_ip] = pkt_size
			else:
				clientIps[dst_ip] += pkt_size
			serverIps[src_ip] += pkt_size
			return src_ip
		elif dst_ip in serverIps:
			if src_ip not in clientIps:
				clientIps[src_ip] = pkt_size
			else:
				clientIps[src_ip] += pkt_size
			serverIps[dst_ip] += pkt_size
			return dst_ip

		elif self.is_private(dst_ip) and not self.is_private(src_ip):
			clientIps[dst_ip] = pkt_size
			serverIps[src_ip] = pkt_size
			return src_ip
		elif self.is_private(src_ip) and not self.is_private(dst_ip):
			clientIps[src_ip] = pkt_size
			serverIps[dst_ip] = pkt_size
			return dst_ip

		elif src_port < dst_port:
			clientIps[dst_ip] = pkt_size
			serverIps[src_ip] = pkt_size
			return src_ip
		elif dst_port < src_port:
			clientIps[src_ip] = pkt_size
			serverIps[dst_ip] = pkt_size
			return dst_ip

		else:
			clientIps[src_ip] = pkt_size
			serverIps[dst_ip] = pkt_size
			return dst_ip


	def send_to_json(self):
		statistics = {}
		statistics['mac_ap'] = self.MAC_AP
		statistics['total_size'] = self.total_size
		statistics['packet_amount'] = self.packet_amount
		statistics['first_timestamp'] = self.first_timestamp
		statistics['last_timestamp'] = self.last_timestamp
		statistics['macs'] = self.macs
		statistics['network_sizes'] = self.network_sizes
		statistics['transport_sizes'] = self.transport_sizes
		statistics['tcp_protocol_sizes'] = self.tcp_protocol_sizes
		statistics['udp_protocol_sizes'] = self.udp_protocol_sizes
		statistics['protocols'] = []
		statistics['protocols'].append(self.http_extractor.dict_out())
		statistics['protocols'].append(self.xmpp_extractor.dict_out())
		statistics['protocols'].append(self.dns_extractor.dict_out())
		statistics['protocols'].append(self.stun_extractor.dict_out())
		statistics['protocols'].append(self.https_extractor.dict_out())
		return json.dumps(statistics)

	def count_packets(self):
		f = open(self.target_pcap,"rb")
		pcap = dpkt.pcap.Reader(f)
		count = 0
		for ts,buf in pcap:
			count += 1
		return count

	def extract(self):
		self.packet_amount = self.count_packets()

		f = open(self.target_pcap,"rb")
		pcap = dpkt.pcap.Reader(f)

		count = 0
		for ts,buf in pcap:
			if count == 0:
				self.first_timestamp = str(datetime.datetime.utcfromtimestamp(ts))

			self.total_size += len(buf)
			eth = dpkt.ethernet.Ethernet(buf)
			src_mac = self.mac_addr(eth.src); dst_mac = self.mac_addr(eth.dst)
			if src_mac in self.macs:
				self.macs[src_mac] += len(buf)
			else:
				self.macs[src_mac] = len(buf)
			if dst_mac in self.macs:
				self.macs[dst_mac] += len(buf)
			else:
				self.macs[dst_mac] = len(buf)

			if type(eth.data) == dpkt.ip.IP:
				ip = eth.data
				self.network_sizes['ip'] += len(buf)
				if type(ip.data) == dpkt.tcp.TCP:
					tcp = ip.data
					self.transport_sizes['tcp'] += len(buf)

					stream = self.pkt_to_stream(self.tcp_streams, buf, ts)
					if stream.srv_port in self.tcp_protocol_sizes:
						self.tcp_protocol_sizes[stream.srv_port] += len(buf)
					else:
						self.tcp_protocol_sizes[stream.srv_port] = len(buf)

				elif type(ip.data) == dpkt.udp.UDP:
					udp = ip.data
					self.transport_sizes['udp'] += len(buf)

					stream = self.pkt_to_stream(self.udp_streams, buf, ts)
					if stream.srv_port in self.udp_protocol_sizes:
						self.udp_protocol_sizes[stream.srv_port] += len(buf)
					else:
						self.udp_protocol_sizes[stream.srv_port] = len(buf)

				else:
					other = ip.data
					self.transport_sizes['other'] += len(buf)
			else:
				not_ip = eth.data
				self.network_sizes['other'] += len(buf)

			count += 1

			if count == self.packet_amount:
				self.last_timestamp = str(datetime.datetime.utcfromtimestamp(ts))


		# Protocol analyzers
		self.http_extractor = HttpExtractor(self.tcp_streams)
		self.dns_extractor = DnsExtractor(self.udp_streams)
		self.xmpp_extractor = ProtocolExtractor(self.tcp_streams, (5222,5223,), "xmpp")
		self.stun_extractor = ProtocolExtractor(self.udp_streams, (3478,), "stun")
		self.https_extractor = HttpsExtractor(self.tcp_streams, self.dns_extractor.get_resolved())

		"""
		print("Total size: %s Bytes" % self.total_size)
		print("Total IP/Other protocol: %s Bytes / %s Bytes" % (
			self.network_sizes['ip'],
			self.network_sizes['other']
			))
		print("Total TCP/UDP/Other protocol: %s Bytes / %s Bytes / %s Bytes" % (
			self.transport_sizes['tcp'],
			self.transport_sizes['udp'],
			self.transport_sizes['other']
			))
		print("Total by IP: ")
		for key,value in self.serverIps.items():
			print("\t%s: %s Bytes" % (key,value))
		print("Total by TCP port: ")
		for key,value in self.tcp_protocol_sizes.items():
			print("\t%s: %s Bytes" % (key, value))
		print("Total by UDP port: ")
		for key,value in self.udp_protocol_sizes.items():
			print("\t%s: %s Bytes" % (key, value))
		print("TCP Streams: %s streams" % len(self.tcp_streams))
		print("UDP Streams: %s streams" % len(self.udp_streams))
		print("Total server side IPs: %s IPs" % len(self.serverIps))
		print("Total client side IPs: %s IPs" % len(self.clientIps))
		print(); print()
		"""


		return self.send_to_json()
