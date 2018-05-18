import dpkt

class Stream(object):
	def __init__ (self, srv_ip, srv_port, clt_ip, clt_port):
		self.srv_ip = srv_ip
		self.srv_port = srv_port
		self.clt_ip = clt_ip
		self.clt_port = clt_port

		self.pkt_list = []

	def add_pkt(self, ts, pkt):
		self.pkt_list.append((ts,pkt))

	def get_pkt(self,index):
		return self.pkt_list[index]

	def tcp_reorder(self, stream):
		print("############### STREAM START ###############")

		print("--- OLD STREAM: ")
		m = 0
		for pkt in stream.pkt_list:
			print(pkt.data.data.seq, m)
			m += 1

		new_stream = Stream(stream.srv_ip, stream.srv_port, stream.clt_ip, stream.clt_port)
		n = 0
		seq = 0; ack = 0
		# First, look for a packet with SYN flag and get SEQ and ACK
		for pkt in stream.pkt_list:
			tcp = pkt.data.data
			if (tcp.flags & dpkt.tcp.TH_SYN) != 0:
				syn = tcp.seq; ack = tcp.ack
				new_stream.add_pkt(stream.get_pkt(n))
				n += 1;	break
			n += 1
		# We should be able to order the rest given the initial SEQ and ACK
		n = 0
		for pkt in stream.pkt_list:
			tcp = pkt.data.data
			# Check if the stream has ended
			if (tcp.flags & dpkt.tcp.TH_FIN) != 0 or (tcp.flags & dpkt.tcp.TH_RST) != 0:
				print("FIN!")
				break
			if tcp.seq == ack:
				syn = tcp.seq; ack = tcp.ack
				new_stream.add_pkt(stream.get_pkt(n))
				n += 1;	continue;
			n += 1


		print("--- NEW STREAM: ")
		m=0
		for pkt in new_stream.pkt_list:
			print(pkt.data.data.seq, m)
			m += 1

		print("############### STREAM END ###############")
		print()