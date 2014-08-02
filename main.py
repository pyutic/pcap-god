import dpkt
import os

def ip_decode(p):
	return ".".join(["%d" % ord(x) for x in str(p)])

ts_arr = []
buf_arr = []

COND_IP = "125.131.189.44"
COND_PORT = 80
name = "bob_pingpong.pcap"
#name = raw_input("Name => ")
f = open(name,'rb')
pcap = dpkt.pcap.Reader(f)

os.system("rm -rf " + COND_IP)
os.mkdir(COND_IP)

for a, b in pcap:
	ts_arr.append(a)
	buf_arr.append(b)

#print len(ts_arr), len(buf_arr)

tcpstack = {} # {srcip port : dstip port}
flow_s2d = {}
flow_d2s = {}
stream_num = {}
stream_packetnum = {}
sn = 0
for i in xrange(len(ts_arr)):
	ts = ts_arr[i]
	buf = buf_arr[i]

	eth = dpkt.ethernet.Ethernet(buf)
	try:
		ip = eth.data
		tcp = ip.data
		src_set = str(ip_decode(ip.src)) + " " + str(tcp.sport)
		dst_set = str(ip_decode(ip.dst)) + " " + str(tcp.dport)
		if(tcp.flags==dpkt.tcp.TH_SYN and ip_decode(ip.dst)==COND_IP and tcp.dport==COND_PORT):
			# I Find well SYN Now!
			#print "SYN : " + src_set + ", " + dst_set 
			if(not tcpstack.has_key(src_set)):
				# First meet
				tcpstack[src_set] = dst_set
				flow_s2d[src_set] = ""
				flow_d2s[src_set] = ""
				stream_num[src_set] = sn
				stream_packetnum[src_set] = 0
				os.system("rm -rf " + COND_IP + "/" + str(stream_num[src_set]))
				os.mkdir(COND_IP + "/" + str(stream_num[src_set]))
				sn = sn + 1
		elif(tcp.flags==(dpkt.tcp.TH_ACK | dpkt.tcp.TH_PUSH)):
			if(tcpstack.has_key(src_set)):
				# src -> dst
				#print "src -> dst"
				#print src_set + " -> " + dst_set
				#print tcp.data
				flow_s2d[src_set] = flow_s2d[src_set] + tcp.data
				f = open(COND_IP + "/" + str(stream_num[src_set]) + "/" + str(stream_packetnum[src_set]) + "_s2d", "wb")
				f.write(tcp.data)
				f.close()
				stream_packetnum[src_set] = stream_packetnum[src_set] + 1
			if(src_set in tcpstack.values()):
				# dst -> src
				#print "dst -> src"
				#print src_set + " -> " + dst_set
				#print tcp.data
				flow_d2s[dst_set] = flow_d2s[dst_set] + tcp.data
				f = open(COND_IP + "/" + str(stream_num[dst_set]) + "/" + str(stream_packetnum[dst_set]) + "_d2s", "wb")
				f.write(tcp.data)
				f.close()
				stream_packetnum[dst_set] = stream_packetnum[dst_set] + 1
		elif(tcp.flags==(dpkt.tcp.TH_FIN | dpkt.tcp.TH_ACK)):
			# Good bye~
			if(tcpstack.has_key(src_set)):
				del tcpstack[src_set]
				print flow_s2d[src_set]
				print flow_d2s[src_set]
				f = open(COND_IP + "/" + str(stream_num[src_set]) + "/s2d", "wb")
				f.write(flow_s2d[src_set])
				f.close()
				f = open(COND_IP + "/" + str(stream_num[src_set]) + "/d2s", "wb")
				f.write(flow_d2s[src_set])
				f.close()
	except:
		continue
print "End"
f.close()
