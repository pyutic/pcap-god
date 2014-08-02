import dpkt

def ip_decode(p):
	return ".".join(["%d" % ord(x) for x in str(p)])

ts_arr = []
buf_arr = []

name = "bob_nc.pcap"
#name = raw_input("Name => ")
f = open(name,'rb')
pcap = dpkt.pcap.Reader(f)

for a, b in pcap:
	ts_arr.append(a)
	buf_arr.append(b)

#print len(ts_arr), len(buf_arr)

tcpstack = []
flowdata = {}

for i in xrange(len(ts_arr)):
	ts = ts_arr[i]
	buf = buf_arr[i]

	eth = dpkt.ethernet.Ethernet(buf)
	try:
		ip = eth.data
		tcp = ip.data
		nm = str(ip_decode(ip.src)) + " " + str(tcp.sport) + " " + str(ip_decode(ip.dst)) + " " + str(tcp.dport)
		if(tcp.flags==dpkt.tcp.TH_SYN):
			# I Find SYN Now!
			print "SYN : " + ip_decode(ip.src), tcp.sport, ip_decode(ip.dst), tcp.dport
			tcpstack.append(nm)
		elif(tcp.flags==(dpkt.tcp.TH_ACK | dpkt.tcp.TH_PUSH)):
			if(nm in tcpstack):
				# I finished 3-way handshake
				print tcp.data
	except:
		continue

# Find else handshake
# Find Data... starts with 'start'
f.close()
