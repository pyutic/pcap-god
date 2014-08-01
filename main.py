import dpkt

def ip_decode(p):
	return ".".join(["%d" % ord(x) for x in str(p)])

ts_arr = []
buf_arr = []

name = raw_input("Name => ")
f = open(name,'rb')
pcap = dpkt.pcap.Reader(f)

for a, b in pcap:
	ts_arr.append(a)
	buf_arr.append(b)

#print len(ts_arr), len(buf_arr)

start = 0
syn_yes = 0
while(1):
	syn_yes = 0
	# Find SYN
	for i in range(start, len(ts_arr)):
		ts = ts_arr[i]
		buf = buf_arr[i]

		eth = dpkt.ethernet.Ethernet(buf)
		try:
			ip = eth.data
			tcp = ip.data
			#print ip_decode(ip.src), ip_decode(ip.dst)
			#print tcp.seq, tcp.ack
			#print tcp.data
			if(tcp.flags==dpkt.tcp.TH_SYN):
				syn_yes = 1
				start = i+1
				break
		except:
			continue
	
	if(syn_yes == 0):
		print "Cannot find SYN Anymore\nGood Bye~"
		break

	print "Find SYN OK => %d" % i
	# Find else handshake
	# Find Data... starts with 'start'
	print "1"
f.close()
