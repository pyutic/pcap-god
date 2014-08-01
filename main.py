import dpkt

def ip_decode(p):
	return ".".join(["%d" % ord(x) for x in str(p)])

name = raw_input("Name => ")
f = open(name,'rb')
pcap = dpkt.pcap.Reader(f)

for ts, buf in pcap:
	eth = dpkt.ethernet.Ethernet(buf)
	try:
		ip = eth.data
		tcp = ip.data
		print ip_decode(ip.src), ip_decode(ip.dst)
		print tcp.seq, tcp.ack
		print tcp.data
	except:
		continue
f.close()
