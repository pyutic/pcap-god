import dpkt
import os
import argparse
import sys
import re
import time

def ip_decode(p):
	return ".".join(["%d" % ord(x) for x in str(p)])

def regex_check(cond, data):
	return bool(re.search(cond, data))

tm = int(round(time.time() * 1000))

ts_arr = []
buf_arr = []

parser = argparse.ArgumentParser()
parser.add_argument("-f", help="Pcap File")
parser.add_argument("-s", help="Source IP(Optional)")
parser.add_argument("-d", help="Destination IP")
parser.add_argument("-p", help="Destination Port", type=int)
parser.add_argument("-o", help="Output Folder")

args = parser.parse_args()

if(args.f):
	name = args.f
else:
	sys.exit("Cannot find value of -d")
print "Target File == " + name

if(args.s):
	COND_S = args.s
else:
	COND_S = ".*"
print "Source IP == " + COND_S

if(args.d):
	COND_IP = args.d
else:
	sys.exit("Cannot find value of -d")
print "Destination IP == " + COND_IP

if(args.p):
	COND_PORT = args.p
else:
	sys.exit("Cannot find value of -p")
print "Destination Port == " + str(COND_PORT)

if(args.o):
	OUTPUT = args.o
else:
	sys.exit("Cannot find value of -o")
print "Output Folder == " + OUTPUT

#---------------------------------
fi = open(name,'rb')
pcap = dpkt.pcap.Reader(fi)

os.system("rm -rf " + OUTPUT)
os.mkdir(OUTPUT)

for a, b in pcap:
	ts_arr.append(a)
	buf_arr.append(b)

#print len(ts_arr), len(buf_arr)

tcpstack = {} # {srcip port : dstip port}
stream_num = {}
stream_packetnum = {}
stream_last = {}
sn = 0
count = 0
per = 10
for i in xrange(len(ts_arr)):
	count = count + 1

	if((float(count*100)/len(ts_arr)) > per):
		print str(per) + "% OK"
		per = per + 10
	ts = ts_arr[i]
	buf = buf_arr[i]

	eth = dpkt.ethernet.Ethernet(buf)
	try:
		ip = eth.data
		tcp = ip.data
		src_set = str(ip_decode(ip.src)) + " " + str(tcp.sport)
		dst_set = str(ip_decode(ip.dst)) + " " + str(tcp.dport)
		if(tcp.flags==dpkt.tcp.TH_SYN and ip_decode(ip.dst)==COND_IP and tcp.dport==COND_PORT and regex_check(COND_S, ip_decode(ip.src))):
			# I Find well SYN Now!
			print "SYN : " + src_set + ", " + dst_set 
			if(not tcpstack.has_key(src_set)):
				# First meet
				tcpstack[src_set] = dst_set
				stream_num[src_set] = sn
				stream_packetnum[src_set] = 0
				os.system("rm -rf " + OUTPUT + "/" + str(stream_num[src_set]))
				os.mkdir(OUTPUT + "/" + str(stream_num[src_set]))
				sn = sn + 1
		elif(tcp.flags==(dpkt.tcp.TH_ACK | dpkt.tcp.TH_PUSH)):
			if(tcpstack.has_key(src_set)):
				# src -> dst
				#print "src -> dst"
				#print tcp.data
				f = open(OUTPUT + "/" + str(stream_num[src_set]) + "/" + str(stream_packetnum[src_set]), "wb")
				f.write("SD")
				f.write(tcp.data)
				f.close()
				stream_packetnum[src_set] = stream_packetnum[src_set] + 1
			if(src_set in tcpstack.values()):
				# dst -> src
				#print "dst -> src"
				#print src_set + " -> " + dst_set
				f = open(OUTPUT + "/" + str(stream_num[dst_set]) + "/" + str(stream_packetnum[dst_set]), "wb")
				f.write("DS")
				f.write(tcp.data)
				f.close()
				stream_packetnum[dst_set] = stream_packetnum[dst_set] + 1

		elif(tcp.flags==(dpkt.tcp.TH_FIN | dpkt.tcp.TH_ACK)):
			# Good bye~
			if(tcpstack.has_key(src_set)):
				del tcpstack[src_set]
	except:
		continue
print "\x1b[41mAll is Well :)\x1b[0m"
print "..." + str((int(round(time.time() * 1000))-tm)/1000.0) + "s"
fi.close()
