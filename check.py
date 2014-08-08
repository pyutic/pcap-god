import socket, glob, argparse

sz = 409600

def inout(destIP, destPort, data):
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.connect((destIP, destPort))

	rt = 1
	i = 0
	while(i<len(data)):
		if(data[i][:2]=="SD"):
			s.send(data[i][2:])
			f = "r"
			
		elif(data[i][:2]=="DS"):
			rcv = s.recv(sz)
			prd = data[i][2:]
			if(rcv!=prd):
				rt = 0
				print "-"*20+"Recved"
				print rcv
				print "="*20+"Predicted"
				print prd
			f = "s"

		i = i+1
	return rt

parser = argparse.ArgumentParser()
parser.add_argument("-o", help="Output Folder")
parser.add_argument("-d", help="Destination IP")
parser.add_argument("-p", help="Destination Port", type=int)
args = parser.parse_args()

out = args.o
destIP = args.d
destPort = args.p

for ii in glob.glob(out+"/*"):
	data = []
	i = 0
	while(1):
		# packet in one stream
		try:
			f = open(ii+"/"+str(i), "rb")
		except:
			break
		i = i+1
		data.append(f.read())
		f.close()
	print destIP, destPort
	inout(destIP, destPort, data)
