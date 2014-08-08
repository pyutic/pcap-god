import socket, glob

destIP = "localhost"
destPort = 31337
sz = 4096
out = "OUT"

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


#inout(destIP, destPort, data)

for ii in glob.glob(out+"/*"):
	data = []
	for i in glob.glob(ii+"/*"):
		# packet in one stream
		f = open(i, "rb")
		data.append(f.read())
	inout(destIP, destPort, data)
