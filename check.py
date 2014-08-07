import socket

destIP = "localhost"
destPort = 31337
sz = 4096

def inout(destIP, destPort, data, f):
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.connect((destIP, destPort))

	rt = 1
	i = 0
	while(i<len(data)):
		if(f=="s"):
			s.send(data[i])
			f = "r"
			
		elif(f=="r"):
			rcv = s.recv(sz)
			if(rcv!=data[i]):
				rt = 0
				print "-"*20+"Recved"
				print rcv
				print "="*20+"Predicted"
				print data[i]
			f = "s"

		i = i+1
	return rt

data = []
hola = ["1", "2", "1\n"]

for i in hola:
	data.append(i)
	data.append(i*2)

inout(destIP, destPort, data, "s")
