import socket

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind(("127.0.0.1", 31337))
s.listen(5)

conn, addr = s.accept()

for i in xrange(3):
	data = conn.recv(1024)
	print "recv : " + data
	conn.send(data*4)

