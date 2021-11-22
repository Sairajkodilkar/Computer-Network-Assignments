from library import *

rdt = RDT(0)
rdt.bind(('127.0.0.1', 8080))
data = rdt.recv(1024)
rdt.send(data)

print(data.decode())
rdt.close()
