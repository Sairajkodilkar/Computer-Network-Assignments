from library import *

rdt = RDT(0)
rdt.connect(('127.0.0.1', 8080))
try:
    rdt.send("my data".encode())
except RuntimeError as error:
    print(error)

data  = rdt.recv(1024)
print(data.decode())
rdt.close()
