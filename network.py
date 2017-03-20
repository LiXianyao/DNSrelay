import threading
import socket

from dataProcess import dnsAnalyze

class send:
    dnsServer = "10.3.9.5"
    filePath = "\dnsrelay.txt"

class recv:
    addr = ('',53)
    soc = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# thread function waiting for respond
def waitResp(data,addr):
    udpSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    udpSocket.sendto(data,(send.dnsServer,53))
   # print("query for response:",data,(send.dnsServer,53))
    noResp = True
    while noResp:
        try:
            recvData, recvAddr = udpSocket.recvfrom(2048)
    #        print("response:", recvData, recvAddr)
            noResp = False
        except:
            print("noResponse.")
    #send pack to analyze, save query result to file    
    dnsAnalyze(recvData)
    #send response to client
    recv.soc.sendto(recvData,addr)
    print("reponse to client:",recvData,addr)
    
# build thread, send request to server, and wait for response
def dnsQuery(data,addr):
    # build thread
    threading.Thread(target = waitResp, args = (data,addr)).start()
        
