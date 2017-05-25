import threading
import socket
import time

from dataProcess import dnsAnalyze

class send:
    dnsServer = "10.3.9.5"
    debug_lv = 0
    no = 0
    start_time = 0
    
def get_time():
    return round(time.clock() - send.start_time,3)

class recv:
    addr = ('',53)
    soc = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

lock = threading.Lock()

# thread function waiting for respond
def waitResp(data,addr,record):
    udpSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    global lock
    if lock.acquire():
        udpSocket.sendto(data,(send.dnsServer,53))
        #print("query for response:",data,(send.dnsServer,53))
        noResp = True
        while noResp:
            try:
                recvData, recvAddr = udpSocket.recvfrom(2048)
        #        print("response:", recvData, recvAddr)
                noResp = False
            except:
                print("noResponse.")
    #send pack to analyze, save query result to file    
    dnsAnalyze(recvData,record,send.debug_lv,get_time(),send.no)
    send.no = send.no + 1
    lock.release()
    #send response to client
    recv.soc.sendto(recvData,addr)
    #print("reponse to client:",recvData,addr)
    
# build thread, send request to server, and wait for response
def dnsQuery(data,addr,record):
    # build thread
    threading.Thread(target = waitResp, args = (data,addr,record)).start()
        
