import socket
import sys, getopt

from dataProcess import dnsAnalyze
from network import *

#import fileProcess

#--------------------dns server and file path setting------------------

def argProcess():
    try:
        opt, args = getopt.getopt(sys.argv[1:],"d::")
        for op,val in opt: # if no argument is accepted
            if op == "-d":
                #print("val:",val)
                if val == "d": #arguments in the format -dd dns path
                    if len(args) != 2:
                        print("too few or too much arguments.")
                        sys.exit()
                    print("set server and path as",args[0],args[1])
                    send.dnsServer = args[0]
                    send.filePath = args[1]
                else: #argument in the format -d dns 
                    send.dnsServer = val
                    print("set dns server as:",val)
            else:
                print("invalid argument.")
                sys.exit()
    except:
        print("input arg is not accepted.")
        sys.exit()

    print("settings complete.")

    #network.dnsQuery(b'\xf0\xf1\xf2',"127.0.0.1") #for testing

#------------------------------------------------------------------


def main():
    #process arguments and init certain values
    argProcess()
    
    recv.soc.bind(recv.addr)
    print("connected")
    
    while True:
        #try get data from port 53, if failed ,re-bind the address
        try:
            data, addr = recv.soc.recvfrom(2048)
            print("client request:",data, addr)
        except:
            print("re-bind")
            recv.soc.bind(recv.addr)
            continue
        
        #analyze the request received
        dnsFound, response = dnsAnalyze(data)
        #if we find it in file, return it; if not, send a query to dns server
        if dnsFound:
            recv.soc.sendto(response,addr)
            print("local response:",response,addr)
        else:
            dnsQuery(data,addr)
        

    #recv.soc.close()


if __name__ == "__main__":
    main()
