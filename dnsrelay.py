import socket
import sys, getopt

#--------------------dns server and file path setting------------------

dnsServer = "10.3.9.5"
filePath = "\dnsrelay.txt"

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
                dnsServer = args[0]
                filePath = args[1]
            else: #argument in the format -d dns 
                dnsServer = val
                print("-d",val)
        else:
            print("invalid argument.")
            sys.exit()
except:
    print("input arg is not accepted.")
    sys.exit()

print("settings complete.")

#------------------------------------------------------------------

    
#def dataProcess(data):
    

#def send():
    

def main():
    HOST = ''
    PORT = 53

    udpSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udpSocket.bind((HOST,PORT))

    while True:
        data, addr = udpSocket.recvfrom(2048)
        print(data,"",addr)
        type(data)

    udpSocket.close()


if __name__ == "__main__":
    main()
