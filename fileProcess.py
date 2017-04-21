#need two function to interact to the fileProcess Model:
# bool dnsFound, string response[] = getIPaddress( domain )

# void addDomain(domain, IPaddrees[])

import sys

class file:
    #path = "dnsrelay.txt"
    ipDict = dict()
    
    def __init__(self,setPath):
        self.path = setPath
        f = open(self.path,'r')
        for line in f:
            #print(line,end='')
            if not line.isspace():
                s = line.split()
                if s[1] in self.ipDict:
                    self.ipDict[s[1]].append(s[0])
                else:
                    self.ipDict[s[1]] = [s[0]]

        f.close()
        return
    
    def getIPaddress(self,domain):
        #domain is a string
        try:
            return True, self.ipDict[domain]
        except:
            print(sys.exc_info())
            return False, []
        
    def addDomain(self,domain,Ipaddress):
        f = open(self.path,'a')
        for ip in Ipaddress:
            f.write(ip + ' ' + domain + '\n')
            if domain in file.ipDict:
                self.ipDict[domain].append(ip)
            else:
                self.ipDict[domain] = [ip]
        f.close()
        return

#test below
if __name__ == "__main__":
    #'''
    f = file("dnsrelay.txt")
    print(f.getIPaddress('test1'))

    print(f.getIPaddress('test3'))
    #f.addDomain('test3',['0.0.0.0','0.0.0.1'])
    #'''
