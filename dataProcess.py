
# given the DNS message "data" in format<'bytes'>
# return two values dnsFound<'bool'> and response<'bytes'>
# where dnsFound shows if the domain name is found
# and response is the dns response if domain name is found,else return 0


#from fileProcess import getIPadress, addDomain

def dnsAnalyze(data):
    #bytes should trans to bytearray
    dataArray = bytearray(data)
    QR = dataArray[2] & 0x80 #judge if it's query or response
    print("QR = %d while dataArray = %d" %(QR,dataArray[2]))
    
    #numbers of query and answer resources
    queryNum = ( dataArray[4] <<4) + dataArray[5]
    ansNum =  (dataArray[6] <<4) + dataArray[7]

    #get the list of queried domains, and the pointer to the first byte of ans resources
    ansPtr, domain = getDomain( dataArray, queryNum)

    if QR==0:# is query, get the domain what to serch and give the result
        domainsIP = list()
        print("try to find something here")
        #dnsFound, domainsIP = getIPadress( domain )
        dnsFound = True
        domainsIP= ["220.181.141.250","255.255.255.255"]
        
        dataArray[2] = dataArray[2] | 0x80#change the qr as response type

        if dnsFound == True:
            if domainsIP == '0.0.0.0':
            #set the RCODE as 3: the domain name referenced in the query does not exist.
                dataArray[3] = dataArray[3] & 0xF0
                dataArray[3] = dataArray[3] | 0x03

            #construct and append the answer resources into the dnspacket
            ansNum = len( domainsIP)# numbers of IP we found
            for IP in domainsIP:
                #return should be a bytearray
                ans = constructAns(IP)
                dataArray+=ans
                #modify the number of answer's resources
                if dataArray[7]==0xFF:
                    dataArray[6]+=1
                    dataArray[7]=0
                else:
                    dataArray[7]+=1;

            response = bytes(dataArray)
            print("form as " , response)
            
    else:# is response
        #check if it's correct, and add into the file if it's not exist
        if hasError(dataArray[3])==False:
            #addDomain(domain, domainsIP)
            print("add something here")
            #add in
        response = ''
        dnsFound = False
    
    #when ip=0.0.0.0 produce a response with alert
    return dnsFound, response


def constructAns(ip):

    ans = bytearray()
    print("handling ip "+ip)
    ans += bytearray.fromhex('C00C')#ptr to the domain name

    if ip.find(':')>0 :#ipv6 address
        print("get an ipv6")
        #some process
    else: #ipv4 address, then the TYPE is A - 01
        ans.append(0)
        ans.append(1)
        RDLength = bytearray.fromhex('0004')

    #the CLASS usually be \x00\x01
    ans.append(0)
    ans.append(1)

    TTL = hex(172800)
    fillLen = 10-len(TTL) #fill the len to 4 bytes ('0x' in TTL[] should drop)
    zero = '0' * fillLen
    #change TTL into bytearray
    TTL = bytearray.fromhex(zero+TTL[2:])

    RDATA = bytearray()
    ip = ip.split('.')
    for byte in ip:
        byte = int(byte)
        RDATA.append(byte)
        
        
    ans += TTL + RDLength + RDATA
    print("return as ", ans)
    return ans


def getDomain( dataArray, queryNum):

    domain=''
    headPtr=12

    while queryNum>0:
        RDLength = 0
        aDomain=''
        while dataArray[headPtr]!= 0:
            aDomain += '.'
            length = dataArray[headPtr]
            aDomain += dataArray[headPtr+1: headPtr+1+length].decode()
            
            headPtr += 1+length;#ptr forward
        aDomain = aDomain[1:]
        print("find a domain "+aDomain)
        queryNum -= 1
        domain += aDomain
        if queryNum>0:
            domain += ','
    domain = str.split(',')
    return headPtr, domain

def hasError(data):
    #the query has error
    if ( data and 0xFF ) >0:
        judge = True
    else:
        judge = False
    return judge
#modify flags

#when adding, just return False,''

#TYPE=A(HOST ADRESS) 1 ;AAAA(IPV6) 28; CNAME 5


#determine if the dns is query or response

#return the checking result and response pack( to the client)

#add the response in the table if it's not in

#need two function to interact to the fileProcess Model:
# bool dnsFound, string response[] = getIPadress( domain )
# void addDomain(domain, IPadrees[])
