
# given the DNS message "data" in format<'bytes'>
# return two values dnsFound<'bool'> and response<'bytes'>
# where dnsFound shows if the domain name is found
# and response is the dns response if domain name is found,else return 0


#from fileProcess import getIPadress, addDomain

def dnsAnalyze(data):
    #bytes需要转化为bytearray
    dataArray = bytearray(data)
    QR = dataArray[2] and 0x80 #根据QR判断此报文为查询or响应
    
    #numbers of query and answer resources
    queryNum = ( dataArray[4] <<4) + dataArray[5]
    ansNum =  (dataArray[6] <<4) + dataArray[7]

    #get the list of queried domains, and the pointer to the first byte of ans resources
    ansPtr, domain = getDomain( dataArray, queryNum)

    if QR==0:# is query, get the domain what to serch and give the result
        dnsFound, domainsIP = getIPadress( domain )
        dataArray[2] = dataArray[2] or 0x80#change the qr as response type

        if domainsIP == '0.0.0.0':
        #set the RCODE as 3: the domain name referenced in the query does not exist.
            dataArray[3] = dataArray[3] and 0xF0
            dataArray[3] = dataArray[3] or 0x03

        #construct and append the answer resources into the dnspacket
        ansNum = len( domainsIP)# numbers of IP we found
        for IP in domainsIP:
            #return should be a bytearray
            ans = constructAns(IP)
            dataArray.append(ans)
            
        response = bytes(dataArray)
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


def constructAns(IP):

    ans = bytearray()
    
    for ip in IP:
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
        
    return ans


def getDomain( dataArray, queryNum):

    domain=''
    headPtr=12

    while queryNum>0:
        RDLength = 0
        aDomain=''
        while dataArray[headPtr]!= 0:
            aDomain += '.'
            length = dataArray[headPtr]# 这段的长度
            aDomain += dataArray[headPtr+1: headPtr+1+length].decode()#这段域名
            
            headPtr += 1+length;#指针后移
        aDomain = aDomain[1:]
        print("find a domain %s",aDomain)
        queryNum -= 1
        domain += aDomain
        if query>0:
            domain += ','
    domain = str.split(',')
    return headPtr, domain

def hasError(data):
    #the query has error
    if ( data and 0xFF ) >0:
        judge = TRUE
    else:
        judge = FALSE
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
