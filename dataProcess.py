# -*- coding: utf-8 -*-
# given the DNS message "data" in format<'bytes'>
# return two values dnsFound<'bool'> and response<'bytes'>
# where dnsFound shows if the domain name is found
# and response is the dns response if domain name is found,else return 0

from fileProcess import file
def dnsAnalyze(data,record ,debug_lv,time,no):
    #bytes should trans to bytearray
    dataArray = bytearray(data)
    datalen = len(dataArray)
    ID = ( dataArray[0] <<4) + dataArray[1]
    QR = dataArray[2] & 0x80 #judge if it's query or response
    OPCODE = dataArray[2] & 0x78 #judge if it's query or response
    AA = dataArray[2] & 0x04 #judge if it's query or response
    TC = dataArray[2] & 0x02 #judge if it's query or response
    RD = dataArray[2] & 0x01 #judge if it's query or response
    RA = dataArray[3] & 0x80 #judge if it's query or response
    Z = dataArray[3] & 0x70 #judge if it's query or response
    RCODE = dataArray[3] & 0x0F #judge if it's query or response
    
    #numbers of query and answer resources
    queryNum = ( dataArray[4] <<4) + dataArray[5]
    ansNum =  (dataArray[6] <<4) + dataArray[7]
    nsNum = ( dataArray[8] <<4) + dataArray[9]
    arNum =  (dataArray[10] <<4) + dataArray[11]

    #get the list of queried domains, and the pointer to the first byte of ans resources
    ansPtr, domain, QTYPE,CLASS,TYPE = getDomain( dataArray, queryNum)

    #initial value of the returned varience
    dnsFound = False
    response = ''
    
    
    if QR==0 and QTYPE ==4:# is query, get the domain what to serch and give the result
        domainsIP = list()
        dnsFound, domainsIP = record.getIPaddress( domain )# ,QTYPE)
        #print("getIP as ",dnsFound, domainsIP)
        
        dataArray[2] = dataArray[2] | 0x80#change the QR as response type 1

        if dnsFound == True:
            #找到一个表示禁用的0.0.0.0ip地址
            if '0.0.0.0' in domainsIP:
            #set the RCODE as 3: the domain name referenced in the query does not exist.
                dataArray[3] = dataArray[3] & 0xF0 #set the RCODE segment into zero
                dataArray[3] = dataArray[3] | 0x03 # then filled it as ERROR

            else:#query is for ip address
                #construct and append the answer resources into the dnspacket
                ansNum = len( domainsIP)# numbers of IP we found
                for IP in domainsIP:
                    ans = constructAns(IP,QTYPE)
                    dataArray+=ans
                    
                    #modify the number of answer's resources
                    if dataArray[7]==0xFF:
                        dataArray[6]+=1
                        dataArray[7]=0
                    else:
                        dataArray[7]+=1;

            response = bytes(dataArray)
            
    elif QR == 128 :# if QR=1 which means it is a response packet
        #check if it's correct, and add into the file if it's not exist
        if hasError(dataArray[3])==False:
            domainsIP = list()#get the IP of the ANS from the packet
            domainsIP = analyseAns(dataArray,ansPtr,ansNum)
            record.addDomain(domain, domainsIP)
            #print("get IPS ",domainsIP,"for domain ",domain)
            
        response = ''
        dnsFound = False


    if debug_lv == 1:
        print ('\t%.2f %d: %s' %(time,no,domain))
    if debug_lv==2:
        print ('\t%.2f %d: %s, TYPE %d, CLASS %d' %(time,no,domain,TYPE,CLASS))
        print ('\tID %d, QR %d, OPCODE %d, AA %d, TC %d, RD %d, RA%d, Z %d,RCODE %d' %(ID,QR,OPCODE,AA,TC,RD,RA,Z,RCODE))
        print ('\tQDCOUNT %d, ANCOUNT %d, NSCOUNT %d, ARCOUNT %d' %(queryNum,ansNum,nsNum,arNum))
        print ('RECV (%d bytes)' %(datalen) , data)
    
    #when ip=0.0.0.0 produce a response with alert
    return dnsFound, response


#get the IP from the ANS resources of the packet
def analyseAns( dataArray, headPtr, ansNum ):
    IPS = list()

    while ansNum>0:#get IP from each resources
        #handling the name field
        if( dataArray[headPtr]&0xC0) == 0xC0: #the domain is a pointer
            headPtr+=2; #skip 2 bytes
        else: #is a name
            while dataArray[headPtr]!= 0:
                length = dataArray[headPtr]
                headPtr += 1+length;#ptr skip the name
            headPtr+=1 #skip the len=0 segment

        #the TYPE field
        TYPE = (dataArray[headPtr]<<4)+dataArray[headPtr+1]
        headPtr+=4#skip TYPE and CLASS field
        
        headPtr += 4#skip TTL

        RDLENGTH  = (dataArray[headPtr]<<4)+dataArray[headPtr+1]
        headPtr += 2#skip RDLENGTH

        if TYPE ==1: #get an IPV4 address
            ip=''
            for i in range(4):
                ip +='.' + str(dataArray[headPtr + i])
            #print("get an ip "+ip)
            IPS.append(ip[1:])# add the ip address into ans
            
        #else if TYPE== 28:# get an IPV6 address
            #   ip=''
            #for i in range(8):
            #    ip +=':' + bytearray.hex(dataArray[headPtr + 2*i: headPtr+ 2*i+2])
            #IPS.append(ip[1:])    
            
        #else: #not an ip address, do nothing

        headPtr += RDLENGTH     #skip the RDLENGTH
            
        ansNum-=1
    
    return IPS



def constructAns(ip, QTYPE):
    ans = bytearray()
    #print("handling ip "+ip)
    ans += bytearray.fromhex('C00C')#ptr to the domain name

    if QTYPE == 6 :#ipv6 address
        ans.append(0)
        ans.append(28)
        RDLength = bytearray.fromhex('0010')
        RDATA = bytearray()
        ip = ip.split(':')
        for byte in ip:
            byte = bytearray.fromhex(byte)
            RDATA.append(byte)
    else: #ipv4 address, then the TYPE is A - 01
        ans.append(0)
        ans.append(1)
        RDLength = bytearray.fromhex('0004')
        RDATA = bytearray()
        ip = ip.split('.')
        for byte in ip:
            byte = int(byte)
            RDATA.append(byte)

    #the CLASS usually be \x00\x01
    ans.append(0)
    ans.append(1)

    TTL = hex(172800)
    fillLen = 10-len(TTL) #fill the len to 4 bytes ('0x' in TTL[] should drop)
    zero = '0' * fillLen
    #change TTL into bytearray
    TTL = bytearray.fromhex(zero+TTL[2:])    
        
    ans += TTL + RDLength + RDATA
    #print("return as ", ans)
    return ans


def getDomain( dataArray, queryNum):
    headPtr=12
    aDomain=''

    while queryNum>0:
        RDLength = 0
        aDomain=''
        while dataArray[headPtr]!= 0:
            aDomain += '.'
            length = dataArray[headPtr]
            aDomain += dataArray[headPtr+1: headPtr+1+length].decode()
            headPtr += 1+length;#ptr forward
            
        headPtr+=1 #skip the len=0 segment   
        aDomain = aDomain[1:]
        queryNum -= 1

    QTYPE = -1
    TYPE = (dataArray[headPtr]<<4)+dataArray[headPtr+1]
    if TYPE==1:#query type is ipv4
        QTYPE = 4
    elif TYPE == 28:#query type is ipv6
        QTYPE = 6

    headPtr += 2 #skip the query type
    CLASS = (dataArray[headPtr]<<4)+dataArray[headPtr+1]
    headPtr += 2 #skip the query class

    return headPtr, aDomain, QTYPE,CLASS,TYPE


#judge whether the query has error
def hasError(data):
    #the query has error
    if ( data & 0x0F ) >0: #the rcode frame is not 0[correct]
        judge = True
    else:
        judge = False
    return judge
