
# given the DNS message "data" in format<'bytes'>
# return two values dnsFound<'bool'> and response<'bytes'>
# where dnsFound shows if the domain name is found
# and response is the dns response if domain name is found,else return 0
def dnsAnalyze(data):


    dnsFound = False;
    response = ''
    #when ip=0.0.0.0 produce a response with alert
    return dnsFound, response
#modify flags

#when adding, just return False,''

#TYPE=A(HOST ADRESS) 1 ;AAAA(IPV6) 28; CNAME 5


#determine if the dns is query or response

#return the checking result and response pack( to the client)

#add the response in the table if it's not in

#need two function to interact to the fileProcess Model:
# bool dnsFound, string response[] = getIPadress( domain )
# void addDomain(domain, IPadrees[])
