dnsrelay.py v1.0
-used getopt to process arguments
-initialize the dns server and file path settings
-build main() function
-in main()
	-receive UDP packet from port 53
-------------------------------------------------------

update v1.1 2017/3/12
dnsrelay.py
-�ع��˴��룬�����ܲ��Ϊ���ģ��
-��argument�������argProcess()������
-in main()
	-����dataProcess.pyģ���е�dnsAnalyze(data)���������������Ƿ��в�ѯ�����������ֱ�ӽ��������addr����������Ŀͻ��ˣ�����û�������network.pyģ���е�dnsQuery(data,addr)��һ����ѯ
	-Ϊ�˱��� ��[WinError 10054] Զ������ǿ�ȹر���һ�����е����ӡ���ÿ�γ��Խ���ʧ��ʱ����bind,�ƺ����м�С���ʳ���

network.py
-�������ڴ��������������ĺ�������
	-class send ������Ҫʹ�õı���
	-class recv ���ܶ˿ڱ���
	-def waitResp(data,addr) ����һ���̷߳��Ͳ�ѯ��Ϣdata��������53�˿ڣ����ȴ�������Ϣ�����ܵ��󷵻ظ�addr����������Ŀͻ��ˣ�
	-def dnsQuery(data,addr) �����߳�waitResp(data,addr)

dataProcess.py
-���뺯�� dnsAnalyze(data) �÷���ע�ͣ�������

fileProcess.py
-δ��ӣ��ӿ�����dataProcess.py ���

-----------------------------------------------------

update v1.2
fileProcess.py
-������file�࣬ά��һ��dictionary��������֪��dnsӳ�䣬�����ļ�ͬ��
	-path ������ļ����ڵ�·��
	-ipDict ���ڴ���������ip��ַ֮���ӳ���ϵ
	-def __init__(self,setPath) ���캯������ʼ��dict��
	-def getIPaddress(self,domain) �����Ƿ���������Ͳ�ѯ�ĵ�ַ�б�
	-def addDomain(self,domain,Ipaddress) ���������ַ�б���뵽ά����dictionary���ļ�����

�޸���network��dataProcess�нӿ�

·�������ƶ���file����

update v1.3
����dataProcess.py�У��ֽ�query�е�domain�ĺ���getDomain��domain�ĽṹΪlist����string,�����ز�ѯ�������ܶԽ���ɣ��������������ڴ��󣻹ر�DHCPʹ�ò�ѯ���������ᱻ�Զ�׷��ĩβ

update v1.4
���dataProcess�ж���Ӧ���ķ������ܣ���IP�������;
����ԭgetDomain��������©�ĶԲ�ѯ���͡���ѯ���ֶεĴ������ӶԲ�ѯ���͵��жϴ���
���Ӷ���fileProcessģ�麯���Ľӿڵġ���ѯ���͡�Ҫ��
