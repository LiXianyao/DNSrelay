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
