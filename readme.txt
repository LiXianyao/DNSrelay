dnsrelay.py v1.0
-used getopt to process arguments
-initialize the dns server and file path settings
-build main() function
-in main()
	-receive UDP packet from port 53
-------------------------------------------------------

update v1.1 2017/3/12
dnsrelay.py
-重构了代码，将功能拆分为多个模块
-将argument处理放入argProcess()函数中
-in main()
	-调用dataProcess.py模块中的dnsAnalyze(data)函数，分析本地是否有查询结果，若有则直接将结果发给addr（发出请求的客户端），若没有则调用network.py模块中的dnsQuery(data,addr)进一步查询
	-为了避免 “[WinError 10054] 远程主机强迫关闭了一个现有的连接”，每次尝试接收失败时重新bind,似乎仍有极小概率出错

network.py
-加入用于处理网络相关问题的函数和类
	-class send 发送需要使用的变量
	-class recv 接受端口变量
	-def waitResp(data,addr) 建立一个线程发送查询信息data到服务器53端口，并等待接受信息，接受到后返回给addr（发出请求的客户端）
	-def dnsQuery(data,addr) 创建线程waitResp(data,addr)

dataProcess.py
-加入函数 dnsAnalyze(data) 用法见注释，待补充

fileProcess.py
-未添加，接口需与dataProcess.py 设计

-----------------------------------------------------

update v1.2
fileProcess.py
-建立了file类，维护一个dictionary，保存已知的dns映射，并与文件同步
	-path 保存的文件所在的路径
	-ipDict 用于储存域名与ip地址之间的映射关系
	-def __init__(self,setPath) 构造函数，初始化dict，
	-def getIPaddress(self,domain) 返回是否存在域名和查询的地址列表
	-def addDomain(self,domain,Ipaddress) 将域名与地址列表加入到维护的dictionary和文件表中

修改了network，dataProcess中接口

路径保存移动至file类中

update v1.3
纠正dataProcess.py中，分解query中的domain的函数getDomain中domain的结构为list而非string,将本地查询与拆包功能对接完成；测试域名不存在错误；关闭DHCP使得查询的域名不会被自动追加末尾

update v1.4
完成dataProcess中对响应包的分析功能，将IP剥离出来;
修正原getDomain函数中遗漏的对查询类型、查询类字段的处理，增加对查询类型的判断处理；
增加对于fileProcess模块函数的接口的《查询类型》要求
