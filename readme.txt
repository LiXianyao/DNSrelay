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
