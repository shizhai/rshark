[TOC]

# ashark & asrd for Windows
## IT部分
### windows系统环境
* 安装最新版本wireshark,**并创建开始菜单**

## User部分
使用notepad++编辑“clients”，按照格式要求修改为用于抓包的设备，目前支持openwrt与ubuntu
> * user: 抓包设备的SSH登录用户名
> * pass: 抓包设备的SSH登录密码
> * port: 抓包设备的SSH登录port，默认为22，一般无需修改
> * ip:   抓包设备的IP地址
> * use tunnel: 是否命令行模式，当前支持命令行模式(for RD)与http(for AUTOTEST)交互控制模式
> * type: 抓包设备的类型，当前支持openwrt, ubuntu
> * chan: 需要抓取的目标信道
> * intf(s): 抓包设备支持的所有接口列表，使用","隔开，若未传入参数，则默认使用第一个接口

### RD模式使用说明
* ashark.exe用于图形界面与命令行参数
> 鼠标双击打开ashark.exe
> 
> 修改clients配置文件，一个clients配置文件可以添加多台设备
> 
> 打开软件后可以通过下拉列表选择目标sniffer设备
> 
> 参考ashark --help传入对应参数，一个CMD窗口仅支持一台sniffer设备

### SAT使用说明
* 双击asrd.exe
* 修改clients文件添加sniffer设备，asrd支持多台sniffer设备，依次追加即可

## 版本历史
v3.6.1 @2024/01/02 <br>
> add channel bandwidth support<br>
> fix path error instead of os.path.join<br>

v3.5.2 @2023/12/29 <br>
> add zoom in/out for plot<br>
> add requirement.txt for python dependances<br>
> print packet sniffer per second in terminal<br>
> ignore favicon.ico<br>

v3.5.1 @2023/12/28 <br>
> add support write parsed data back to csv file<br>
> add support progressbar to indicate the plot & write back progress<br>
> add async support for render<br>

v3.4.4 @2023/12/27 <br>
> render plot by press the button instead of automatically while it cost too much time<br>

v3.4.3 @2023/12/27 <br>
> add support to list all for pshark<br>
> fix LOG color fail for INFO<br>
> remove some useless log<br>
> fix store to wireshark persist file fail with split to 4096GB for each file

v3.4.2 @2023/12/26 <br>
> fix log output miss timestamp and color<br>
> fix parse windows generated at startup, we should generate at right time<br>

v3.4.1

> add support to save sniffer device info

v3.3.6

> fix winget resize issues
> 
> use win style align to windows

v3.3.5

> fix can't exit asrd by press keyboard ctrl+c

v3.3.4

> fix mac filter fail for asrd: http://10.17.7.29:8000/?cmd=start&ip=192.168.8.1&interface=mon1&macs=d4:da:21:5c:e6:b6,60:55:f9:f7:2a:88

v3.3.3

> fix access file server in asrd fail as no root_dir passed

v3.3.2

> fix wireshark startup fail as use r""

v3.3.1

> add retry count for each rate
> 
> add pkt count for each rate
> 
> fix miss mgmt(assoc/auth) frame when pshark on the fly

v3.2.2

> add support to retry counts tendancy chart
> 
> add restart feature for asrd when firewall of windows kill us

v3.1.1

> support windows GUI
> 
> merge rshark with ashark to ashark to support cmd line and GUI
> 
> fix parse online fail when too many pkt arrived

v2.1.1

> add pshark support to parse rx performance

v2.0.1

> add support widget support for user input info
> 
> add support iperf client support
> 
> ashark for widget, rshark for cli command, asrd for QA web request

v1.6.1

> add netester support for DUT RX performance analize

v1.5.1

> add extract default sniffer devices list from clients for rshark
> 
> move temp store dir to current dir

v1.4.4

> fix store capture file with wrong name issue
> 
> fix pshark issues that cann't filter pkts

v1.4.1

> fix wrong time stamp to sniffer log when target system is running offline by sync time to peer
> 
> add GUI for rshark to input target’s infomation

v1.3.4

> fix time cost too long when use openwrt sniffer device to start capture

v1.3.3

> fix host not found cause application hang while running asrd

v1.3.2

> fix issue in case1 with connecting to WAN port of openwrt
> 
> fix fail to role back to APPDATA to search wireshark when fail during ProgramData

v1.3.1

> add ENV path for wireshark without manual operation, but wireshare should be installed in to "Start Menu"
> 
> fix ssh-key issue that path escap in win

v1.2.3

> fix capture files are delted automatically by os when exit the asrd

v1.2.2

> fix User PC cann't access internet when execute rshark with OpenWRT

v1.2.1

> add support gen ssh key automatically with user call win_init.bat

> add comment for clients

v1.1.1
> add support wifi_init.bat support which can add ssh key and wirehark env to windows automatically

v1.0.3
> fix asrd store file failed when win exe release is used which the path refer to Temp

v1.0.2
> fix asrd store file failed when "./stores" not found or created

v1.0.1
> add support exe without python libary dependance
> 
> add support openwrit configure file static version integrity

v0.9.7
> for damon.bat: add http file server support which support download capture file by web browser
> for example:
> > 1. start a sniffer by access url: 
> > http://10.17.7.29:8000/?cmd=start&ip=10.17.7.107&interface=mon1
> > 2. the response:
> > {"status": "OK", "msg": {"name": "sniffer0", "ip": "10.17.7.107", "interface": "mon1", "access": "http://10.17.7.29/10.17.7.107/2023_11_17_20_20_1_30.pcapng"}}
> > 3. we can download sniffer log by access
> > http://10.17.7.29/10.17.7.107/2023_11_17_20_20_1_30.pcapng
> > 
> 
> URI COMMANDs:
> 
> 查看可以抓包的终端设备列表：cmd=terms
> 
> 针对某个设备开启抓包：cmd=start&ip=10.17.7.107&interface=mon1
> 
> 停止某个正在抓包的进程：cmd=stop&ip=10.17.7.107&interface=mon1

v0.9.6
> add http damon.bat support for AUTOTEST

v0.9.5
> fix asrd http stop command cause script hang up issue by clean up resource allocate

v0.9.4
> fix windows delete running status file fail with getting script \_\_file\_\_

v0.9.3
> fix script hang up when raise for exception by call os.exit

v0.9.2
> configure openwrt by remote wireless file instead of uci directly