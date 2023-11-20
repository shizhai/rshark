[TOC]

# windows直接访问
## IT部分
### windows系统环境
依赖的软件python与wireshark已经在本文件同级目录提供

* 安装python3.8，并在安装过程中选择自动添加进环境变量

* 安装最新版本wireshark并配置wireshark至环境变量中[参考](https://zhuanlan.zhihu.com/p/231668109)

## User部分
1. 使用notepad++编辑“clients”，按照格式要求修改为用于抓包的设备，目前支持openwrt与ubuntu
> * user: 抓包设备的SSH登录用户名
> * pass: 抓包设备的SSH登录密码
> * port: 抓包设备的SSH登录port，默认为22，一般无需修改
> * ip:   抓包设备的IP地址
> * use tunnel: 是否命令行模式，当前支持命令行模式(for RD)与http(for AUTOTEST)交互控制模式
> * type: 抓包设备的类型，当前支持openwrt, ubuntu
> * chan: 需要抓取的目标信道
> * intf(s): 抓包设备支持的所有接口列表，使用","隔开，若未传入参数，则默认使用第一个接口
> 
2. 首次使用需要执行一次`win_init.bat`脚本

### RD模式使用说明
1. 若使用源码release版本：修改clients配置文件之后再双击 "start.bat"启动，首次会检测环境依赖是否完整，不完整将自动安装python依赖，请保证电脑处理连接外网，并且未开启代理
2. 若使用exe release版本：修改clients配置文件之后再双击rshark.exe文件即可

### AUTOTEST使用说明
1. 若使用源码release版本：双击windows批处理脚本："damon.bat"启动，首次会检测环境依赖是否完整，不完整将自动安装python依赖，请保证电脑处理连接外网，并且未开启代理
2. 若使用exe release版本，修改clients配置文件之后再双击asrd.exe文件即可

## 版本历史
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