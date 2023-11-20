#!/usr/bin/env python3

import logging
import threading
import time
import sys
import signal
import argparse
import queue
import os
import subprocess
import paramiko
import pexpect
from pexpect import popen_spawn

#Popen 对象方法
# poll(): 检查进程是否终止，如果终止返回 returncode，否则返回 None。
# wait(timeout): 等待子进程终止。
# communicate(input,timeout): 和子进程交互，发送和读取数据。
# send_signal(singnal): 发送信号到子进程 。
# terminate(): 停止子进程,也就是发送SIGTERM信号到子进程。
# kill(): 杀死子进程。发送 SIGKILL 信号到子进程。

cli_running=False
cli_running_ip=None
cli_running_intf=None
rshark_running = os.path.split(os.path.realpath(__file__))[0] + "/rshark.running"

#[{"ip""ip addr", "user": "user name", ...}]
conf_hosts = []

def rshark_remove_running(ip, intf):
    new_lines = []
    if not cli_running:
        # print("test1")
        return

    if not os.path.exists(rshark_running):
        # print("test2")
        return
    # print(rshark_running)
    with open(rshark_running, "r") as rrf:
        while True:
            line = rrf.readline()
            if not line:
                break
            linex = line.split(",")
            if linex[0] == ip and linex[1] == intf:
                print("Remove running sniffer device{}@{}".format(ip, intf))
                continue

            new_lines.append(line)

        rrf.close()

    with open(rshark_running, "w") as rrf:
        for line in new_lines:
            rrf.write(line)
        rrf.close()

def rshark_check_running(ip, intf):
    if not os.path.exists(rshark_running):
        with open(rshark_running, "w") as rrf:
            rrf.write(ip + "," + intf)
            return False

    with open(rshark_running, "r") as rrf:
        while True:
            line = rrf.readline()
            if not line:
                break
            linex = line.split(",")
            if linex[0] == args.ip and linex[1] == args.interface:
                print("host {} with interface {} is runsing!".format(args.ip, args.interface))
                rrf.close()
                return True

        rrf.close()

    with open(rshark_running, "a") as rrf:
        rrf.write(ip + "," + intf)
        rrf.close()
        return False

def exit_sig(signum, frame):
    rshark_remove_running(cli_running_ip, cli_running_intf)
    sys.exit()

def rshark_from_conf(file):
    with open(file, "r") as conf_file:
        while True:
            line = conf_file.readline()
            if line.startswith("#"):
                continue
            if not line:
                break

            l = line.split("!")
            # user, pass, port, ip, use tunnel, type(openwrt, ubuntu), chan(for tunnel), intf(s)
            # use tunnel means that call from cli(1) or http(0)
            lhost = {}
            lhost["user"] = l[0]
            lhost["password"] = l[1]
            lhost["port"] = l[2]
            lhost["ip"] = l[3]
            if os.name != "posix":
                lhost["dst"] = "local://" + os.path.split(os.path.realpath(__file__))[0] + "\stores\\" + lhost["ip"] + "\\" # default store to script path
            else:
                lhost["dst"] = "local://" + os.path.split(os.path.realpath(__file__))[0] + "/stores/" + lhost["ip"] + "/"# default store to script path

            lhost["usetunnel"] = False if l[4] == "0" else True
            lhost["type"] = l[5]
            lhost["channel"] = l[6]
            lhost["interface"] = l[7].strip(",").split(",")
            lhost["interface"][-1] = lhost["interface"][-1].strip("\n")
            lhost["timeout"] = 10
            conf_hosts.append(lhost)
    pass

def rshark_lookup_hosts(ip, ifraise, useTunnel):
    for host in conf_hosts:
        if host["ip"] == ip and host["usetunnel"] == useTunnel:
            return host
    
    print("host: " + ip + " Not found!")
    if ifraise:
        raise
def rshark_get_hosts(useTunnel):
    rsp = []
    for item in conf_hosts:
        if item["usetunnel"] == useTunnel:
            rsp.append(item)

    return rsp

class Rshark():
    def __init__(self, rtype, rip, rport, ruser, rpasswd, lstore, intf, channel, macs, timeout):
        self.rip = rip
        self.rport = rport
        self.ruser = ruser
        self.rpasswd = rpasswd
        self.ostype = os.name
        self.macs = macs.split(",") if macs else []
        self.timeout = timeout
        self.wait_subprocess = []
        self.exit_event = threading.Event()
        self.start_eventq = queue.Queue()
        self.store_types = {
            "local": {"cb": self.rshark_store_local, "arg": None, "need_path": True},
            "wireshark": {"cb": self.rshark_store_wireshark, "arg": None, "need_path": False}
        }

        store_tmp = lstore.split("://", 1)
        if store_tmp[0] in self.store_types:
            self.store_type = store_tmp[0]
            if not store_tmp[1] and self.store_types[store_tmp[0]]["need_path"]:
                print("ERROR, local store method need path")
                # os.kill(os.getpid(), signal.SIGABRT)
                exit_sig(None, None)

            self.store_types[store_tmp[0]]["arg"] = store_tmp[1]
            self.lstore = self.store_types[store_tmp[0]]
        else:
            print("ERROR, store type {} not support!".format(store_tmp[0]))
            # os.kill(os.getpid(), signal.SIGABRT)
            exit_sig(None, None)

        self.intf = intf.strip("\n ")
        self.chan = channel
        self.timeout = 5
        self.rtypes = {
            "openwrt": { "cb": self.rshark_conf_openwrt, "ps": "ps w | grep \"tcpdump -i {}\" | grep -v 'grep' | awk '{{ print $1 }}' | head -n 1"},
            "ubuntu":  { "cb": self.rshark_conf_ubuntu, "ps": "ps aux | grep \"tcpdump -i {}\" | grep -v 'grep' | awk '{{ print $2 }}' | head -n 1" },
        }
        self.rtype = rtype

        if rtype in self.rtypes:
            self.conf_handler = self.rtypes[rtype]["cb"]
        else:
            print("ERROR, target device type {} not support!".format(rtype))
            # os.kill(os.getpid(), signal.SIGABRT)
            exit_sig(None, None)

        self.ssh = paramiko.SSHClient()
        key = paramiko.AutoAddPolicy()
        self.ssh.set_missing_host_key_policy(key)

        self.ssh.connect(self.rip, self.rport, self.ruser, self.rpasswd, timeout=self.timeout)

    def rshark_check_event(self):
        if self.exit_event.is_set():
            self.exit_event.set()
            return True
        return False
    
    def rshark_force_exit(self):
        if self.tcpdump_pid > 0:
            print("kill pid: ", self.tcpdump_pid)
            kill_str = "kill -9 " + str(self.tcpdump_pid)
            self.ssh.exec_command(kill_str)

        for item in self.wait_subprocess:
            item.kill()
            pass

        self.exit_event.set()
        self.ssh.close()

    def __del__(self):
        self.ssh.close()

    def rshark_conf_openwrt(self):
        #cmds = "for i in `seq 10`;do i=$((i-1));ifname=$(uci get wireless.@wifi-iface[$i].ifname 2>/dev/null);"
        #cmds = cmds + "if [ $? -gt 0 ];then break;fi;if [ \"$ifname\" == \"" + self.intf + "\" ];then echo $i;fi;done"
        ##print(cmds)
        #stdin, stdout, stderr = self.ssh.exec_command(cmds)
        #response = []
        #while True:
        #    rsp = stdout.readline().strip("\n ")
        #    if rsp:
        #        response.append(rsp)
        #        break

        #cmds = "uci set wireless.@wifi-iface[" + str(response[0]) + "].mode=monitor"
        ##print(cmds)
        #self.ssh.exec_command(cmds)
        #stdin, stdout, stderr = self.ssh.exec_command("uci get wireless.@wifi-iface[" + str(rsp) + "].device")
        #response = []
        #while True:
        #    rsp = stdout.readline().strip("\n ")
        #    if rsp:
        #        response.append(rsp)
        #        break

        if self.ostype != "posix":
            wireless_file = os.path.split(os.path.realpath(__file__))[0] + "\\" + "openwrt\\wireless"
        else:
            wireless_file = os.path.split(os.path.realpath(__file__))[0] + "/" + "openwrt/wireless"

        self.ssh.exec_command(">/etc/config/wireless")
        if os.path.exists(wireless_file):
            print("Read wireless config file from {}".format(wireless_file))
            #+ self.ruser +"@" + self.rip + ":/tmp/"
            with open(wireless_file, "r") as wireless_id:
                while True:
                    line = wireless_id.readline()
                    if not line:
                        break
                    line_cmd = "echo " + line.strip("\n") + " >> /etc/config/wireless"
                    # print(line_cmd)
                    self.ssh.exec_command(line_cmd)

                wireless_id.close()
        else:
            get_target_type = "if [ -n \"$(cat /etc/banner | grep openwrt -ri)\" ];then echo openwrt ;else echo QSDK;fi"
            stdin, stdout, stderr = self.ssh.exec_command(get_target_type)
            target_type = stdout.readline().strip("\n")
            print("Use static wireless({}) config file for OpenWrt!".format(target_type))


            if target_type == "QSDK":
                wireless_file_contents = '''
config wifi-device 'wifi0'
	option type 'qcawificfg80211'
	option channel 'auto'
	option hwmode '11axa'
	option disabled '1'
	option band '5G'
	option noscan '0'
	option htmode 'VHT80'
	option txpower '28'
	option txpower_max '28'
	option country 'US'
	option macaddr '94:83:c4:12:e0:70'

config wifi-iface
	option device 'wifi0'
	option network 'lan'
	option mode 'monitor'
	option ifname 'mon0'

config wifi-device 'wifi1'
	option type 'qcawificfg80211'
	option disabled '0'
	option band '2G'
	option noscan '0'
	option txpower '28'
	option txpower_max '28'
	option country 'CN'
	option macaddr '94:83:c4:12:e0:71'
	option htmode 'HT20'
	option hwmode '11axg'
	option channel '1'

config wifi-iface
	option device 'wifi1'
	option network 'lan'
	option mode 'monitor'
	option ifname 'mon1'
'''
            else:
                wireless_file_contents = """
config wifi-device 'radio0'
        option type 'mac80211'
        option path 'platform/soc/c000000.wifi'
        option channel '36'
        option band '5g'
        option htmode 'HE80'
        option disabled '0'

config wifi-iface 'default_radio0'
        option device 'radio0'
        option network 'lan'
        option mode 'monitor'
        option ssid 'OpenWrt'
        option encryption 'none'
        option ifname 'mon0'

config wifi-device 'radio1'
        option type 'mac80211'
        option path 'platform/soc/c000000.wifi+1'
        option channel '1'
        option band '2g'
        option htmode 'HE20'
        option disabled '0'

config wifi-iface 'default_radio1'
        option device 'radio1'
        option network 'lan'
        option mode 'monitor'
        option ssid 'OpenWrt'
        option encryption 'none'
        option ifname 'mon1'
"""

        wireless_id = wireless_file_contents.split("\n")
        for line in wireless_id:
            line_cmd = "echo " + line + " >> /etc/config/wireless"
            # print(line_cmd)
            self.ssh.exec_command(line_cmd)

        self.ssh.exec_command("ifconfig " + self.intf + " down")
        self.ssh.exec_command("uci set wireless.wifi" + self.intf[-1] + ".channel=" + str(self.chan))
        self.ssh.exec_command("uci commit")
        self.ssh.exec_command("wifi")

        while True:
            cmdstr="ifconfig | grep \'^" + self.intf + "\' | awk \'{print $1}\'"
            #print(cmdstr)
            stdin, stdout, stderr = self.ssh.exec_command(cmdstr)
            rsp = stdout.readline().replace("\n", "")
            #print("rsp:", rsp)
            #print("intf:", self.intf)
            if rsp == self.intf:
                break

        print("conf openwrt done!")

    def rshark_conf_ubuntu(self):
        stdin, stdout, stderr = self.ssh.exec_command("whoami")
        rsp = stdout.readline().replace("\n", "")
        if rsp.casefold() != "root".casefold():
            print("ERROR, root user only!")
            # os.kill(os.getpid(), signal.SIGABRT)
            exit_sig(None, None)

        #print("test1")
        self.ssh.exec_command("systemctl stop avahi-daemon.service")
        self.ssh.exec_command("systemctl stop avahi-daemon.socket")
        self.ssh.exec_command("service avahi-daemon stop")
        self.ssh.exec_command("for dev in `ifconfig | grep '^wl' | awk '{print $1}' | tr -d ':'`;do sudo airmon-ng check kill; airmon-ng start $dev;done")
        #print("test2")
        stdin, stdout, stderr = self.ssh.exec_command("ifconfig | grep \'^" + str(self.intf) + "\' | awk \'{print $1}\' | tr -d ':'")

        response = []
        while True:
            rsp = stdout.readline().strip("\n ")
            print(rsp)
            if rsp:
                response.append(rsp)
                break

        print(response)
        if self.intf not in response:
            print("ERROR, Interface {} pull up failed".format(self.intf))
            # os.kill(os.getpid(), signal.SIGABRT)
            exit_sig(None, None)
        else:
            self.ssh.exec_command("iw dev " + self.intf + " set channel " + str(self.chan))

        pass

    def rshark_update_key(self):
        self.ssh.exec_command("rm ~/.ssh/authorized_keys >/dev/null 2>&1")

        if self.ostype != "posix":
            # ssh_copy_id_cmd = "scp " + str(os.path.expanduser("~")) + \
            #                       "\.ssh\id_rsa.pub " + self.ruser +"@" + self.rip + ":/tmp/"

            # print(ssh_copy_id_cmd)

            # child = pexpect.popen_spawn.PopenSpawn(ssh_copy_id_cmd)
            # while True:
            #     index = child.expect(["error", "(yes/no)?", "The authenticity of host", "password:"], timeout=300)
            #     print("Expect:{}".format(index))
            #     if index == 0:
            #         child.kill(0)
            #     elif index == 1 or index == 2:
            #         child.sendline("yes")
            #         print("send yes!")
            #     elif index == 3:
            #         child.sendline(self.rpasswd + "\r")
            #         print("send password", self.rpasswd)
            #         break
            ssh_copy_id = str(os.path.expanduser("~")) + "\.ssh\id_rsa.pub"
            #+ self.ruser +"@" + self.rip + ":/tmp/"
            id_pubs = []
            with open(ssh_copy_id, "r") as id_pub:
                while True:
                    line = id_pub.readline()
                    if not line:
                        break
                    id_pubs.append(line)

                id_pub.close()

            ssh_copy_id_cmd = "echo " + id_pubs[0].strip("\n") + "> /tmp/id_rsa.pub"
            # print(ssh_copy_id_cmd)
            self.ssh.exec_command(ssh_copy_id_cmd)
        else:
            ssh_copy_id_cmd = "ssh-copy-id -f -i " + \
                                  str(os.path.expanduser("~")) + \
                                  "/.ssh/id_rsa.pub " + self.ruser +"@" + self.rip

            # print(ssh_copy_id_cmd)

            child = pexpect.spawn(ssh_copy_id_cmd)

            while True:
                index = child.expect(["error", "yes.*?", "password:", "Number of key(s) added: 1", "Now try logging into the machine"])
                print("Expect:{}".format(index))
                if index == 0:
                    child.kill(0)
                elif index == 1:
                    child.sendline("yes")
                elif index == 2:
                    child.sendline(self.rpasswd)
                elif index == 3 or index == 4:
                    break

        if self.ostype != "posix":
            self.ssh.exec_command("cp /tmp/id_rsa.pub /etc/dropbear/authorized_keys >/dev/null 2>&1")
            self.ssh.exec_command("mv /tmp/id_rsa.pub ~/.ssh/authorized_keys >/dev/null 2>&1")

        #ubuntu will ignore this step
        self.ssh.exec_command("cp ~/.ssh/authorized_keys /etc/dropbear/ >/dev/null 2>&1")
        pass

    def rshark_store_local(self, arg, inputd):
        '''
        store input data to local filesystem, arg means where to write the input data
        Mode	Description
        rb	Opens a file for reading only in binary format. The file pointer is placed at the beginning of the file. This is the default mode.
        rb+	Opens a file for both reading and writing in binary format. The file pointer placed at the beginning of the file.
        wb	Opens a file for writing only in binary format. Overwrites the file if the file exists. If the file does not exist, creates a new file for writing.
        wb+	Opens a file for both writing and reading in binary format. Overwrites the existing file if the file exists. If the file does not exist, creates a new file for reading and writing.
        ab	Opens a file for appending in binary format. The file pointer is at the end of the file if the file exists. That is, the file is in the append mode. If the file does not exist, it creates a new file for writing.
        ab+	Opens a file for both appending and reading in binary format. The file pointer is at the end of the file if the file exists. The file opens in the append mode. If the file does not exist, it creates a new file for reading and writing.
        '''
        print("store local.....", arg)
        if not os.path.exists(arg):
            os.makedirs(arg)
            print("WARNING, store path {} not found!".format(arg))

        dst_file = arg + self.file

        print("Storing {}".format(dst_file))
        try:
            print("Store to file ", dst_file)
            df = open(dst_file, mode='ab')
        except:
            print("ERROR, Fail to open {}".format(dst_file))
            # os.kill(os.getpid(), signal.SIGABRT)
            exit_sig(None, None)
        else:
            while True:
                b = inputd.read(1)
                df.write(b)
                if self.rshark_check_event():
                    break

    def rshark_store_wireshark(self, arg, inputd):
        print("store wireshark.....")
        pargs = ["wireshark", "-k", "-i", "-"]
        ## check_output　is similar with popen except that the stdout　invalid for user in check output 
        self.wait_subprocess.append(subprocess.check_output(pargs, stdin=inputd))

    def rshark_sniffer_dir(self, user, ip, port):
        return
        pargs = ["ssh", user + "@" + ip, "tcpdump", "-i", "mon1", "-U", "-s0", "-w", "-", "not", "port", str(port) ]
        proc_tcpdump = subprocess.Popen(pargs, stdout=subprocess.PIPE)
        pargs = ["wireshark", "-k", "-i", "-"]
        # check_output　is similar with popen except that the stdout　invalid for user in check output 
        proc_wireshark = subprocess.check_output(pargs, stdin=proc_tcpdump.stdout)
        proc_tcpdump.wait(1)
        pass

    def rshark_sniffer_pre(self):
        #key sync
        self.rshark_update_key()
        print("sync key done!")
        #wifi conf
        if not self.conf_handler:
            print("ERROR, Not support configure target device!")
            # os.kill(os.getpid(), signal.SIGABRT)
            exit_sig(None, None)
        else:
            self.conf_handler()

        print("env prepare done!")
        pass

    def rshark_host_pre(self):
        pargs = ["./mount-qa.sh"]
        mount = subprocess.Popen(pargs, None)

    def rshark_sniffer(self):
        #prepare env
        self.rshark_sniffer_pre()

        #start sniffer:https://iotechonline.com/tcpdump-over-ssh-and-wireshark/
        pargs = ["ssh"]
        pargs.append("-p")
        pargs.append(str(self.rport))
        pargs.append("-o")
        pargs.append("StrictHostKeyChecking=no")
        pargs.append("-o")
        pargs.append("UserKnownHostsFile=/dev/null")
        pargs.append(self.ruser + "@" + self.rip)
        pargs.append("tcpdump")
        pargs.append("-i")
        pargs.append(str(self.intf))

        for filter in self.macs:
            pargs.append("ether")
            pargs.append("host")
            pargs.append(filter)

        pargs.append("-U")
        pargs.append("-s0")
        pargs.append("-w")
        pargs.append("-")

        if len(self.macs) <= 0:
            pargs.append("not")
            pargs.append("port")
            pargs.append(str(self.rport))

        #print(pargs)
        print("starting sniffer.....")

        #print(pargs)
        proc_tcpdump = subprocess.Popen(pargs, stdout=subprocess.PIPE, stderr=None)
        self.wait_subprocess.append(proc_tcpdump)

        remote_pid_cmd = self.rtypes[self.rtype]["ps"].format(self.intf)
        #print("remote pid cmd: ", remote_pid_cmd)
        while True:
            stdin, stdout, stderr = self.ssh.exec_command(remote_pid_cmd)
            rsp = stdout.readline().strip("\n ")
            if rsp:
                self.tcpdump_pid = int(rsp)
                break
        
        if self.store_types[self.store_type]["need_path"]:
            #tm_year=2023, tm_mon=11, tm_mday=13, tm_hour=15, tm_min=44, tm_sec=4, tm_wday=0, tm_yday=317, tm_isdst=0
            self.file = str(time.localtime().tm_year) + "_" +\
                    str(time.localtime().tm_mon) + "_" +\
                    str(time.localtime().tm_mday) + "_" +\
                    str(time.localtime().tm_hour) + "_" +\
                    str(time.localtime().tm_hour) + "_" +\
                    str(time.localtime().tm_min) + "_" +\
                    str(time.localtime().tm_sec) + ".pcapng"
        else:
            self.file = False

        # notify the blocked caller task is runing
        self.start_eventq.put(self.file)

        #pargsw = ["wireshark", "-k", "-i", "-"]
        # check_output　is similar with popen except that the stdout　invalid for user in check output 
        #proc_wireshark = subprocess.check_output(pargsw, stdin=proc_tcpdump.stdout)
        self.lstore["cb"](self.lstore["arg"], proc_tcpdump.stdout)
        if self.rshark_check_event():
            pass
        # else:
        #     proc_tcpdump.wait(1)
        self.wait_subprocess.remove(proc_tcpdump)
        proc_tcpdump.kill()
        rshark_remove_running(self.rip, self.intf)

def rshark_conf_init(conf):
    if conf and os.path.exists(conf):
        rshark_from_conf(conf)
        #print(conf_hosts)

if __name__ == "__main__":
    #https://docs.python.org/zh-cn/3/library/argparse.html
    parse = argparse.ArgumentParser(description="Start sniffer with cli, target(openwrt) configure file can be store to openwrt/wireless or use inner static file")
    parse.add_argument("--conf", help="path to the config file", required=False, type=str)

    parse.add_argument("-u", "--user", help="remote sniffer host user name to login", required=False, type=str)
    parse.add_argument("-p", "--password", help="remote sniffer host password to login", required=False, type=str)
    parse.add_argument("-i", "--interface", help="wireless interface of remote sniffer host to use", required=False, type=str)
    parse.add_argument("-c", "--channel", help="wireless channel of remote sniffer host to use", required=False, type=int)
    parse.add_argument("--ip", help="remote sniffer host ip address", required=False, type=str)
    parse.add_argument("--port", help="remote sniffer host ssh port", required=False, default="22", type=str)
    parse.add_argument("--type", help="the type of remote target host, default: openwrt", choices=["openwrt", "ubuntu"], required=False, type=str)
    parse.add_argument("--dst", help="where to store the sniffer log, show start with: local://yourpath OR wireshark://.", default="wireshark://.", required=False, type=str)
    parse.add_argument("--macs", help="mac list with \',\' splited to filter the target", required=False, type=str)
    parse.add_argument("--timeout", help="time to wait for the remote host reponse(10s)", required=False, default=10, type=int)

    args = parse.parse_args()
    print(args)

    #while True:
    #    pass

    lhost = {}

    if not (args.ip and args.conf):
        if os.path.exists("./clients"):
            args.conf = "./clients"
            print("no parameter input but find local conf file clients, use it!")
        else:
            print("ERROR, Miss some parameters!")
            # os.kill(os.getpid(), signal.SIGABRT)
            exit_sig(None, None)

    if args.conf and os.path.exists(args.conf):
        rshark_from_conf(args.conf)
        # print(conf_hosts)

    if not args.ip:
        if not args.conf:
            print("ERROR! remote ip address required and not configure file found!")
        else:
            for item in conf_hosts:
                if item["usetunnel"]:
                    args.ip = item["ip"]
                    break

            if not args.ip:
                print("ERROR! remote ip address required and not configure file found!")
            else:
                print("WARNING! remote ip address required, use first one {}!".format(args.ip))

    if not (args.type and args.user and args.password and args.dst and args.interface and args.channel):
        if args.conf:
            lhost = rshark_lookup_hosts(args.ip, True, True)
        else:
            print("ERROR, Miss some parameters!")
            # os.kill(os.getpid(), signal.SIGABRT)
            exit_sig(None, None)

    args.type = lhost["type"] if not args.type else args.type
    args.user = lhost["user"] if not args.user else args.user
    args.password = lhost["password"] if not args.password else args.password
    args.interface = lhost["interface"][0] if not args.interface else args.interface
    args.channel = lhost["channel"] if not args.channel else args.channel
    args.dst = lhost["dst"] if not args.dst else args.dst

    shark = Rshark(args.type, args.ip, args.port, args.user, args.password, args.dst, args.interface, args.channel, args.macs, args.timeout)
    # record runing device
    cli_running = True
    cli_running_ip = args.ip
    cli_running_intf = args.interface
    if rshark_check_running(args.ip, args.interface):
        sys.exit()

    signal.signal(signal.SIGINT, exit_sig)
    signal.signal(signal.SIGTERM, exit_sig)
    signal.signal(signal.SIGABRT, exit_sig)
    # signal.signSIGABRTal(signal.SIGKILL, exit_sig)

    shark.rshark_sniffer()

    #shark.rshark_sniffer_dir(args.user, args.ip, args.port)
    #rshark_update_key(ip, port, user, passwd, timeout)
    #rshark_sniffer(user, ip, port, None)
    #threading.join(th)
