#!/usr/bin/env python3
# from scapy.all import *
import asyncio
import re
import threading
import time
import sys
import signal
import argparse
import queue
import os
import subprocess


import datetime

from paramiko import SSHClient
from paramiko import AutoAddPolicy

# from pexpect import popen_spawn
# from pyshark.capture.pipe_capture import PipeCapture

import rshark_msgbox
# from tkinter import Tk

#Popen 对象方法
# poll(): 检查进程是否终止，如果终止返回 returncode，否则返回 None。
# wait(timeout): 等待子进程终止。
# communicate(input,timeout): 和子进程交互，发送和读取数据。
# send_signal(singnal): 发送信号到子进程 。
# terminate(): 停止子进程,也就是发送SIGTERM信号到子进程。
# kill(): 杀死子进程。发送 SIGKILL 信号到子进程。

pshark_realtime = True
use_msgbox=False
cli_running=False
cli_running_ip=None
cli_running_intf=None
# rshark_running = os.path.split(os.path.realpath(__file__))[0] + "/rshark.running"
rshark_running = "./rshark.running"
pshark_data_cache = []

os_platform = sys.platform.lower()

if not os_platform.startswith("win"):
    import pexpect

current_path = None
store_parent_path = None
if os_platform == "linux":
    current_path = os.path.split(os.path.realpath(__file__))[0]
    store_parent_path = current_path + "/stores/"
elif os_platform.startswith("win"):
    current_path = ".\\"
    store_parent_path = current_path + "\\stores\\"
else:
    raise

def rshark_get_path_info():
    return {"platform": os_platform, "current_path": current_path, "store_parent_path": store_parent_path}


def rshark_gen_sniffer_openwrt_wireless_conf(target_type):
    if target_type == "QSDK":
        return '''
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
        return  """
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

    if len(new_lines) == 0:
        os.remove(rshark_running)

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
                print("WARNING! host {} with interface {} is runsing!".format(args.ip, args.interface))
                rrf.close()
                return True

        rrf.close()

    with open(rshark_running, "a") as rrf:
        rrf.write(ip + "," + intf)
        rrf.close()
        return False

def exit_sig(signum, frame):
    rshark_remove_running(cli_running_ip, cli_running_intf)
    if len(pshark_data_cache) > 0:
        print("=========pshark cache=========")
        print(pshark_data_cache)
    
    print("Exit with signum {}...".format(signum))
    sys.exit()

def rshark_from_conf(file, hosts_out=None):
    with open(file, "r", encoding="utf-8") as conf_file:
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
            if os_platform.startswith("win"):
                lhost["dst"] = "local://" + current_path + "\stores\\" + lhost["ip"] + "\\" # default store to script path
            else:
                lhost["dst"] = "local://" + current_path + "/stores/" + lhost["ip"] + "/"# default store to script path

            lhost["usetunnel"] = False if l[4] == "0" else True
            lhost["type"] = l[5]
            lhost["channel"] = l[6]
            lhost["interface"] = l[7].strip(",").split(",")
            lhost["interface"][-1] = lhost["interface"][-1].strip("\n")
            lhost["timeout"] = 10

            if type(hosts_out) == list:
                hosts_out.append(lhost)
            else:
                conf_hosts.append(lhost)

    conf_file.close()
    pass

def rshark_lookup_hosts(ip, ifraise, useTunnel):
    for host in conf_hosts:
        if host["ip"] == ip and host["usetunnel"] == useTunnel:
            return host
    
    print("host: " + ip + " Not found!")
    if ifraise:
        raise
    else:
        return None

def rshark_get_hosts(useTunnel):
    rsp = []
    for item in conf_hosts:
        if item["usetunnel"] == useTunnel:
            rsp.append(item)

    return rsp


def is_valid_mac_address(mac_address):
    # 正则表达式匹配标准MAC地址格式
    pattern = re.compile(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$')
    return bool(pattern.match(mac_address))

class Rshark():
    def __init__(self, rtype, rip, rport, ruser, rpasswd, lstore, intf, channel, macs, timeout, pmacs):
        self.parse_win = None
        self.new_eloop = None
        self.pipc = None
        self.data_cache = {}
        self.rip = rip
        self.rport = rport
        self.ruser = ruser
        self.rpasswd = rpasswd
        self.macs = macs.split(",") if macs else []
        self.pmacs = pmacs if pmacs else {}
        self.timeout = timeout
        self.time_start = time.time()
        self.time_prev = self.time_start
        self.total_cap = 0
        self.tcpdump_pid = 0
        self.wait_subprocess = []
        self.exit_event = threading.Event()
        self.start_eventq = queue.Queue()
        self.store_types = {
            "local": {"cb": self.rshark_store_local, "arg": None, "need_path": True},
            "wireshark": {"cb": self.rshark_store_wireshark, "arg": None, "need_path": False},
            "pshark": {"cb": self.rshark_store_pyshark, "arg": None, "need_path": False}
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

        posix_nt_home = os.path.expanduser("~")
        if os_platform.startswith("win"):
            if  not os.path.exists(posix_nt_home + "\.ssh\id_rsa.pub"):
                print("create ssh key1...")
                if not os.path.exists(posix_nt_home + "\.ssh"):
                    os.makedirs(posix_nt_home + "\.ssh")
                ssh_keygen_cmd = "ssh-keygen -t rsa -N \"\" -f %userprofile%/.ssh/id_rsa -q"
                # print(ssh_keygen_cmd)
                subprocess.Popen(ssh_keygen_cmd, stdout=subprocess.PIPE, shell=True)
                # print(posix_nt_home + "\.ssh\id_rsa.pub")
        else:
            if not os.path.exists(posix_nt_home + "/.ssh") or not os.path.exists(posix_nt_home +"/.ssh/id_rsa.pub"):
                # print("create ssh key2...")
                ssh_keygen_cmd = "ssh-keygen -t rsa -N \"\" -f ~/.ssh/id_rsa -q"
                subprocess.Popen(ssh_keygen_cmd, stdout=subprocess.PIPE, shell=True)

        self.ssh = SSHClient()
        key = AutoAddPolicy()
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

        if self.pipc:
            self.pipc.close()
            print("Close pipe capture done!")

        print("Close remote process done!")
        for item in self.wait_subprocess:
            item.kill()
            print("Close {} process done!".format(item))
            pass

        # print("Close shark eventloop done!")
        # self.new_loop.stop()
        # self.new_loop.close()

        self.exit_event.set()
        print("Set exit event done!")
        self.ssh.close()
        print("Close ssh done!")

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

        stdin, stdout, stderr = self.ssh.exec_command("uci show firewall | grep \".name='wan'\" | awk -F= '{print $1}'")
        rsp = stdout.readline().strip("\n ").rstrip("name")
        allow_input = "uci set " + rsp + "input=ACCEPT"
        self.ssh.exec_command(allow_input)
        allow_forward = "uci set " + rsp + "forward=ACCEPT"
        self.ssh.exec_command(allow_forward)
        self.ssh.exec_command("uci commit")
        self.ssh.exec_command("/etc/init.d/firewall restart")
        print("Configure openwrt firewall done!")

        self.ssh.exec_command("uci set system.@system[0].timezone=\'CST-8\'")
        self.ssh.exec_command("uci set system.@system[0].zonename=\'Asia/Shanghai\'")
        self.ssh.exec_command("uci commit")
        self.ssh.exec_command("date -s \"" + str(datetime.datetime.now()).split(".")[0] +"\"")
        print("Configure openwrt time {} done!".format(str(datetime.datetime.now()).split(".")[0]))

        self.ssh.exec_command("sed -i '/dhcp-option=/d' /etc/dnsmasq.conf")
        self.ssh.exec_command("echo 'dhcp-option=3' >> /etc/dnsmasq.conf")
        self.ssh.exec_command("echo 'dhcp-option=6' >> /etc/dnsmasq.conf")
        self.ssh.exec_command("uci set dhcp.@dnsmasq[0].port=0")
        self.ssh.exec_command("uci commit")
        self.ssh.exec_command("/etc/init.d/dnsmasq restart")
        print("Configure openwrt dhcp done!")

        if os_platform.startswith("win"):
            wireless_file = current_path + "\\" + "openwrt\\wireless"
        else:
            wireless_file = current_path + "/" + "openwrt/wireless"

        if os.path.exists(wireless_file):
            self.ssh.exec_command(">/etc/config/wireless")
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
            _, stdout, _ = self.ssh.exec_command(get_target_type)
            target_type = stdout.readline().strip("\n")
            print("Use static wireless({}) config file for OpenWrt!".format(target_type))

        if_idx = (0, 1)
        tinf_cmds = ["uci get wireless.@wifi-iface[{}].mode", "uci get wireless.@wifi-iface[{}].ifname"]

        tinfos = []
        for idx in if_idx:
            tinfo = {}
            for tinf_cmd in tinf_cmds:
                tinf_cmd = tinf_cmd.format(str(idx))
                _, stdout, _ = self.ssh.exec_command(tinf_cmd)
                tinfo[tinf_cmd.split(".")[-1]] = stdout.readline().strip("\n")
            tinfos.append(tinfo)

        # print(tinfos)

        item_fund = False

        for item in tinfos:
            if item["ifname"].lower() == self.intf.lower() and item["mode"].lower() == "monitor":
                item_fund = True
                self.ssh.exec_command("iwconfig " + self.intf + " channel " + str(self.chan))
                print("Set channel without full configure wifi!")
                break

        if not item_fund:
            self.ssh.exec_command(">/etc/config/wireless")
            wireless_file_contents = rshark_gen_sniffer_openwrt_wireless_conf(target_type)
            wireless_id = wireless_file_contents.split("\n")
            for line in wireless_id:
                line_cmd = "echo " + line + " >> /etc/config/wireless"
                # print(line_cmd)
                self.ssh.exec_command(line_cmd)

            print("Sync full openwrt wifi configure done!")

            self.ssh.exec_command("ifconfig " + self.intf + " down")
            self.ssh.exec_command("uci set wireless.wifi" + self.intf[-1] + ".channel=" + str(self.chan))
            self.ssh.exec_command("uci commit")
            self.ssh.exec_command("wifi")

        # make sure target interface is up
        while True:
            cmdstr="ifconfig | grep \'^" + self.intf + "\' | awk \'{print $1}\'"
            #print(cmdstr)
            stdin, stdout, stderr = self.ssh.exec_command(cmdstr)
            rsp = stdout.readline().replace("\n", "")
            #print("rsp:", rsp)
            #print("intf:", self.intf)
            if rsp == self.intf:
                break

        print("Enable new openwrt wifi configure done!")

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
        _, stdout, _ = self.ssh.exec_command("ifconfig | grep \'^" + str(self.intf) + "\' | awk \'{print $1}\' | tr -d ':'")

        response = []
        while True:
            rsp = stdout.readline().strip("\n ")
            # print(rsp)
            if rsp:
                response.append(rsp)
                break

        if self.intf not in response:
            print("ERROR, Interface {} pull up failed".format(self.intf))
            # os.kill(os.getpid(), signal.SIGABRT)
            exit_sig(None, None)
        else:
            self.ssh.exec_command("ifconfig " + self.intf + " down")
            self.ssh.exec_command("ifconfig " + self.intf + " up")
            self.ssh.exec_command("iw dev " + self.intf + " set channel " + str(self.chan))

        pass

    def rshark_update_key(self):
        self.ssh.exec_command("rm ~/.ssh/authorized_keys >/dev/null 2>&1")

        if os_platform.startswith("win"):
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
            ssh_copy_id = '/'.join(ssh_copy_id.split('\\'))
            #+ self.ruser +"@" + self.rip + ":/tmp/"
            id_pubs = []
            with open(r"{}".format(ssh_copy_id), "r") as id_pub:
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

        if os_platform.startswith("win"):
            self.ssh.exec_command("cp /tmp/id_rsa.pub /etc/dropbear/authorized_keys >/dev/null 2>&1")
            self.ssh.exec_command("mv /tmp/id_rsa.pub ~/.ssh/authorized_keys >/dev/null 2>&1")
            # print("move")

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
        wiresharkx = "wireshark"
        result = None
        if os_platform.startswith("win"):
            cmd1 = "dir /s /b \"%ProgramData%\Microsoft\Windows\Start Menu\Programs\\" + wiresharkx +".lnk\""
            rsp = subprocess.Popen(cmd1, stdout=subprocess.PIPE, shell=True)
            result = r"{}".format(rsp.stdout.readline().decode("gbk").strip("\r\n "))
            match = re.search(r'ProgramData', result, re.M|re.I).group(0)
            if not match:
                cmd1 = "dir /s /b \"%APPDATA%\Microsoft\Windows\Start Menu\Programs\\" + wiresharkx + ".lnk\""
                rsp = subprocess.Popen(cmd1, stdout=subprocess.PIPE, shell=True)
                result = r"{}".format(rsp.stdout.readline().decode("gbk").strip("\r\n "))
                match = re.search(r'AppData', result, re.M|re.I).group(0)
                if not match:
                    print("ERROR, Fail to open {}".format(wiresharkx))
                    # os.kill(os.getpid(), signal.SIGABRT)
                    exit_sig(None, None)

            # print(result)
            cmd1 = "powershell -Command \"(New-Object -ComObject WScript.Shell).CreateShortcut('" + r"{}".format(result) + "').TargetPath\""
            # print(cmd1)
            rsp = subprocess.Popen(cmd1, stdout=subprocess.PIPE, shell=True)
            result = r"{}".format(rsp.stdout.readline().decode("gbk").strip("\r\n "))
            # print(result)
            wiresharkx = result

        print("store wireshark@{}...".format(wiresharkx))
        pargs = [wiresharkx, "-k", "-S", "-b", "duration:5", "-i", "-"]
        if os_platform.startswith("win"):
            for win_temp in ["--temp-dir", "."]:
                pargs.append(win_temp)
        ## check_output　is similar with popen except that the stdout　invalid for user in check output 
        # print(pargs)
        self.wait_subprocess.append(subprocess.check_output(pargs, stdin=inputd))
        exit_sig(None, None)

    def rshark_set_pshark_cb(self, sub_args):
        self.store_types["pshark"]["arg"] = sub_args

    def rshark_store_addb(self, tx, rx, rssi, dot11_frame_type, retry):
        found = False
        # print(dot11_frame_type)
        if self.pmacs:
            if tx in self.pmacs:
                if "-" in self.pmacs[tx] or rx in self.pmacs[tx]:
                    found = True
            elif rx in self.pmacs:
                if "-" in self.pmacs[rx] or tx in self.pmacs[rx]:
                    found = True

            if not found:
                return

        print(dot11_frame_type)
        if tx not in self.data_cache:
            item_tx = {}
            item_tx_rx = {}
            item_tx_rx_type = {}
            item_tx_rx_type["rssi"] = int(rssi)
            item_tx_rx_type["rssi_cnt"] = 1 if int(rssi) != 0 else 0
            item_tx_rx_type["cnt"] = 1
            item_tx_rx_type["retry"] = 1 if retry else 0
            item_tx_rx[dot11_frame_type] = item_tx_rx_type
            item_tx[rx] = item_tx_rx
            self.data_cache[tx] = item_tx
            # print(self.data_cache)
            # while True:
            #     pass
        elif tx in self.data_cache and rx not in self.data_cache[tx]:
            item_tx = self.data_cache[tx]
            item_tx_rx = {}
            item_tx_rx_type = {}
            item_tx_rx_type["rssi"] = int(rssi)
            item_tx_rx_type["rssi_cnt"] = 1 if int(rssi) != 0 else 0
            item_tx_rx_type["cnt"] = 1
            item_tx_rx_type["retry"] = 1 if retry else 0
            item_tx_rx[dot11_frame_type] = item_tx_rx_type
            item_tx[rx] = item_tx_rx
            # print(self.data_cache)
            # while True:
            #     pass
        else:
            dmeta = self.data_cache[tx][rx]
            if dot11_frame_type not in dmeta:
                metad = {}
                metad["rssi"] = int(rssi)
                metad["rssi_cnt"] = 1 if int(rssi) != 0 else 0
                metad["cnt"] = 1
                metad["retry"] = 1 if retry else 0
                dmeta[dot11_frame_type] = metad
            else:
                metad = dmeta[dot11_frame_type]
                metad["rssi"] = int(rssi)
                metad["rssi_cnt"] = 1

                if "cnt" in metad:
                    metad["cnt"] = metad["cnt"] + 1 if not retry else metad["cnt"]
                else:
                    metad["cnt"] = 1

                if "retry" in metad:
                    metad["retry"] = metad["retry"] + 1 if retry else metad["retry"]
                else:
                    metad["retry"] = 0
 
        # return self.data_cache

    def rshark_store_pyshark(self, arg, inputd):
        if pshark_realtime:
            self.rshark_store_pyshark_quick_parse(arg, inputd)
        else:
            self.rshark_store_pyshark_full_parse(arg, inputd)

    def rshark_store_pyshark_quick_parse(self, arg, inputd):
        # bssid = re.compile(r'BSSID:([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}', re.I)
        regs = {
            "ta": re.compile(r'[ST]A:(([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2})', re.I),
            "ra": re.compile(r'[RD]A:(([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2})', re.I),
            "rssi": re.compile(r'(\S*)dBm signal', re.I),
            "retry": re.compile(r'Retry', re.I),
        }

        ctrlx = {"Acknowledgment": "ack", "Request-To-Send": "rts", "Clear-To-Send": "cts", "BA": None, "BAR": None, "Power Save-Poll": None, "CF-End": None, "CF-End+CF-Ack": None}
        # ctrlx = {"acknowledgment": "ack", "request-to-send": "rts", "clear-to-send": "cts", "ba": None, "bar": None, "power save-poll": None, "cf-end": None, "cf-end+cf-ack": None}

        rcs = []
        for c in ctrlx:
            rcs.append(c)

        rcs = r"|".join(rcs)

        # pattern = re.compile(r'{}'.format(rcs), re.I)
        pattern = re.compile(r'{}'.format(rcs))

        print(pattern)
        dot11_frame_type = "data_mgmt"

        leggal_start = re.compile(r'\d+us', re.I)

        pre_time = time.time()

        # for line in inputd.readline():
        for line in inputd:
            line = line.decode('utf-8')
            if not leggal_start.match(line):
                # print(line)
                continue

            # self.total_cap = self.total_cap + 1
            # cur_time = time.time()
            # if (round(cur_time - self.time_prev)) > 1:
            #     print("Rate:{:8.2f} pps /w {:8} pkts @ {:8.2f} s".format(round(self.total_cap / (cur_time - self.time_start), 2),
            #                                           self.total_cap, round(cur_time - self.time_start, 2)))
            #     self.time_prev = cur_time


            r = pattern.search(line)

            dot11_frame_type = "data_mgmt"

            if r:
                dot11_frame_type = ctrlx[r.group()]
                # print(dot11_frame_type)
            else:
                dot11_frame_type = "data_mgmt"

            if not dot11_frame_type:
                continue

            ta = regs["ta"].search(line)
            if ta:
                ta = ta.groups()[0].strip()
            else:
                ta = "None"

            ra = regs["ra"].search(line)
            if ra:
                ra = ra.groups()[0].strip()
            else:
                ra = "None"

            # print("ta->{}, ra->{}".format(ta, ra))

            rssi = regs["rssi"].search(line)
            rssi = rssi.groups()[0].strip() if rssi else "0"

            retry = regs["retry"].search(line, re.I)
            if retry:
                retry = retry.group().strip()
                print(retry)
            else:
                retry = False

            # print(dot11_frame_type)

            self.rshark_store_addb(ta, ra, rssi, dot11_frame_type, retry)

            if time.time() - pre_time > 3:
                if arg and type(arg) == dict and callable(arg["cb"]):
                    arg["cb"](self.data_cache)
                pre_time = time.time()

            if self.rshark_check_event():
                print("User cancel shark!")
                break

    def rshark_store_pyshark_full_parse(self, arg, inputd):
        # self.new_eloop = None
        if arg and type(arg) == dict:
            self.new_eloop = arg["eloop"]
        else:
            self.new_eloop = asyncio.get_event_loop()
        # self.new_eloop = asyncio.get_event_loop()

        stop_exit = False
        flag_exit_stop = 0

        while not stop_exit:
            try:
                # self.new_eloop = asyncio.new_event_loop()
                # asyncio.set_event_loop(self.new_eloop)

                # self.pipc = PipeCapture(pipe=inputd, eventloop=self.new_eloop, use_json=True)
                self.pipc = PipeCapture(pipe=inputd, eventloop=self.new_eloop)

                self.pipc.set_debug()
                # print(pipc.get_parameters()) 
                # pkts = self.pipc._packets_from_pipe_sync(pipex=inputd)
                pkts = self.pipc._packets_from_tshark_sync()

                for pkt in pkts:
                    if flag_exit_stop > 0:
                        print("Retry start....5")
                        print(self.new_eloop)
                        print(self.pipc)
                    self.total_cap = self.total_cap + 1
                    cur_time = time.time()
                    if (round(cur_time - self.time_prev)) > 1:
                        print("Rate:{:8.2f} pps /w {:8} pkts @ {:8.2f} s".format(round(self.total_cap / (cur_time - self.time_start), 2),
                                                              self.total_cap, round(cur_time - self.time_start, 2)))
                        self.time_prev = cur_time

                    if not hasattr(pkt, 'wlan') or not hasattr(pkt.wlan, 'fc_type'):
                        print("crash pkt")
                        continue

                    # print(dir(pkt.wlan))
                    # print(pkt.wlan.fc_type, pkt.wlan.fc_subtype)

                    frame_type = "data_mgmt"

                    # print(pkt.wlan.fc_type)

                    fc_type = int(pkt.wlan.fc_type, 16) if pkt.wlan.fc_type.startswith("0x") else int(pkt.wlan.fc_type)

                    if fc_type == 1:
                        if hasattr(pkt.wlan, 'fc_subtype'):
                            type_subtype = int(pkt.wlan.fc_subtype, 16) if pkt.wlan.fc_subtype.startswith("0x") else int(pkt.wlan.fc_subtype)
                        elif hasattr(pkt.wla, 'fc_type_subtype'):
                            type_subtype = int(pkt.wlan.fc_type_subtype, 16) if pkt.wlan.fc_type_subtype.startswith("0x") else int(pkt.wlan.fc_type_subtype)
                        else:
                            continue
                        # print(pkt.wlan.fc_subtype)
                        str_type_subtype = {27: "rts", 28: "cts", 29: "ack", 11: "rts", 12: "cts", 13: "ack"}
                        type_subtype = int(pkt.wlan.fc_type_subtype, 16) if pkt.wlan.fc_type_subtype.startswith("0x") else int(pkt.wlan.fc_type_subtype)
                        # print(type_subtype)
                        if type_subtype in str_type_subtype:
                            frame_type = str_type_subtype[type_subtype]
                        else:
                            continue

                    retry = True if hasattr(pkt.wlan, "flags") and int(pkt.wlan.flags, 16) & 0x8 == 0x8 else False

                    rssi = 0
                    if hasattr(pkt, 'wlan_radio') and hasattr(pkt.wlan_radio, 'signal_dbm'):
                        rssi = pkt.wlan_radio.signal_dbm
                        # print(pkt.wlan_radio.signal_dbm)

                    # frame_subtype = pkt.wlan.fc_subtype
                    if flag_exit_stop > 0:
                        print(pkt)

                    ra = pkt.wlan.ra if hasattr(pkt.wlan, "ra") else "None"
                    ta = pkt.wlan.ta if hasattr(pkt.wlan, "ta") else "None"

                    self.rshark_store_addb(ta, ra, rssi, frame_type, retry)
                    if arg and type(arg) == dict and callable(arg["cb"]):
                        arg["cb"](self.data_cache)

                    if self.rshark_check_event():
                        print("User cancel shark!")
                        self.pipc.close()
                        stop_exit = True
                        break

                time.sleep(1)
                self.pipc.reset()
                self.pipc.clear()
                self.pipc.close()

                # if self.new_eloop.is_running:
                #     self.new_eloop.stop()

                # if not self.new_eloop.is_closed:
                #     self.new_eloop.close()

                flag_exit_stop = flag_exit_stop + 1
                print("Exit and Retry:{}!".format("False" if stop_exit else "True"))
            except OSError:
                self.pipc.reset()
                self.pipc.clear()
                flag_exit_stop = flag_exit_stop + 1
                print("Exception and Retry:{}!".format("False" if stop_exit else "True"))
                time.sleep(1)
                print(flag_exit_stop)

            if self.rshark_check_event():
                print("User cancel shark!")
                self.pipc.close()
                break

    def rshark_sniffer_pre(self):
        #key sync
        self.rshark_update_key()
        print("Sync handshake key done!")
        #wifi conf
        if not self.conf_handler:
            print("ERROR, Not support configure target device!")
            # os.kill(os.getpid(), signal.SIGABRT)
            exit_sig(None, None)
        else:
            self.conf_handler()

        print("Env setup done!")
        pass

    def rshark_host_pre(self):
        pargs = ["./mount-qa.sh"]
        mount = subprocess.Popen(pargs, None)

    def rshark_check_tcpdump(self):
        remote_pid_cmd = self.rtypes[self.rtype]["ps"].format(self.intf)
        while True:
            _, stdout, _ = self.ssh.exec_command(remote_pid_cmd)
            rsp = stdout.readline().strip("\n ")
            if rsp:
                return int(rsp)

    def rshark_get_tcpdump_pid(self):
        return self.tcpdump_pid

    async def rshark_pipe_tcpdump(self, pargs):
        return await asyncio.create_subprocess_exec(*pargs, stdout=subprocess.PIPE, stderr=None)

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

        fmacs = []
        for filter_item in self.pmacs:
            fmacs.append(filter_item)

        for filter_item in self.macs:
            fmacs.append(filter_item)

        fmacs = list(dict.fromkeys(fmacs))
        fmacs = list(filter(is_valid_mac_address, fmacs))
        # print(fmacs)

        for f in fmacs:
            for ix in range(1, 4, 1):
                pargs.append("wlan")
                pargs.append("addr" + str(ix))
                pargs.append(f)
                pargs.append("or")

        if self.pmacs or self.macs:
            pargs.pop(-1)

        pargs.append("-nn")
        # pargs.append("-X")

        if self.lstore["arg"] and type(self.lstore["arg"]) == dict and self.lstore["arg"]["stores"].startswith("pshark://"):
            if pshark_realtime:
                pargs.append("-et")
                pargs.append("-y")
                pargs.append("ieee802_11_radio")
                pargs.append("-l")
            else:
                pargs.append("-e")
                pargs.append("-w")
                pargs.append("-")
        else:
            pargs.append("-vv")
            pargs.append("-w")
            pargs.append("-")

        # this will cause pkt missed such as QOS NULL
        # if len(self.macs) <= 0:
        #     pargs.append("not")
        #     pargs.append("port")
        #     pargs.append(str(self.rport))

        # print(pargs)
        print("Starting sniffer@channel[{}].....".format(self.chan))

        #print(pargs)
        proc_tcpdump = subprocess.Popen(pargs, stdout=subprocess.PIPE, stderr=None)

        # self.new_eloop = asyncio.get_event_loop()
        # self.new_eloop = asyncio.new_event_loop()
        # my_eloop_pipe = self.new_eloop.create_task(self.rshark_pipe_tcpdump(pargs=pargs))
        # proc_tcpdump = self.new_eloop.run_until_complete(my_eloop_pipe)
        # print(dir(proc_tcpdump))
        # print(proc_tcpdump.stdout)
        # print(type(proc_tcpdump.stdout))
        
        self.wait_subprocess.append(proc_tcpdump)

        # remote_pid_cmd = self.rtypes[self.rtype]["ps"].format(self.intf)
        # #print("remote pid cmd: ", remote_pid_cmd)
        # while True:
        #     stdin, stdout, stderr = self.ssh.exec_command(remote_pid_cmd)
        #     rsp = stdout.readline().strip("\n ")
        #     if rsp:
        #         self.tcpdump_pid = int(rsp)
        #         break
        self.tcpdump_pid = self.rshark_check_tcpdump()
        
        if self.store_types[self.store_type]["need_path"]:
            #tm_year=2023, tm_mon=11, tm_mday=13, tm_hour=15, tm_min=44, tm_sec=4, tm_wday=0, tm_yday=317, tm_isdst=0
            self.file = str(time.localtime().tm_year) + "_" +\
                    str(time.localtime().tm_mon) + "_" +\
                    str(time.localtime().tm_mday) + "_" +\
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
        proc_tcpdump.communicate()
        proc_tcpdump.wait(5)
        rshark_remove_running(self.rip, self.intf)

def rshark_conf_init(conf):
    if conf and os.path.exists(conf):
        rshark_from_conf(conf, None)
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
    parse.add_argument("--pmacs", help="mac list with \',\' splited to parse the target", required=False, type=str)
    parse.add_argument("--timeout", help="time to wait for the remote host reponse(10s)", required=False, default=10, type=int)

    args = parse.parse_args()
    # print(args)

    lhost = {}

    # if we support msgbox now, so comment this
    if not use_msgbox and not (args.ip and args.conf):
        if os.path.exists("./clients"):
            args.conf = "./clients"
            print("no parameter input but find local conf file clients, use it!")
        else:
            print("ERROR, Miss some parameters!")
            # os.kill(os.getpid(), signal.SIGABRT)
            exit_sig(None, None)

    if args.conf and os.path.exists(args.conf):
        rshark_from_conf(args.conf, None)
        # print(conf_hosts)


    if not args.ip:
        if not args.conf:
            if not use_msgbox:
                print("ERROR! remote ip address required and not configure file found!")
            else:
                hosts_out = []
                rshark_from_conf("./clients", hosts_out=hosts_out)
                # print(hosts_out)
                # msgbox_info = rshark_msgbox_info() 
                rinfos = []
                for item_host in hosts_out:
                    rinfo = {}
                    rinfo["user"] = item_host["user"]
                    rinfo["password"] = item_host["password"]
                    rinfo["port"] = item_host["port"]
                    rinfo["ip"] = item_host["ip"]
                    rinfo["interface"] = item_host["interface"]
                    rinfo["type"] = item_host["type"]
                    rinfo["channel"] = list(range(1, 14))
                    rinfo["stores"] = ["wireshark://.", "local://.", "pshark://."]
                    rinfos.append(rinfo)
                #rinfo = {"user": "root", "password": "12345678", "ip": "192.168.8.1", "port": "22", "channel": list(range(1, 13)), "interface": "mon1",
                #         "type": ["openwrt", "ubuntu"], "stores":["wireshark://.", "local://.", "pshark://."]}

                #rinfo = {"user": "root", "password": "12345678", "ip": "10.17.7.28", "port": "22", "channel": list(range(1, 13)), "interface": "wlan0mon",
                #         "type": ["openwrt", "ubuntu"], "stores":["wireshark://.", "local://.", "pshark://."]}
                #print(rinfos)
                msgbox_info = rshark_msgbox.rshark_rmsgbox(rinfos)
                args.type = msgbox_info["type"]
                args.user = msgbox_info["user"]
                args.password = msgbox_info["password"]
                args.ip = msgbox_info["ip"]
                args.interface = msgbox_info["interface"]
                args.channel = msgbox_info["channel"]
                args.dst = msgbox_info["stores"]
                args.pmacs = msgbox_info["pmacs"]
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
        lhost = rshark_lookup_hosts(args.ip, False, True)
        if not lhost:
            print("ERROR, Miss some parameters!")
            # os.kill(os.getpid(), signal.SIGABRT)
            exit_sig(None, None)

    args.type = lhost["type"] if not args.type else args.type
    args.user = lhost["user"] if not args.user else args.user
    args.password = lhost["password"] if not args.password else args.password
    args.interface = lhost["interface"][0] if not args.interface else args.interface
    args.channel = lhost["channel"] if not args.channel else args.channel
    args.dst = lhost["dst"] if not args.dst else args.dst

    shark = Rshark(args.type, args.ip, args.port, args.user, args.password, args.dst, args.interface, args.channel, args.macs, args.timeout, args.pmacs)
    # record runing device
    # cli_running = True
    # cli_running_ip = args.ip
    # cli_running_intf = args.interface
    # if rshark_check_running(args.ip, args.interface):
        # sys.exit()

    signal.signal(signal.SIGINT, exit_sig)
    signal.signal(signal.SIGTERM, exit_sig)
    signal.signal(signal.SIGABRT, exit_sig)
    # signal.signSIGABRTal(signal.SIGKILL, exit_sig)

    shark.rshark_sniffer()

    #shark.rshark_sniffer_dir(args.user, args.ip, args.port)
    #rshark_update_key(ip, port, user, passwd, timeout)
    #rshark_sniffer(user, ip, port, None)
    #threading.join(th)
