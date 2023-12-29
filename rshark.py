#!/usr/bin/env python3
# from scapy.all import *
import asyncio
import re
import threading
import time
import sys
import copy
import queue
import os
import subprocess

from datetime import datetime

from paramiko import SSHClient
from paramiko import AutoAddPolicy

from log import *

display_realtime = True
pshark_realtime = True
use_msgbox=False
cli_running=False
cli_running_ip=None
cli_running_intf=None
# rshark_running = os.path.split(os.path.realpath(__file__))[0] + "/rshark.running"
rshark_running = "./rshark.running"

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
                log(INFO, "Remove running sniffer device{}@{}".format(ip, intf))
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
                log(WARNING, "Host {} with interface {} is runsing!".format(args.ip, args.interface))
                rrf.close()
                return True

        rrf.close()

    with open(rshark_running, "a") as rrf:
        rrf.write(ip + "," + intf)
        rrf.close()
        return False

def exit_sig(signum, frame):
    rshark_remove_running(cli_running_ip, cli_running_intf)

    log(WARNING, "Exit with signum {}...".format(signum))

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
                lhost["dst"] = "local://" + current_path + r"\stores\\" + lhost["ip"] + "\\" # default store to script path
            else:
                lhost["dst"] = "local://" + current_path + "/stores/" + lhost["ip"] + "/"# default store to script path

            lhost["usetunnel"] = False if l[4] == "0" else True
            lhost["type"] = l[5]
            lhost["channel"] = l[6]
            lhost["interface"] = l[7].strip(",").split(",")
            lhost["interface"][-1] = lhost["interface"][-1].strip("\n")
            lhost["timeout"] = 10
            lhost["upmacs"] = l[9].strip("\n").strip(",").split(",") if len(l) >= 10 else [] #配置文件中的过滤MAC地址
            # print("xxxxxxx", l, lhost["upmacs"])

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

    log(ERROR, "Host: " + ip + " Not found!")
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
        self.data_handle_queue = queue.Queue(maxsize=50)
        self.rate_db = {}
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
        self.input_running = False
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
                log(ERROR, "Local store method need path")
                # os.kill(os.getpid(), signal.SIGABRT)
                exit_sig(None, None)

            self.store_types[store_tmp[0]]["arg"] = store_tmp[1]
            self.lstore = self.store_types[store_tmp[0]]
        else:
            log(ERROR, "Store type {} not support!".format(store_tmp[0]))
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
            log(ERROR, "Target device type {} not support!".format(rtype))
            # os.kill(os.getpid(), signal.SIGABRT)
            exit_sig(None, None)

        posix_nt_home = os.path.expanduser("~")
        if os_platform.startswith("win"):
            if  not os.path.exists(posix_nt_home + r"\.ssh\id_rsa.pub"):
                log(INFO, "Create ssh key1...")
                if not os.path.exists(posix_nt_home + r"\.ssh"):
                    os.makedirs(posix_nt_home + r"\.ssh")
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
        self.rate_db = {}
        if self.tcpdump_pid > 0:
            log(INFO, r"Close pid: {}".format(self.tcpdump_pid))
            kill_str = "kill -9 " + str(self.tcpdump_pid)
            try:
                self.ssh.exec_command(kill_str)
            except:
                pass

        if self.pipc:
            try:
                self.pipc.close()
            except:
                pass
            log(INFO, "Close pipe capture done!")

        log(INFO, "Close remote process done!")
        for item in self.wait_subprocess:
            try:
                item.kill()
            except:
                pass
            finally:
                log(INFO, "Close {} process done!".format(item.pid))

        try:
            self.exit_event.set()
            log(INFO, "Set exit event done!")
        except:
            pass
        try:
            self.ssh.close()
            log(INFO, "Close ssh done!")
        except:
            pass

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
        log(INFO, "Configure openwrt firewall done!")

        self.ssh.exec_command("uci set system.@system[0].timezone=\'CST-8\'")
        self.ssh.exec_command("uci set system.@system[0].zonename=\'Asia/Shanghai\'")
        self.ssh.exec_command("uci commit")
        self.ssh.exec_command("date -s \"" + str(datetime.now()).split(".")[0] +"\"")
        log(INFO, "Configure openwrt time {} done!".format(str(datetime.now()).split(".")[0]))

        self.ssh.exec_command("sed -i '/dhcp-option=/d' /etc/dnsmasq.conf")
        self.ssh.exec_command("echo 'dhcp-option=3' >> /etc/dnsmasq.conf")
        self.ssh.exec_command("echo 'dhcp-option=6' >> /etc/dnsmasq.conf")
        self.ssh.exec_command("uci set dhcp.@dnsmasq[0].port=0")
        self.ssh.exec_command("uci commit")
        self.ssh.exec_command("/etc/init.d/dnsmasq restart")
        log(INFO, "Configure openwrt dhcp done!")

        if os_platform.startswith("win"):
            wireless_file = current_path + "\\" + "openwrt\\wireless"
        else:
            wireless_file = current_path + "/" + "openwrt/wireless"

        if os.path.exists(wireless_file):
            self.ssh.exec_command(">/etc/config/wireless")
            log(INFO, "Read wireless config file from {}".format(wireless_file))
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
            log(INFO, "Use static wireless({}) config file for OpenWrt!".format(target_type))

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
                log(INFO, "Set channel without full configure wifi!")
                break

        if not item_fund:
            self.ssh.exec_command(">/etc/config/wireless")
            wireless_file_contents = rshark_gen_sniffer_openwrt_wireless_conf(target_type)
            wireless_id = wireless_file_contents.split("\n")
            for line in wireless_id:
                line_cmd = "echo " + line + " >> /etc/config/wireless"
                # print(line_cmd)
                self.ssh.exec_command(line_cmd)

            log(INFO, "Sync full openwrt wifi configure done!")

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

        log(INFO, "Enable new openwrt wifi configure done!")

    def rshark_conf_ubuntu(self):
        _, stdout, _= self.ssh.exec_command("whoami")
        rsp = stdout.readline().replace("\n", "")
        if rsp.casefold() != "root".casefold():
            log(ERROR, "root user only!")
            # os.kill(os.getpid(), signal.SIGABRT)
            exit_sig(None, None)

        # print("test1")
        self.ssh.exec_command("systemctl stop avahi-daemon.service")
        self.ssh.exec_command("systemctl stop avahi-daemon.socket")
        self.ssh.exec_command("service avahi-daemon stop")
        self.ssh.exec_command("for dev in `ifconfig | grep '^wl' | awk '{print $1}' | tr -d ':'`;do sudo airmon-ng check kill; airmon-ng start $dev;done")
        # print("test2")
        _, stdout, _ = self.ssh.exec_command("ifconfig | grep \'^" + str(self.intf) + "\' | awk \'{print $1}\' | tr -d ':'")

        response = []
        while True:
            rsp = stdout.readline().strip("\n ")
            # print(rsp)
            if rsp:
                response.append(rsp)
                break
        # print("test2")

        if self.intf not in response:
            log(ERROR, "Interface {} pull up failed".format(self.intf))
            # os.kill(os.getpid(), signal.SIGABRT)
            exit_sig(None, None)
        else:
            self.ssh.exec_command("ifconfig " + self.intf + " down")
            self.ssh.exec_command("ifconfig " + self.intf + " up")
            self.ssh.exec_command("iw dev " + self.intf + " set channel " + str(self.chan))

        # print("test3")
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
            ssh_copy_id = str(os.path.expanduser("~")) + r"\.ssh\id_rsa.pub"
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
                log(DEBUG, "Expect:{}".format(index))
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
        log(INFO, r"Store local dir {}".format(arg))
        if not os.path.exists(arg):
            os.makedirs(arg)
            log(WARNING, "Store path {} not found!".format(arg))

        dst_file = arg + self.file

        try:
            log(INFO, r"Store to file {}".format(dst_file))
            df = open(dst_file, mode='ab')
        except:
            log(ERROR, "Fail to open {}".format(dst_file))
            # os.kill(os.getpid(), signal.SIGABRT)
            exit_sig(None, None)
        else:
            while True:
                b = inputd.read(1)
                self.input_running = True
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
                    log(ERROR, "Fail to open {}".format(wiresharkx))
                    # os.kill(os.getpid(), signal.SIGABRT)
                    exit_sig(None, None)

            # print(result)
            cmd1 = "powershell -Command \"(New-Object -ComObject WScript.Shell).CreateShortcut('" + r"{}".format(result) + "').TargetPath\""
            # print(cmd1)
            rsp = subprocess.Popen(cmd1, stdout=subprocess.PIPE, shell=True)
            result = r"{}".format(rsp.stdout.readline().decode("gbk").strip("\r\n "))
            # print(result)
            wiresharkx = result

        log(INFO, "Store wireshark@{}...".format(wiresharkx))
        pargs = [wiresharkx, "-k", "-S", "-b", "filesize:4096000", "-i", "-"]
        # if os_platform.startswith("win"):
        #     for win_temp in ["--temp-dir", "."]:
        #         pargs.append(win_temp)
        pargs.append("-w")
        pargs.append("./Capture.pcapng")
        ## check_output　is similar with popen except that the stdout　invalid for user in check output 
        # print(pargs)
        self.input_running = True
        # shark_pid = subprocess.check_output(pargs, stdin=inputd)
        shark_pid = subprocess.Popen(pargs, stdin=inputd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
        # shark_pid = subprocess.Popen(pargs, stdin=inputd, stdout=subprocess.PIPE, stderr=None, close_fds=True)
        self.wait_subprocess.append(shark_pid)
        for lineb in shark_pid.stderr:
            line = lineb.decode("utf-8")
            if re.search(r"\[Capture MESSAGE\] -- File:", line):
                log(INFO, "Temp " + line.split("--")[1].strip("\r\n "))
        shark_pid.wait()

    def rshark_set_pshark_cb(self, sub_args):
        self.store_types["pshark"]["arg"] = sub_args

    def rshark_filter_pmacs(self, ta, ra):
        found = False
        if self.pmacs:
            if ta in self.pmacs:
                if "-" in self.pmacs[ta] or ra in self.pmacs[ta]:
                    found = True
            elif ra in self.pmacs:
                if "-" in self.pmacs[ra] or ta in self.pmacs[ra]:
                    found = True

            if not found:
                return False

        return True

    def rshark_store_addb(self, ta, ra, rssi, dot11_frame_type, retry):
        # print(dot11_frame_type)
        item_tx = {}
        item_tx_rx = {}
        item_tx_rx_type = {}
        # print(dot11_frame_type)
        if ta not in self.data_cache:
            item_tx_rx_type["rssi"] = int(rssi)
            item_tx_rx_type["rssi_cnt"] = 1 if int(rssi) != 0 else 0
            item_tx_rx_type["cnt"] = 1
            item_tx_rx_type["retry"] = 1 if retry else 0
            item_tx_rx[dot11_frame_type] = item_tx_rx_type
            item_tx[ra] = item_tx_rx
            self.data_cache[ta] = item_tx
            # print(ta, "->", self.data_cache[ta])
            # print(self.data_cache)
            # while True:
            #     pass
        elif ta in self.data_cache and ra not in self.data_cache[ta]:
            item_tx_rx_type["rssi"] = int(rssi)
            item_tx_rx_type["rssi_cnt"] = 1 if int(rssi) != 0 else 0
            item_tx_rx_type["cnt"] = 1
            item_tx_rx_type["retry"] = 1 if retry else 0
            item_tx_rx[dot11_frame_type] = item_tx_rx_type
            self.data_cache[ta][ra] = item_tx_rx
            # print(ta, "->", self.data_cache[ta])
            # print(self.data_cache)
            # while True:
            #     pass
        else:
            item_tx_rx = self.data_cache[ta][ra]
            if dot11_frame_type not in item_tx_rx:
                # print(ta, "->", ra, "->", dot11_frame_type, dmeta)
                item_tx_rx_type["rssi"] = int(rssi)
                item_tx_rx_type["rssi_cnt"] = 1 if int(rssi) != 0 else 0
                item_tx_rx_type["cnt"] = 1
                item_tx_rx_type["retry"] = 1 if retry else 0
                item_tx_rx[dot11_frame_type] = item_tx_rx_type
            else:
                metad = item_tx_rx[dot11_frame_type]
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
            # print(self.data_cache[ta])

        # return self.data_cache

    def get_rate_from_line(self, line):
        rbps = [
            # rmcs
            re.compile(r'\s(\S+\s\Sb/s).*(MCS\s\S)'),
            re.compile(r'(.*)\s(MCS\s\S)'),
            # rbps
            re.compile(r'(tsft).*\s(\S+\s\Sb/s)')
        ]

        for r in rbps:
            rsp = r.search(line)
            if rsp:
                return rsp.group(2).replace("Mb/s", "").replace(" ", "")

        return None

    def rshark_rate_db_addr_check(self, tx, rx):
        illegal = ["none", "ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"]
        if tx.lower() in illegal:
            return False

        if rx.lower() in illegal:
            return False

        return True

    def rshark_add_rate_db(self, tx, rx, retry, line):
        """
        {rate1: {mac1->mac2: {cnts: 123, retry: 12}}, rate2: {mac1->mac3: {cnts:123, retry: 23}}}
        """

        if not self.rshark_rate_db_addr_check(tx, rx):
            return

        mac_indx = tx +"->" + rx
        rate_value = self.get_rate_from_line(line)

        if not rate_value:
            # print("Unkown rate: ", line)
            return

        macs_value = {}
        if not rate_value in self.rate_db:
            macs_value[mac_indx] = {}
            macs_value[mac_indx]["cnts"] = 1 if not retry else 0
            macs_value[mac_indx]["retry"] = 1 if retry else 0
            self.rate_db[rate_value] = macs_value
        else:
            macs_value = self.rate_db[rate_value]
            macs_macv = {}
            if mac_indx in macs_value:
                macs_macv = macs_value[mac_indx]
            else:
                macs_macv = {"cnts":0, "retry": 0}

            if retry:
                macs_macv["retry"] += 1
            else:
                macs_macv["cnts"] += 1

            self.rate_db[rate_value][mac_indx] = macs_macv

            # print(self.rate_db)

    def rshark_store_pyshark(self, arg, inputd):
        if pshark_realtime:
            self.rshark_store_pyshark_quick_parse(arg, inputd)
        else:
            # self.rshark_store_pyshark_full_parse(arg, inputd)
            raise

    def rshark_parse_lines(self, line, rclass_reg_list, rclass_list, rclass_names, regs):
        rets = {}

        # print(rclass_ctrl_reg)
        rci = -1
        # print(rclass_reg_list)
        # print(rclass_list)
        for rc in rclass_reg_list:
            # rcc = re.compile(r'\s('+rc+')', re.I)
            rcc = re.compile(r'\s('+rc+')')
            rcs = rcc.search(line)
            if not rcs:
                continue

            item = rcs.groups()[0]
            # print(rclass_list, item, rc)
            rci = rclass_list.index(item)
            break

        # print(rclass_list[rci] if rci >= 0 else "None")
        if rci >= 0 and rclass_list[rci] in regs:
            rets["dot11_frame_type"] = rclass_names[rclass_list[rci]]
            # print(rclass_list[rci], rclass_names[rclass_list[rci]])

            rets["ra"] = "None"
            rets["ta"] = "None"
            srssi = regs["rssi"].search(line)
            rets["rssi"] = srssi.groups()[0] if srssi else 0
            sretry = regs["Retry"].search(line)
            rets["retry"] = True if sretry else False
            regt = regs[rclass_list[rci]]
            # print(regt)

            for c in regt:
                for r in regt[c]:
                    ci = r.search(line)
                    if ci:
                        g = ci.groups()
                        # print(" ", c, "->", g[1], end="")
                        rets[c] = g[1]
                        break

            return rets

    def rshark_store_pyshark_quick_parse(self, arg, inputd):
        if arg and type(arg) == dict and callable(arg["cb"]):
            # self.rshark_handle_data_coroutine = self.rshark_handle_data(arg)
            # self.rshark_handle_data_eloop = asyncio.new_event_loop()
            # self.rshark_handle_data_task = self.rshark_handle_data_eloop.create_task(self.rshark_handle_data_coroutine)
            # self.rshark_handle_data_eloop.run_until_complete(self.rshark_handle_data_task)
            threading.Thread(target=self.rshark_handle_data, kwargs=arg).start()

        leggal_start = re.compile(r'\d+us', re.I)

        # please refer: tcpdump source code @ print-802_11.c
        # rclass = ["data", "mgmt"]
        rclass_list = []
        rclass_reg_list = []
        rclass_ctrl_name = {"Acknowledgment": "ack", "Request-To-Send": "rts", "Clear-To-Send": "cts", "BA": None, "BAR": None, "Power Save-Poll": None, "CF-End": None, "CF-End+CF-Ack": None}
        # Unhandled Management|Assoc Request|Assoc Response|Probe Request|Probe Response|Beacon|ATIM|Disassociation|Authentication|DeAuthentication|Action
        rclass_mgmt_name = {"Unhandled Management": "mgmt",
                            "Assoc Request": "mgmt",
                            "Assoc Response": "mgmt",
                            "Probe Request": "mgmt",
                            "Probe Response": "mgmt",
                            "Beacon": "mgmt",
                            "ATIM": "mgmt",
                            "Disassociation": "mgmt",
                            "Authentication": "mgmt",
                            "DeAuthentication": "mgmt",
                            "Action": "mgmt"}
        rclass_data_name = {"Data": "data"}
        # rclass_ctrl_list = ["Acknowledgment", "Request-To-Send", "Clear-To-Send", "BA", "BAR", "Power Save-Poll", "CF-End", "CF-End+CF-Ack"]
        rclass_ctrl_list = list(rclass_ctrl_name.keys())
        rclass_list = rclass_ctrl_list
        rclass_ctrl_reg = r"|".join(rclass_ctrl_list)
        rclass_reg_list.append(rclass_ctrl_reg)
        # rclass_reg_list = rclass_ctrl_list

        rclass_mgmt_list = list(rclass_mgmt_name.keys())
        rclass_list = rclass_list + rclass_mgmt_list
        rclass_mgmt_reg = r"|".join(rclass_mgmt_list)
        rclass_reg_list.append(rclass_mgmt_reg)

        rclass_data_list = list(rclass_data_name.keys())
        rclass_list = rclass_list + rclass_data_list
        rclass_data_reg = r"|".join(rclass_data_list)
        rclass_reg_list.append(rclass_data_reg)
        # rclass_reg_list = rclass_reg_list + rclass_data_list

        # print(rclass)

        rclass_names = {**rclass_data_name, **rclass_mgmt_name, **rclass_ctrl_name}
        # print(rclass_names)

        regs = {}
        regsd = {
            "ra": [
                re.compile(r'(DA):(([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}) (BSSID|SA).*Data', re.I),
                re.compile(r'(BSSID):(([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}) SA.*Data', re.I),
                re.compile(r'(RA):(([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}) TA.*Data', re.I),
            ],
            "ta": [
                re.compile(r'(DA|BSSID):.* SA:(([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}) .*(([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}) Data', re.I),
                re.compile(r'(DA):.* BSSID:(([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}) .*(([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}) Data', re.I),
                re.compile(r'(RA):.* TA:(([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}) .*(([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}) Data', re.I),
            ]}

        regs["Data"] = regsd

        # RA:78:60:5b:b9:35:fd Acknowledgment
        regs["Acknowledgment"] = {
            "ra":[
                # re.compile(r'(RA):(([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}) Acknowledgment', re.I),
                re.compile(r'(RA):(([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}) Acknowledgment'),
            ],
            "ta":[

            ]
        }

        # RA:48:f1:7f:a9:a1:55 TA:4c:77:66:c5:c2:c1 Request-To-Send
        regs["Request-To-Send"] = {
            "ra":[
                # re.compile(r'(RA):(([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}) TA.* Request-To-Send', re.I),
                re.compile(r'(RA):(([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}) TA.* Request-To-Send'),
            ],
            "ta":[
                # re.compile(r'(RA):.* TA:(([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}) Request-To-Send', re.I),
                re.compile(r'(RA):.* TA:(([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}) Request-To-Send'),
            ]
        }

        # RA:78:60:5b:b9:35:fd Clear-To-Send
        regs["Clear-To-Send"] = {
            "ra":[
                # re.compile(r'(RA):(([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}) TA.* Clear-To-Send', re.I),
                re.compile(r'(RA):(([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}) Clear-To-Send'),
            ],
            "ta":[
            ]
        }

        # BSSID:92:23:b4:1c:8a:a3 DA:02:25:77:74:8e:75 SA:92:23:b4:1c:8a:a3 Probe Response
        # BSSID:78:60:5b:b9:35:fd DA:78:60:5b:b9:35:fd SA:c2:95:73:97:f4:66 Authentication
        # BSSID:78:60:5b:b9:35:fd DA:c2:95:73:97:f4:66 SA:78:60:5b:b9:35:fd Assoc Response
        regs["mgmt"] = {
            "ra":[
                re.compile(r'(DA):(([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}).*('+rclass_mgmt_reg+')'),
            ],
            "ta":[
                re.compile(r'(SA):(([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}) ('+rclass_mgmt_reg+')'),
            ]
        }

        for mitem in rclass_mgmt_name:
            regs[mitem] = regs["mgmt"]

        regs["rssi"] = re.compile(r'(\S*)dBm signal', re.I)
        regs["Retry"] = re.compile(r'\sRetry\s', re.I)

        pre_time = time.time()

        # for line in inputd.readline():
        for line in inputd:
            try:
                line = line.decode('utf-8')
            except Exception:
                continue

            if not leggal_start.match(line):
                # print(line)
                continue

            self.input_running = True

            prev_len = len(self.data_cache)
            # def rshark_parse_lines(self, line, rclass_reg_list, rclass_list, rclass_names, regs):
            retes = self.rshark_parse_lines(line, rclass_reg_list=rclass_reg_list, rclass_list=rclass_list, rclass_names=rclass_names, regs=regs)
            if not retes:
                continue

            if not self.rshark_filter_pmacs(retes["ta"],retes["ra"]):
                continue

            if retes["dot11_frame_type"] == "data":
                self.total_cap = self.total_cap + 1
                self.rshark_sniffer_rate()

            # def rshark_store_addb(self, ta, ra, rssi, dot11_frame_type, retry):
            self.rshark_store_addb(retes["ta"], retes["ra"], retes["rssi"], retes["dot11_frame_type"], retes["retry"])

            self.rshark_add_rate_db(retes["ta"], retes["ra"], retes["retry"], line)

            if time.time() - pre_time > 3:
                if display_realtime:
                    if arg and type(arg) == dict and callable(arg["cb"]):
                        # arg["cb"](self.data_cache, self.rate_db)
                        arg_handle = {}
                        arg_handle["data_cache"] = copy.deepcopy(self.data_cache)
                        arg_handle["rate_db"] = copy.deepcopy(self.rate_db)
                        try:
                            self.data_handle_queue.put(arg_handle)
                        except queue.Full:
                            self.data_handle_queue.get()
                            log(WARNING, "Plot overflow ~ drop the oldest data!")
                            self.data_handle_queue.put(arg_handle)
                    else:
                        with open("presults.txt", "+w") as f:
                            for mac1 in self.data_cache:
                                for mac2 in self.data_cache[mac1]:
                                    f.write(mac1+"->"+mac2+" " + str(self.data_cache[mac1][mac2]))

                            f.close()

                pre_time = time.time()

            if self.rshark_check_event():
                print("User cancel shark!")
                break

            if len(self.data_cache) < prev_len:
                raise

    def rshark_sniffer_rate(self):
        cur_time = time.time()
        if (round(cur_time - self.time_prev)) > 1:
            log(INFO, r"Data Frame Rate:{:8.2f} pps /w {:8} pkts @ {:8.2f} s".format(round(self.total_cap / (cur_time - self.time_start), 2),
                                                  self.total_cap, round(cur_time - self.time_start, 2)))
            self.time_prev = cur_time

    def rshark_handle_data(self, **arg):
        while True:
            data_handle = {}
            try:
                data_handle = self.data_handle_queue.get(block=True, timeout=0.2)
            except queue.Empty:
                pass

            if self.rshark_check_event():
                break

            if data_handle:
                arg["cb"](data_handle["data_cache"], data_handle["rate_db"])

    def rshark_sniffer_pre(self):
        #key sync
        self.rshark_update_key()
        log(INFO, "Sync handshake key done!")
        #wifi conf
        if not self.conf_handler:
            log(ERROR, "Not support configure target device!")
            # os.kill(os.getpid(), signal.SIGABRT)
            exit_sig(None, None)
        else:
            self.conf_handler()

        log(INFO, "Env setup done!")
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

        pargs.append("-nnvv")
        # pargs.append("-X")
        pargs.append("-s")
        pargs.append("2048")

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
            pargs.append("-w")
            pargs.append("-")

        # this will cause pkt missed such as QOS NULL
        # if len(self.macs) <= 0:
        #     pargs.append("not")
        #     pargs.append("port")
        #     pargs.append(str(self.rport))

        log(INFO, "Starting sniffer@channel[{}].....".format(self.chan))

        try:
            proc_tcpdump = subprocess.Popen(pargs, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

            # self.new_eloop = asyncio.get_event_loop()
            # self.new_eloop = asyncio.new_event_loop()
            # my_eloop_pipe = self.new_eloop.create_task(self.rshark_pipe_tcpdump(pargs=pargs))
            # proc_tcpdump = self.new_eloop.run_until_complete(my_eloop_pipe)
            # print(dir(proc_tcpdump))
            # print(proc_tcpdump.stdout)
            # print(type(proc_tcpdump.stdout))

            self.wait_subprocess.append(proc_tcpdump)

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

            self.lstore["cb"](self.lstore["arg"], proc_tcpdump.stdout)
            if self.rshark_check_event():
                pass
            # else:
            #     proc_tcpdump.wait(1)
        except KeyboardInterrupt:
            exit_sig(None, None)
        else:
            self.wait_subprocess.remove(proc_tcpdump)
            proc_tcpdump.kill()
            proc_tcpdump.communicate()
            proc_tcpdump.wait(5)
            rshark_remove_running(self.rip, self.intf)

def rshark_conf_init(conf):
    if conf and os.path.exists(conf):
        rshark_from_conf(conf, None)