import logging
import threading
import random
import asrd_socket
import queue
import time
import argparse
import os
import subprocess
import paramiko
import pexpect

#Popen 对象方法
# poll(): 检查进程是否终止，如果终止返回 returncode，否则返回 None。
# wait(timeout): 等待子进程终止。
# communicate(input,timeout): 和子进程交互，发送和读取数据。
# send_signal(singnal): 发送信号到子进程 。
# terminate(): 停止子进程,也就是发送SIGTERM信号到子进程。
# kill(): 杀死子进程。发送 SIGKILL 信号到子进程。

class Rshark():
    def __init__(self, rtype, rip, rport, ruser, rpasswd, lstore, intf, channel, macs, csp, timeout):
        self.rip = rip
        self.rport = rport
        self.ruser = ruser
        self.rpasswd = rpasswd
        self.macs = macs.split(",") if macs else []
        self.timeout = timeout
        self.conf_store_path = csp
        store_types = {
            "local": {"cb": self.rshark_store_local, "arg": None},
            "wireshark": {"cb": self.rshark_store_wireshark, "arg": None}
        }

        store_tmp = lstore.split("://", 1)
        if store_types[store_tmp[0]]:
            if not store_tmp[1] and self.conf_store_path:
                store_tmp[1] = self.conf_store_path
            else:
                raise
            store_types[store_tmp[0]]["arg"] = store_tmp[1]
            self.lstore =store_types[store_tmp[0]]
        else:
            raise

        self.intf = intf
        self.chan = channel
        self.timeout = 5
        rtypes = {
            "openwrt": self.rshark_conf_openwrt,
            "ubuntu":  self.rshark_conf_ubuntu,
        }

        if rtypes[rtype]:
            self.conf_handler = rtypes[rtype]
        else:
            raise

        self.ssh = paramiko.SSHClient()
        key = paramiko.AutoAddPolicy()
        self.ssh.set_missing_host_key_policy(key)

        self.ssh.connect(self.rip, self.rport, self.ruser, self.rpasswd, timeout=self.timeout)

    def __del__(self):
        self.ssh.close()


    def rshark_conf_openwrt(self):
        cmds = "for i in `seq 10`;do i=$((i-1));ifname=$(uci get wireless.@wifi-iface[$i].ifname 2>/dev/null);"
        cmds = cmds + "if [ $? -gt 0 ];then break;fi;if [ \"$ifname\" == \"" + self.intf + "\" ];then echo $i;fi;done"
        stdin, stdout, stderr = self.ssh.exec_command(cmds)
        response = []
        while True:
            rsp = stdout.readline().strip("\n ")
            if rsp:
                response.append(rsp)
                break

        cmds = "uci set wireless.@wifi-iface[" + str(response[0]) + "].mode=monitor"
        #print(cmds)
        self.ssh.exec_command(cmds)
        stdin, stdout, stderr = self.ssh.exec_command("uci get wireless.@wifi-iface[" + str(rsp) + "].device")
        response = []
        while True:
            rsp = stdout.readline().strip("\n ")
            if rsp:
                response.append(rsp)
                break

        self.ssh.exec_command("uci set wireless." + rsp + ".channel=" + str(self.chan))
        self.ssh.exec_command("uci commit")
        self.ssh.exec_command("wifi")

        time.sleep(2)

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
        print("test0")
        stdin, stdout, stderr = self.ssh.exec_command("whoami")
        rsp = stdout.readline().replace("\n", "")
        if rsp.casefold() != "root".casefold():
            raise

        print("test1")
        self.ssh.exec_command("systemctl stop avahi-daemon.service")
        self.ssh.exec_command("systemctl stop avahi-daemon.socket")
        self.ssh.exec_command("service avahi-daemon stop")
        self.ssh.exec_command("for dev in `ifconfig | grep '^wl' | awk '{print $1}' | tr -d ':'`;do sudo airmon-ng check kill; airmon-ng start $dev;done")
        print("test2")
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
            raise
        else:
            self.ssh.exec_command("iw dev " + self.intf + " set channel " + str(self.chan))

        pass

    def rshark_update_key(self):
        child = pexpect.spawn("ssh-copy-id -f -i " + \
                              str(os.path.expanduser("~")) + \
                              "/.ssh/id_rsa.pub " + self.ruser +"@" + self.rip, timeout=self.timeout)
        index = child.expect(["error", "yes", "password", "Number of key(s) added: 1", "Now try logging into the machine"])

        while True:
            #print("Expect:{}".format(index))
            if index == 0:
                child.kill(0)
            elif index == 1:
                child.sendline("yes")
            elif index == 2:
                child.sendline(self.rpasswd)
                break
            elif index == 3 or index == 4:
                break
        #ubuntu will ignore this step
        self.ssh.exec_command("cp ~/.ssh/authorized_keys /etc/dropbear/ >/dev/null 2>&1")
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
        print("store local.....")
        if not os.path.exists(arg):
            raise

        path = arg.strip(".")

        #tm_year=2023, tm_mon=11, tm_mday=13, tm_hour=15, tm_min=44, tm_sec=4, tm_wday=0, tm_yday=317, tm_isdst=0
        dst_file = path + str(time.localtime().tm_year) + "_" +\
                str(time.localtime().tm_mon) + "_" +\
                str(time.localtime().tm_mday) + "_" +\
                str(time.localtime().tm_hour) + "_" +\
                str(time.localtime().tm_hour) + "_" +\
                str(time.localtime().tm_min) + "_" +\
                str(time.localtime().tm_sec) + ".pcapng"
        try:
            df = open(dst_file, mode='ab')
        except:
            raise
        else:
            while True:
                b = inputd.read(1)
                df.write(b)

    def rshark_store_wireshark(self, arg, inputd):
        print("store wireshark.....")
        pargs = ["wireshark", "-k", "-i", "-"]
        ## check_output　is similar with popen except that the stdout　invalid for user in check output 
        proc_wireshark = subprocess.check_output(pargs, stdin=inputd)

    def rshark_sniffer_dir(self, user, ip, port):
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
            raise
        else:
            self.conf_handler()

        print("env prepare done!")
        pass

    def rshark_sniffer(self):
        #prepare env
        self.rshark_sniffer_pre()

        #start sniffer:https://iotechonline.com/tcpdump-over-ssh-and-wireshark/
        pargs = ["ssh"]
        pargs.append("-p")
        pargs.append(str(self.rport))
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

        print(pargs)

        #print(pargs)
        proc_tcpdump = subprocess.Popen(pargs, stdout=subprocess.PIPE, stderr=None)
        #pargsw = ["wireshark", "-k", "-i", "-"]
        # check_output　is similar with popen except that the stdout　invalid for user in check output 
        #proc_wireshark = subprocess.check_output(pargsw, stdin=proc_tcpdump.stdout)
        self.lstore["cb"](self.lstore["arg"], proc_tcpdump.stdout)
        proc_tcpdump.wait(1)


if __name__ == "__main__":
    #https://docs.python.org/zh-cn/3/library/argparse.html
    parse = argparse.ArgumentParser()
    parse.add_argument("-f", "--file", help="use conf file instead cmd line", required=False, type=str)
    args = parse.parse_args()

    if not args.file:
        parse = argparse.ArgumentParser()
        parse.add_argument("-u", "--user", help="remote sniffer host user name to login", required=True, type=str)
        parse.add_argument("-p", "--password", help="remote sniffer host password to login", required=True, type=str)
        parse.add_argument("-i", "--interface", help="wireless interface of remote sniffer host to use", required=True, type=str)
        parse.add_argument("-c", "--channel", help="wireless channel of remote sniffer host to use", required=True, type=int)
        parse.add_argument("--ip", help="remote sniffer host ip address", required=True, type=str)
        parse.add_argument("--port", help="remote sniffer host ssh port", required=False, default="22", type=str)
        parse.add_argument("--type", help="the type of remote target host, default: openwrt", choices=["openwrt", "ubuntu"], required=False, default= "openwrt", type=str)
        parse.add_argument("--dst", help="where to store the sniffer log, show start with: local:// or wireshark://", required=True, type=str)
        parse.add_argument("--macs", help="mac list with \',\' splited to filter the target", required=False, type=str)
        parse.add_argument("--timeout", help="time to wait for the remote host reponse(10s)", required=False, default=10, type=int)
        args = parse.parse_args()

        shark = Rshark(args.type, args.ip, args.port, args.user, args.password, args.dst, args.interface, args.channel, args.macs, args.timeout)
        shark.rshark_sniffer()
    elif os.path.exists(args.file):
        with open(args.file, "r") as conf_file:
            while True:
                line = conf_file.readline()
                if line.startswith("#"):
                    continue
                l = line.split(":")
                args.user = l[0]
                args.ip = l[1]
                args.password = l[3]
                args.
    else:
        raise

    print(args)
    #shark.rshark_sniffer_dir(args.user, args.ip, args.port)
    #rshark_update_key(ip, port, user, passwd, timeout)
    #rshark_sniffer(user, ip, port, None)
    #threading.join(th)
