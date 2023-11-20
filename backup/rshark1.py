import logging
import threading
import random
import asrd_socket
import queue
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

def rshark_update_key(ip, port, user, passwd, timeout):
    ssh = paramiko.SSHClient()
    key = paramiko.AutoAddPolicy()
    ssh.set_missing_host_key_policy(key)
    ssh.connect(ip, port, user, passwd, timeout=timeout)
    child = pexpect.spawn("ssh-copy-id -f -i " + str(os.path.expanduser("~")) + "/.ssh/id_rsa.pub root@" + ip, timeout=5)
    index = child.expect(["error", "yes", "password", "Number of key(s) added: 1", "Now try logging into the machine"])

    while True:
        print("Expect:{}".format(index))
        if index == 0:
            child.kill(0)
        elif index == 1:
            child.sendline("yes")
        elif index == 2:
            child.sendline(passwd)
            break
        elif index == 3 or index == 4:
            break

    ssh.exec_command("cp ~/.ssh/authorized_keys /etc/dropbear/ >/dev/null 2>&1")
    ssh.close()

def rshark_sniffer(user, ip, port, q):
    pargs = ["ssh", user + "@" + ip, "tcpdump", "-i", "mon1", "-U", "-s0", "-w", "-", "not", "port", str(port) ]
    proc_tcpdump = subprocess.Popen(pargs, stdout=subprocess.PIPE)
    pargs = ["wireshark", "-k", "-i", "-"]
    # check_output　is similar with popen except that the stdout　invalid for user in check output 
    proc_wireshark = subprocess.check_output(pargs, stdin=proc_tcpdump.stdout)
    proc_tcpdump.wait(1)

if __name__ == "__main__":
    user="root"
    passwd="12345678"
    port = 22
    timeout = 1000
    ip = "10.17.7.107"
    rshark_update_key(ip, port, user, passwd, timeout)
    rshark_sniffer(user, ip, port, None)
    #th = threading.Thread(rshark_sniffer, args=(user, ip, port, q)

    #th.start()

    #threading.join(th)