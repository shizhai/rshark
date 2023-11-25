#!/bin/bash

rm -rf venv

sudo apt remove python3-openssl -y
sudo apt install openssh-server openssl -y
sudo apt install python3-dev -y
sudo apt install python3-pip -y
sudo apt install python3.8-venv -y
sudo apt install wireshark -y

sudo chmod +x /usr/bin/dumpcap

sudo ln -s $(pwd)/rshark.py /usr/bin/rshark
sudo ln -s $(pwd)/asrd.py /usr/bin/asrd

if [ "$2" == "venv" ];then
    python3 -m venv venv
    source venv/bin/activate
fi

# from requirement
#pip3 install pyOpenSSL -i https://pypi.tuna.tsinghua.edu.cn/simple/
#pip3 install wheel -i https://pypi.tuna.tsinghua.edu.cn/simple/
#pip3 install paramiko -i https://pypi.tuna.tsinghua.edu.cn/simple/
#pip3 install pexpect -i https://pypi.tuna.tsinghua.edu.cn/simple/
#pip3 install argparse -i https://pypi.tuna.tsinghua.edu.cn/simple/
#pip3 install pycryptodome -i https://pypi.tuna.tsinghua.edu.cn/simple/
