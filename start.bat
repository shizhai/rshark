@echo off & setlocal enabledelayedexpansion & PUSHD %~DP0 &TITLE EDC AutoIt

call .\venv\Scripts\activate

call pip install -i https://pypi.tuna.tsinghua.edu.cn/simple pyOpenSSL
call pip install -i https://pypi.tuna.tsinghua.edu.cn/simple wheel
call pip install -i https://pypi.tuna.tsinghua.edu.cn/simple paramiko
call pip install -i https://pypi.tuna.tsinghua.edu.cn/simple pexpect
call pip install -i https://pypi.tuna.tsinghua.edu.cn/simple argparse
call pip install -i https://pypi.tuna.tsinghua.edu.cn/simple pycryptodome

python rshark.py --conf clients


pause
