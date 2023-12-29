@echo off & setlocal enabledelayedexpansion & PUSHD %~DP0 &TITLE EDC AutoIt

call .\venv\Scripts\activate

call pyinstaller --onefile  asrd.py
call pyinstaller --onedir -i .\files\wifi.ico ashark.py

mkdir .\dist\ashark\files\iperf
copy .\files\iperf .\dist\ashark\files\iperf
copy .\files\wifi.ico .\dist\ashark\files\wifi.ico
copy .\files\asrd_clients .\dist\clients
copy .\files\ashark_clients .\dist\ashark\files\clients
copy readme.html .\dist

pause