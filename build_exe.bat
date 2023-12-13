@echo off & setlocal enabledelayedexpansion & PUSHD %~DP0 &TITLE EDC AutoIt

call .\venv\Scripts\activate
rem call pyinstaller --onedir  asrd.py
rem call pyinstaller --onefile rshark.py

call pyinstaller --onefile  asrd.py
call pyinstaller --onedir ashark.py

copy asrd_clients .\dist\clients
copy rshark_clients .\dist\ashark\clients

mkdir .\dist\ashark\files\iperf
copy .\files\iperf .\dist\ashark\files\iperf

copy readme.html .\dist

pause