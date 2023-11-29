@echo off & setlocal enabledelayedexpansion & PUSHD %~DP0 &TITLE EDC AutoIt

call .\venv\Scripts\activate

call pyinstaller --onefile  asrd.py
rem call pyinstaller --onedir  asrd.py

rem call pyinstaller --onefile rshark.py
call pyinstaller --onedir rshark.py

rem copy clients .\dist\asrd
copy asrd_clients .\dist\clients
copy rshark_clients .\dist\rshark\clients

copy readme.html .\dist

pause