@echo off & setlocal enabledelayedexpansion & PUSHD %~DP0 &TITLE EDC AutoIt

call .\venv\Scripts\activate

call pyinstaller --onefile  asrd.py
rem call pyinstaller --onedir  asrd.py

rem call pyinstaller --onefile rshark.py
call pyinstaller --onedir rshark.py

rem copy clients .\dist\asrd
copy clients .\dist

copy readme.html .\dist

pause