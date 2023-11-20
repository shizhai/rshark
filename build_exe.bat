@echo off & setlocal enabledelayedexpansion & PUSHD %~DP0 &TITLE EDC AutoIt

call .\venv\Scripts\activate

call pyinstaller --onefile asrd.py

call pyinstaller --onefile rshark.py

copy clients win_init.bat readme.html .\dist

pause