@echo off & setlocal enabledelayedexpansion & PUSHD %~DP0 &TITLE EDC AutoIt

call .\venv\Scripts\activate

call pyinstaller --onefile asrd.py

call pyinstaller --onefile rshark.py

copy clients .\dist

copy win_init.bat .\dist

copy readme.html .\dist

pause