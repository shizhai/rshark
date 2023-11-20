@echo off & setlocal enabledelayedexpansion & PUSHD %~DP0 &TITLE AixLink


IF EXIST %userprofile%/.ssh/id_rsa goto NEXT
ssh-keygen -t rsa -N '' -f %userprofile%/.ssh/id_rsa -q

:NEXT
echo add bat
pause