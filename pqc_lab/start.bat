@echo off
setlocal
set PYTHONUTF8=1
cd /d "%~dp0.."
python pqc_lab\lab.py serve
if errorlevel 1 pause
