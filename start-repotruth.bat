@echo off
cd /d "%~dp0"
py -3.13 -m repotruth serve --open
if errorlevel 1 pause
