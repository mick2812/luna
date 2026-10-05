@echo off
setlocal
cd /d "%~dp0"
py -3 -m unittest discover -s tests -v
if errorlevel 1 goto finished
py -3 rabbit_hole_monster.py --check
:finished
pause
