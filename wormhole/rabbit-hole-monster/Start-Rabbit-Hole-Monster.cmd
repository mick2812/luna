@echo off
setlocal
cd /d "%~dp0"
where py >nul 2>&1
if not errorlevel 1 (
  py -3 -c "import sys; sys.exit(sys.version_info < (3,11))" >nul 2>&1
  if not errorlevel 1 (
    py -3 "%~dp0rabbit_hole_monster.py"
    goto finished
  )
)
where python >nul 2>&1
if not errorlevel 1 (
  python -c "import sys; sys.exit(sys.version_info < (3,11))" >nul 2>&1
  if not errorlevel 1 (
    python "%~dp0rabbit_hole_monster.py"
    goto finished
  )
)
echo Python 3.11 or newer was not found. Install Python with the launcher enabled.
:finished
pause
