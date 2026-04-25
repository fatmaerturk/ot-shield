@echo off
echo Testing Conpot Integration...

set PYTHONPATH=C:\Users\Fatma\Documents\GitHub\otshield-v1\conpot

echo PYTHONPATH set to: %PYTHONPATH%

echo.
echo Testing conpot help command...
py conpot\bin\conpot --help

if %errorlevel% == 0 (
    echo.
    echo ✅ Conpot help command works!
    echo.
    echo Testing conpot start...
    py conpot\bin\conpot -f -v
) else (
    echo.
    echo ❌ Conpot help command failed!
)

pause 