@echo off
echo Installing Conpot for the Python used by OTShield backend...
echo.

set PYTHON_EXE=C:\Users\Fancy\AppData\Local\Python\pythoncore-3.14-64\python.exe

if not exist "%PYTHON_EXE%" (
    echo ERROR: Python not found at %PYTHON_EXE%
    echo Edit this file and set PYTHON_EXE to your python.exe path from application.properties
    pause
    exit /b 1
)

echo Using: %PYTHON_EXE%
"%PYTHON_EXE%" --version
echo.

echo Running: pip install conpot
"%PYTHON_EXE%" -m pip install conpot

if %errorlevel% == 0 (
    echo.
    echo Conpot installed successfully. You can now use "Start Conpot" in the app.
) else (
    echo.
    echo Installation failed. Try running manually in a terminal:
    echo   "%PYTHON_EXE%" -m pip install conpot
)

echo.
pause
