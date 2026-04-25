@echo off
echo Installing Python and Conpot for OTSHIELD...

REM Check if Python is installed
python --version >nul 2>&1
if %errorlevel% == 0 (
    echo Python is already installed
    goto :install_conpot
)

python3 --version >nul 2>&1
if %errorlevel% == 0 (
    echo Python3 is already installed
    goto :install_conpot
)

echo Python is not installed. Please install Python from https://www.python.org/downloads/
echo Make sure to check "Add Python to PATH" during installation
pause
exit /b 1

:install_conpot
echo Installing Conpot...

REM Try to install Conpot
python -m pip install conpot
if %errorlevel% == 0 (
    echo Conpot installed successfully with Python
    goto :end
)

python3 -m pip install conpot
if %errorlevel% == 0 (
    echo Conpot installed successfully with Python3
    goto :end
)

echo Failed to install Conpot. The system will use simulated mode.
echo You can manually install Conpot by running: pip install conpot

:end
echo.
echo Conpot setup complete!
echo You can now use the Conpot integration in OTSHIELD.
echo.
pause 