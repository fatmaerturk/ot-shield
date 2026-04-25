@echo off
REM Try to install Conpot on Windows when crc16/pycrypto fail to build.
REM Run from project root. Uses the Python set in backend's application.properties, or default 'py'.

set PYTHON_EXE=py
if defined CONPOT_PYTHON set PYTHON_EXE=%CONPOT_PYTHON%

echo ========================================
echo Conpot install (Windows workarounds)
echo ========================================
echo Using: %PYTHON_EXE%
%PYTHON_EXE% --version
echo.

REM 1) Use pycryptodome as drop-in for pycrypto (avoids building pycrypto)
echo [1/3] Installing pycryptodome (replacement for pycrypto)...
%PYTHON_EXE% -m pip install pycryptodome
if %errorlevel% neq 0 (
  echo pycryptodome install failed.
  goto :manual
)
echo.

REM 2) Install Visual C++ build tools requirement note, then try conpot
echo [2/3] Installing Conpot (may still fail on crc16)...
%PYTHON_EXE% -m pip install conpot --no-cache-dir
if %errorlevel% equ 0 (
  echo.
  echo Conpot installed successfully.
  goto :end
)

REM 3) If still failing, user needs C++ build tools
echo.
echo [3/3] Conpot or one of its deps (e.g. crc16) failed to build.
echo.
echo OPTION A - Install C++ Build Tools (one-time):
echo   1. Open: https://visualstudio.microsoft.com/visual-cpp-build-tools/
echo   2. Download "Build Tools for Visual Studio 2022"
echo   3. Run installer, select "Desktop development with C++"
echo   4. After install, open a NEW terminal and run:
echo      %PYTHON_EXE% -m pip install conpot
echo.
echo OPTION B - Use simulation mode (no Conpot needed):
echo   In the app, click Start Conpot. If Conpot is not installed,
echo   the backend will run in simulation mode and show demo logs.
echo.
goto :end

:manual
echo.
echo To use a specific Python (e.g. 3.11), set CONPOT_PYTHON first:
echo   set CONPOT_PYTHON=C:\Users\Fancy\AppData\Local\Programs\Python\Python311\python.exe
echo   install_conpot_windows.bat
echo.

:end
pause
