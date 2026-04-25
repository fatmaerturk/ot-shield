@echo off
echo ========================================
echo Finding Python Installation...
echo ========================================
echo.

REM Try common Python commands
echo Checking 'python' command...
python --version >nul 2>&1
if %errorlevel% == 0 (
    echo [FOUND] python
    where python
    echo.
    goto :check_py
)

echo [NOT FOUND] python
echo.

:check_py
echo Checking 'py' launcher...
py --version >nul 2>&1
if %errorlevel% == 0 (
    echo [FOUND] py launcher
    where py
    echo.
    echo To get Python path, run: py -c "import sys; print(sys.executable)"
    echo.
    goto :check_common_paths
)

echo [NOT FOUND] py launcher
echo.

:check_common_paths
echo Checking common Python installation paths...
echo.

REM Check AppData\Local\Programs\Python
if exist "%LOCALAPPDATA%\Programs\Python" (
    echo [FOUND] %LOCALAPPDATA%\Programs\Python
    dir /b "%LOCALAPPDATA%\Programs\Python"
    echo.
)

REM Check Program Files
if exist "C:\Program Files\Python*" (
    echo [FOUND] C:\Program Files\Python*
    dir /b "C:\Program Files\Python*"
    echo.
)

REM Check Program Files (x86)
if exist "C:\Program Files (x86)\Python*" (
    echo [FOUND] C:\Program Files (x86)\Python*
    dir /b "C:\Program Files (x86)\Python*"
    echo.
)

REM Check user directory
if exist "%USERPROFILE%\AppData\Local\Programs\Python" (
    echo [FOUND] %USERPROFILE%\AppData\Local\Programs\Python
    dir /b "%USERPROFILE%\AppData\Local\Programs\Python"
    echo.
)

echo ========================================
echo Instructions:
echo ========================================
echo 1. If Python was found above, copy the full path to python.exe
echo 2. Open: backend\src\main\resources\application.properties
echo 3. Add or uncomment this line (replace with your path):
echo    conpot.python.path=C:\\Path\\To\\Python\\python.exe
echo 4. Use double backslashes (\\) in the path
echo 5. Restart the backend
echo.
echo Example:
echo    conpot.python.path=C:\\Users\\YourName\\AppData\\Local\\Programs\\Python\\Python311\\python.exe
echo.
pause
