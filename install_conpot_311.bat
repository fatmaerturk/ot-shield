@echo off
REM Conpot'u Python 3.11'e kurar. Crc16/pycrypto hatasi alirsaniz once C++ Build Tools kurun.
set PY=C:\Users\Fancy\AppData\Local\Programs\Python\Python311\python.exe

echo Conpot kuruluyor (Python 3.11)...
echo.

if not exist "%PY%" (
    echo HATA: %PY% bulunamadi.
    pause
    exit /b 1
)

"%PY%" -m pip install --upgrade pip
"%PY%" -m pip install conpot

if %errorlevel% equ 0 (
    echo.
    echo Basarili. Backend'i yeniden baslatin ve Start Conpot deyin.
) else (
    echo.
    echo Kurulum basarisiz. "crc16, pycrypto" build hatasi aldiysaniz:
    echo 1. https://visualstudio.microsoft.com/visual-cpp-build-tools/
    echo 2. Build Tools for Visual Studio 2022 indirin
    echo 3. Kurulumda "Desktop development with C++" secin
    echo 4. Kurulum bitince YENI bir terminal acin ve bu dosyayi tekrar calistirin
)

echo.
pause
