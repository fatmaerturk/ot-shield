@echo off
set PY=C:\Users\Fancy\AppData\Local\Programs\Python\Python311\python.exe
echo Checking Python and Conpot...
echo.

if not exist "%PY%" (
    echo [HATA] Python bulunamadi: %PY%
    echo.
    echo Python 3.11 kurulu mu? Farkli bir yerdeyse application.properties icinde
    echo conpot.python.path degerini o yola guncelleyin.
    echo.
    echo Olası konumlar:
    dir /b "%LOCALAPPDATA%\Programs\Python\Python*" 2>nul
    if errorlevel 1 echo   %LOCALAPPDATA%\Programs\Python\ altinda Python klasoru yok
    pause
    exit /b 1
)

echo [OK] Python: %PY%
"%PY%" --version
echo.

echo Conpot modulu kontrol ediliyor...
"%PY%" -c "import conpot; print('Conpot OK:', conpot.__file__)" 2>nul
if errorlevel 1 (
    echo [HATA] Conpot bu Python'da yok. Kurmak icin:
    echo   "%PY%" -m pip install conpot
    echo.
    echo Eger "crc16, pycrypto build failed" hatasi alirsaniz, once su adimlar:
    echo 1. https://visualstudio.microsoft.com/visual-cpp-build-tools/
    echo 2. "Desktop development with C++" ile kurun
    echo 3. Yeni terminal acip yukaridaki pip install conpot komutunu calistirin
    pause
    exit /b 1
)

echo.
echo Her sey hazir. Backend'i yeniden baslatin ve Start Conpot deyin.
pause
