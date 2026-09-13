@echo off
REM =====================================
REM AIO SSL Tool - Windows Build Script
REM Version 6.4.4
REM =====================================

setlocal enabledelayedexpansion

echo.
echo =====================================
echo  AIO SSL Tool - Windows Build
echo  Version 6.4.4
echo =====================================
echo.

REM Check Python installation
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python is not installed or not in PATH
    echo Please install Python 3.8 or higher
    pause
    exit /b 1
)

echo [OK] Python found
python --version
echo.

REM Check required files
echo Checking required files...
set MISSING_FILES=0

if not exist HomeIcon.png (
    echo [ERROR] HomeIcon.png not found
    set MISSING_FILES=1
) else (
    echo [OK] HomeIcon.png found
)

if not exist icon-ico.ico (
    echo [ERROR] icon-ico.ico not found
    set MISSING_FILES=1
) else (
    echo [OK] icon-ico.ico found
)

if not exist aio_ssl_tool.py (
    echo [ERROR] aio_ssl_tool.py not found
    set MISSING_FILES=1
) else (
    echo [OK] aio_ssl_tool.py found
)

if not exist AIO-SSL-Tool-Windows.spec (
    echo [ERROR] AIO-SSL-Tool-Windows.spec not found
    set MISSING_FILES=1
) else (
    echo [OK] AIO-SSL-Tool-Windows.spec found
)

if not exist requirements.txt (
    echo [ERROR] requirements.txt not found
    set MISSING_FILES=1
) else (
    echo [OK] requirements.txt found
)

if %MISSING_FILES%==1 (
    echo.
    echo [ERROR] Missing required files. Build cannot continue.
    pause
    exit /b 1
)

echo.
echo [OK] All required files present
echo.

REM Install/upgrade dependencies
echo =====================================
echo  Installing dependencies...
echo =====================================

python -m pip install --upgrade pip >nul 2>&1

echo Installing PyInstaller...
pip install pyinstaller
if errorlevel 1 (
    echo [ERROR] Failed to install PyInstaller
    pause
    exit /b 1
)

echo Installing project dependencies...
pip install -r requirements.txt
if errorlevel 1 (
    echo [ERROR] Failed to install dependencies
    pause
    exit /b 1
)

echo [OK] Dependencies installed
echo.

REM Clean previous builds
echo =====================================
echo  Cleaning previous builds...
echo =====================================

if exist build (
    echo Removing build directory...
    rmdir /s /q build
)

if exist dist (
    echo Removing dist directory...
    rmdir /s /q dist
)

echo [OK] Clean complete
echo.

REM Build with PyInstaller using spec file
echo =====================================
echo  Building executable...
echo =====================================
echo.
echo Using spec file: AIO-SSL-Tool-Windows.spec
echo.

pyinstaller --clean AIO-SSL-Tool-Windows.spec

if errorlevel 1 (
    echo.
    echo [ERROR] Build failed
    pause
    exit /b 1
)

REM Check if build was successful
echo.
echo =====================================
echo  Build Results
echo =====================================

if exist dist\AIO-SSL-Tool-Windows.exe (
    echo [SUCCESS] Build completed!
    echo.
    echo Executable: dist\AIO-SSL-Tool-Windows.exe
    
    for %%A in (dist\AIO-SSL-Tool-Windows.exe) do (
        set size=%%~zA
        set /a sizeMB=!size! / 1048576
        echo Size: !sizeMB! MB
    )
    
    echo.
    echo To test: dist\AIO-SSL-Tool-Windows.exe
    echo.
) else (
    echo [ERROR] Executable not found
    echo Check output above for errors
    pause
    exit /b 1
)

echo =====================================
echo  Build Complete!
echo =====================================
echo.
