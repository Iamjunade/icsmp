@echo off
title REDACT // SENSITIVE CONTENT SCANNER (MINI DLP)
color 0B
chcp 65001 >nul

echo ======================================================================
echo    REDACT // SENSITIVE CONTENT SCANNER (MINI DLP) - LAB MP-06
echo ======================================================================
echo  [1/3] Navigating to project directory...
cd /d "%~dp0"

echo  [2/3] Running verification test suite (T1 - T11)...
python test_dlp_scanner.py
if %ERRORLEVEL% NEQ 0 (
    echo.
    echo [ERROR] Unit tests failed! Please check python installation.
    pause
    exit /b %ERRORLEVEL%
)

echo.
echo  [3/3] Launching localhost backend engine & Web Console...
echo  - Server URL : http://localhost:8000
echo  - Opening your default browser...

:: Open the web browser after a brief delay so the server has initialized
start "" cmd /c "timeout /t 2 /nobreak >nul && start http://localhost:8000"

:: Start the Python backend HTTP server
python server.py

pause
