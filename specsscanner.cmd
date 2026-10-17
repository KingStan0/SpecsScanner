@echo off
rem SpecsScanner launcher - double-click friendly wrapper around SpecsScanner.ps1
setlocal
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0SpecsScanner.ps1" %*
echo.
pause
endlocal
