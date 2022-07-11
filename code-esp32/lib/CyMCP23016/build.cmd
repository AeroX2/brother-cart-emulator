@echo off
cls

set BUILD_ARGS=--lib="." --verbose --board=uno --board=micro --board=leonardo --board=megaatmega1280 --board=megaatmega2560 --board=huzzah

:: Get script directory
set SCRIPT_DIR=%~dp0
set SCRIPT_DIR=%SCRIPT_DIR:~0,-1%

:: Build example
set TEST=%SCRIPT_DIR%\examples\BasicIOTest\BasicIOTest.ino

pio ci %BUILD_ARGS% %TEST%

exit %ERRORLEVEL%