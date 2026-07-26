@echo off
setlocal
:: Builds the 32-bit CardIO.dll replacement.
:: Requires Visual Studio 2022 with the x86 C++ toolset.

set "VCVARS=C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars32.bat"
if not exist "%VCVARS%" (
    echo ERROR: vcvars32.bat not found at:
    echo   %VCVARS%
    echo Edit VCVARS in this script to point at your Visual Studio install.
    exit /B 1
)

call "%VCVARS%" >NUL || (echo ERROR: failed to initialise the x86 build environment & exit /B 1)

cd /d "%~dp0"
if not exist build mkdir build

:: /MT statically links the CRT so the DLL drops into the PED-Basic folder
:: without needing any redistributable alongside it.
cl /nologo /LD /MT /O2 /W3 /GS- ^
   src\CardIO.cpp ^
   /Fo:build\ /Fd:build\ /Fe:build\CardIO.dll ^
   /link /DEF:src\CardIO.def /OUT:build\CardIO.dll ^
   kernel32.lib user32.lib
if errorlevel 1 (
    echo.
    echo BUILD FAILED
    exit /B 1
)

echo.
echo Built build\CardIO.dll
echo.
echo Exports:
dumpbin /nologo /exports build\CardIO.dll | findstr /C:"CCardIO"

endlocal
