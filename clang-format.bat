@echo off
setlocal EnableExtensions EnableDelayedExpansion

set "CLANG=C:\Program Files\LLVM\bin\clang-format.exe"

set /a OK=0, ERR=0

for /R "%~dp0" %%F in (*.h *.hh *.hpp *.hxx *.inl *.tpp *.c *.cc *.cpp *.cxx *.ixx) do (
    set "P=%%~fF"
    echo Processing %%F...
    "%CLANG%" -i -style=file "%%F"
    if errorlevel 1 (
        echo [FAIL] %%F
        set /a ERR+=1
    ) else (
        set /a OK+=1
    )
)

echo.
echo Done. Formatted files: !OK!   Errors: !ERR!
exit /b %ERR%
