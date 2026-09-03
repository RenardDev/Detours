@echo off
setlocal EnableExtensions EnableDelayedExpansion

set "CLANG=C:\Program Files\LLVM\bin\clang-format.exe"

if not "%~1"=="" (
	"%CLANG%" -style=file %*
	exit /b !ERRORLEVEL!
)

set /a OK=0, ERR=0

for %%F in (Detours.h Detours.cpp main.cpp) do (
	set "FILE=%~dp0%%F"
	if exist "!FILE!" (
		echo Processing !FILE!...
		"%CLANG%" -i -style=file "!FILE!"
		if errorlevel 1 (
			echo [FAIL] !FILE!
			set /a ERR+=1
		) else (
			set /a OK+=1
		)
	)
)

echo.
echo Done. Formatted files: !OK!   Errors: !ERR!
exit /b %ERR%
