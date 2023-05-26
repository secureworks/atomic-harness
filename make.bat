@echo off
Title "MAKEFILE"


SET ARCH[0]=386
SET ARCH[1]=amd64
SET ARCH[2]=arm
SET ARCH[3]=arm64
SET BUILD=windows

setlocal enabledelayedexpansion
set CGO_ENABLED=0


IF "%1" == "clean" (
	echo cleaning previous executables...
	for /f tokens^=* %%i in ("dir %~dp0\bin") do echo/ Path: %%~dpi ^| Name: %%~nxi
	set /p "choice= Are you sure you want to delete ALL files in the bin folder? (y/n): " 
	echo choice: '!choice!'
	IF NOT "!choice!" EQU "y" (
	echo have a good day^^!
	EXIT /B 1
	)
	DEL "%~dp0\bin\*" /S /Q
	echo Finished Cleaning.
	EXIT /B 0
)

IF "%1" == "" (
	echo *****************************
	echo run './make help' to see the allowed functions' 
	echo *****************************
	EXIT /B 0
)

IF "%1" == "help" (
	echo Please select a file to compile:
	echo -----------------------------
	echo ** atomic-harness: ./make atomic-harness	
	echo ** atrutil: ./make atrutil

	echo -----------------------------
	echo to compile both: 
	echo ** ./make all

	echo -----------------------------
	echo to remove old executables: 
	echo ** ./make clean
	echo -----------------------------
	EXIT /B 0
)


REM Bring code to last version
echo Pulling all commits...
git pull
echo.

REM Create Changelog
echo Building changelog...
git log --oneline --decorate > CHANGELOG
echo Changelog Build Finished
echo.

 

    SET GOOS=windows
    echo Building !GOOS!

    SET EXTENSION=".exe"
	IF "%1" == "all" (
      	go build -buildmode=exe -ldflags "-s -w -X main.version=%@version% -X main.buildstamp=%@bdate%-%@btime% -X main.hash=%@gitrev%" -o bin/atomic-harness!EXTENSION! ./cmd/harness/
      	go build -buildmode=exe -ldflags "-s -w -X main.version=%@version% -X main.buildstamp=%@bdate%-%@btime% -X main.hash=%@gitrev%" -o bin/atrutil!EXTENSION! ./cmd/atrutil
   	)
 	IF "%1" == "atrutil" (
      	go build -buildmode=exe -ldflags "-s -w -X main.version=%@version% -X main.buildstamp=%@bdate%-%@btime% -X main.hash=%@gitrev%" -o bin/atrutil!EXTENSION! ./cmd/atrutil
   	)
	IF "%1" == "atomic-harness" (
      	go build -buildmode=exe -ldflags "-s -w -X main.version=%@version% -X main.buildstamp=%@bdate%-%@btime% -X main.hash=%@gitrev%" -o bin/atomic-harness!EXTENSION! ./cmd/harness/
   	)
)
echo Finished Building. Executables located in ./bin directory