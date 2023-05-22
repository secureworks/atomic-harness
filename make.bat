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
	echo cleaning previous executables
	for /F "delims=" %%i in ('dir %~dp0\bin') do (rmdir "%%i" /s/q || del "%%i" /s/q)
	echo Finished Cleaning.
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

  for /F "tokens=2 delims==" %%s in ('set ARCH[') do (
    
    SET GOOS=windows
    SET GOARCH=%%s
    SET GOARM=6
    echo Building !GOOS!/!GOARCH!

    SET EXTENSION=".exe"

      go build -buildmode=exe -ldflags "-s -w -X main.version=%@version% -X main.buildstamp=%@bdate%-%@btime% -X main.hash=%@gitrev%" -o bin/atomic-harness_!GOARCH!!EXTENSION! ./cmd/harness/
      go build -buildmode=exe -ldflags "-s -w -X main.version=%@version% -X main.buildstamp=%@bdate%-%@btime% -X main.hash=%@gitrev%" -o bin/atrutil_!GOARCH!!EXTENSION! ./cmd/atrutil
   
   echo.
  )
)

echo.
echo Finished Building