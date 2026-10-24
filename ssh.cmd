@echo off
setlocal
pushd "%~dp0" || exit /b 1
"%SystemRoot%\System32\OpenSSH\ssh.exe" -F .ssh/config storagehost %*
set "ssh_exit_code=%errorlevel%"
popd
endlocal & exit /b %ssh_exit_code%
