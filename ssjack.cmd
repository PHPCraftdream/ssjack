@echo off
setlocal
"%~dp0build\ssjack.exe" %*
exit /b %errorlevel%
