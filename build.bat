@echo off
setlocal
set MSBUILD=C:\Program Files\Microsoft Visual Studio\18\Community\MSBuild\Current\bin\MSBuild.exe
echo Building Release^|x64...
"%MSBUILD%" "Comtech Tools\Comtech Tools.vcxproj" /p:Configuration=Release /p:Platform=x64 /t:Rebuild /v:minimal
echo.
echo Build exit code: %ERRORLEVEL%