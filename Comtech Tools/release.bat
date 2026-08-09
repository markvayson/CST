@echo off
set /p msg="Commit Message: "
set /p tag="Tag Version: "
git commit -am "%msg%"
git tag %tag%
git push
git push origin %tag%
pause