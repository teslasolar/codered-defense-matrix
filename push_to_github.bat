@echo off
REM =========================================
REM  CodeRED Defense Matrix - GitHub Push
REM =========================================

echo =========================================
echo   CodeRED Defense Matrix - GitHub Push
echo =========================================
echo.

REM Check if we're in the right directory
if not exist "README.md" (
    echo [ERROR] Not in CodeRED Defense Matrix directory!
    exit /b 1
)

REM Show current status
echo [*] Current Git Status:
git status --short
echo.

REM Add all important files
echo [*] Adding all project files...

REM Add source code
git add src\
git add tests\

REM Add documentation
git add README.md
git add SECURITY.md
git add CONTRIBUTING.md
git add LICENSE
git add docs\

REM Add configuration files
git add requirements.txt
git add pytest.ini
git add .gitignore
git add Dockerfile
git add docker-compose.yml

REM Add deployment scripts
git add deployment\
git add launch.sh
git add *.py
git add *.bat
git add *.sh

REM Add configs if exists
git add configs\ 2>nul

REM Check what's been staged
echo.
echo [*] Files staged for commit:
git diff --cached --name-only | find /c /v ""
echo.

REM Show what will be committed
echo Files to be committed:
git diff --cached --name-only | more

echo.
set /p CONFIRM="Do you want to commit these changes? (y/n) "

if /i "%CONFIRM%"=="y" (
    echo [*] Committing changes...
    git commit -m "Complete CodeRED Defense Matrix implementation - Comprehensive defensive cybersecurity system with full test suite"

    REM Check if remote is set
    git remote | findstr "origin" >nul
    if errorlevel 1 (
        echo [*] Setting remote origin...
        git remote add origin https://github.com/teslasolar/codered-defense-matrix.git
    )

    REM Push to GitHub
    echo.
    echo [*] Pushing to GitHub...
    git push -u origin main
    if errorlevel 1 (
        echo [*] Trying master branch...
        git push -u origin master
    )

    echo.
    echo =========================================
    echo [SUCCESS] Pushed to GitHub!
    echo Repository: https://github.com/teslasolar/codered-defense-matrix
    echo.
    echo Next steps:
    echo 1. Go to: https://github.com/teslasolar/codered-defense-matrix/settings/pages
    echo 2. Enable GitHub Pages from main/master branch
    echo 3. Documentation: https://teslasolar.github.io/codered-defense-matrix/
    echo =========================================
) else (
    echo [*] Commit cancelled
)

pause