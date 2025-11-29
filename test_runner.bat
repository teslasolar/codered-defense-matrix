@echo off
REM Test Runner for CodeRED Defense Matrix - Windows Version
REM Runs comprehensive tests with security validation

echo.
echo ============================================================
echo          CodeRED Defense Matrix - Test Runner
echo          Testing defensive cybersecurity components
echo ============================================================
echo.

REM Check if Python is available
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Python is not installed or not in PATH
    exit /b 1
)

REM Check for pytest
python -c "import pytest" >nul 2>&1
if %errorlevel% neq 0 (
    echo [WARNING] pytest not installed. Installing test dependencies...
    pip install pytest pytest-asyncio pytest-cov pytest-mock
)

echo [*] Running Security Tests...
echo ----------------------------------------
python -m pytest tests/test_security_core.py -v --tb=short

echo.
echo [*] Running VectorChain Tests...
echo ----------------------------------------
python -m pytest tests/test_vector_chain.py -v --tb=short

echo.
echo [*] Running SwarmDefender Tests...
echo ----------------------------------------
python -m pytest tests/test_swarm_defender.py -v --tb=short

echo.
echo [*] Running Integration Tests...
echo ----------------------------------------
python -m pytest tests/test_integration.py -v --tb=short -m integration

echo.
echo [*] Generating Coverage Report...
echo ----------------------------------------
python -m pytest tests/ --cov=src --cov-report=term --cov-report=html:htmlcov --quiet

echo.
echo ============================================================
echo Test run complete! Check htmlcov/index.html for coverage.
echo ============================================================
pause