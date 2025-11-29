@echo off
setlocal

echo ==========================================
echo   SECUREWIPE — Release Automation Script
echo ==========================================

REM ---- Choose Upload Target ----
echo.
echo Select upload target:
echo   1 = TestPyPI
echo   2 = PyPI (LIVE)
set /p TARGET="Enter choice (1 or 2): "

if "%TARGET%"=="1" (
    set REPO=testpypi
) else (
    if "%TARGET%"=="2" (
        set REPO=pypi
    ) else (
        echo Invalid choice.
        exit /b 1
    )
)

echo.
echo Cleaning old build artifacts...
del /s /q dist 2>nul
del /s /q build 2>nul
del /s /q *.egg-info 2>nul

echo.
echo Running tests...
py -m pytest
if errorlevel 1 (
    echo Tests failed — aborting release!
    exit /b 1
)

echo.
echo Building package...
py -m pip install --upgrade build >nul
py -m build
if errorlevel 1 (
    echo Build failed!
    exit /b 1
)

echo.
echo Smoke testing installation...
py -m pip uninstall -y securewipe >nul
py -m pip install dist\securewipe-*.whl
py -c "import securewipe; print('Version:', securewipe.__version__)"
if errorlevel 1 (
    echo Smoke test failed!
    exit /b 1
)

echo.
echo Uploading to %REPO%...
py -m pip install --upgrade twine >nul
py -m twine upload --repository %REPO% dist\*
if errorlevel 1 (
    echo Upload failed!
    exit /b 1
)

echo.
echo ==========================================
echo   RELEASE COMPLETED SUCCESSFULLY!
echo ==========================================

endlocal
exit /b 0
