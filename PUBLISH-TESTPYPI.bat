@echo off
setlocal
title Inspectra - publish to TestPyPI
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\publish-testpypi.ps1" %*
echo.
pause
