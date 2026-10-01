@echo off
setlocal
where node >nul 2>nul
if errorlevel 1 (
  echo Node.js was not found. Install Node.js 22.12 or newer, reopen this window, and retry.
  echo First-time setup in this checkout: npm ci --include=dev --ignore-scripts
  pause
  exit /b 1
)
node "%~dp0scripts\start-studio.mjs" %*
set "studio_exit=%errorlevel%"
if not "%studio_exit%"=="0" pause
exit /b %studio_exit%
