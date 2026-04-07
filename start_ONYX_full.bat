@echo off
color 0a
title ONYX CTI - MASTER LAUNCHER
echo [=========================================]
echo [       ONYX CTI PLATFORM - GENESIS       ]
echo [=========================================]
echo.
echo [*] Cleaning up old processes...
taskkill /F /IM node.exe >nul 2>&1
taskkill /F /IM python.exe >nul 2>&1

:: Absolute Paths for Python modules
set ROOT_DIR=%~dp0
set CORE_DIR=%ROOT_DIR%onyx-core
set NLP_DIR=%ROOT_DIR%onyx-nlp
set API_DIR=%ROOT_DIR%onyx-api

echo [*] Launching ONYX Backend (Standalone Mode)...
:: We set PYTHONPATH to the root of each package so that 'import onyx_core' works from anywhere
start "ONYX Backend" powershell -NoExit -Command "$env:STANDALONE_MODE='true'; $env:PYTHONPATH='%CORE_DIR%;%NLP_DIR%;%API_DIR%'; cd '%API_DIR%'; py -m uvicorn onyx_api.main:app --host 0.0.0.0 --port 8000 --reload"

echo [*] Launching ONYX Dashboard (Frontend)...
start "ONYX Dashboard" powershell -NoExit -Command "cd '%ROOT_DIR%onyx-dashboard'; npm run dev"

echo [*] Waiting for Next.js to compile...
timeout /t 10

echo [*] Launching Chrome...
start chrome "http://localhost:3000"

echo.
echo [=========================================]
echo [   PLATFORM IS BOOTING... DO NOT CLOSE   ]
echo [=========================================]
exit
