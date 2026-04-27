@echo off
color 0a
title ONYX CTI - MASTER LAUNCHER
echo [=======================================================]
echo [       ONYX CTI PLATFORM - MASTER LAUNCH SEQUENCE      ]
echo [=======================================================]
echo.

echo [1/6] Nettoyage des processus orphelins (Node/Python)...
taskkill /F /IM node.exe >nul 2>&1
taskkill /F /IM python.exe >nul 2>&1
echo [OK] Nettoyage termine.
echo.

echo [2/6] Verification des dependances systeme...
where node >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERREUR] Node.js n'est pas installe ou n'est pas dans le PATH.
    pause
    exit /b 1
)
where py >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERREUR] Python Launcher 'py' n'est pas installe.
    pause
    exit /b 1
)
echo [OK] Node.js et Python detectes.
echo.

echo [3/6] Configuration des chemins d'acces (Paths)...
set ROOT_DIR=%~dp0
set CORE_DIR=%ROOT_DIR%onyx-core
set NLP_DIR=%ROOT_DIR%onyx-nlp
set API_DIR=%ROOT_DIR%onyx-api
set DASHBOARD_DIR=%ROOT_DIR%onyx-dashboard

if not exist "%API_DIR%" (
    echo [ERREUR] Le repertoire Backend est introuvable : %API_DIR%
    pause
    exit /b 1
)
if not exist "%DASHBOARD_DIR%" (
    echo [ERREUR] Le repertoire Frontend est introuvable : %DASHBOARD_DIR%
    pause
    exit /b 1
)
echo [OK] Chemins valides.
echo.

echo [4/6] Lancement du Backend ONYX (FastAPI)...
set STANDALONE_MODE=true
set PYTHONPATH=%CORE_DIR%;%NLP_DIR%;%API_DIR%
start "ONYX Backend" cmd /k "title ONYX Backend Logs && color 0b && echo [BACKEND] Demarrage... && cd /d "%API_DIR%" && py -m uvicorn onyx_api.main:app --host 0.0.0.0 --port 8000 --reload || (echo [ERREUR] Crash du Backend && pause)"
echo [OK] Backend lance en arriere-plan.
echo.

echo [5/6] Lancement du Frontend ONYX (Next.js)...
start "ONYX Dashboard" cmd /k "title ONYX Frontend Logs && color 0e && echo [FRONTEND] Demarrage... && cd /d "%DASHBOARD_DIR%" && npm run dev || (echo [ERREUR] Crash du Frontend && pause)"
echo [OK] Frontend lance en arriere-plan.
echo.

echo [6/6] Finalisation de la sequence de boot...
echo [*] Attente de 10 secondes pour la compilation initiale de Next.js...
ping 127.0.0.1 -n 11 > nul

echo [*] Ouverture du navigateur par defaut...
start http://localhost:3000

echo.
echo [=======================================================]
echo [   PLATFORME OPERATIONNELLE - NE FERMEZ PAS CETTE VUE  ]
echo [=======================================================]
echo.
echo Appuyez sur une touche pour quitter ce lanceur principal...
pause >nul
