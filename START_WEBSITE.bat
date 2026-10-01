@echo off
title CSTD Sentinel AI SOC - Enterprise Server Runner
cd /d "%~dp0"

echo =================================================================
echo   CSTD AI SENTINEL - ENTERPRISE CYBER THREAT DETECTION SOC
echo =================================================================
echo.
echo [1/3] Verifying and building production bundle...
if not exist "dist" (
    echo Building React production bundle...
    call npm run build
)

echo [2/3] Installing backend dependencies if needed...
if not exist "server\node_modules" (
    echo Installing server packages...
    cd server
    call npm install --omit=dev
    cd ..
)

echo [3/3] Starting Full-Stack Server on http://localhost:5000 ...
echo       REST API:   http://localhost:5000/api/health
echo       WebSocket:  ws://localhost:5000/ws
echo.

:: Open default web browser
start http://localhost:5000/

:: Start the Full-Stack Node.js Express & WebSocket server
call node server/server.js

pause
