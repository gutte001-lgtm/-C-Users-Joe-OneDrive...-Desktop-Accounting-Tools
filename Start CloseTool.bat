@echo off
title CloseTool - Running
cd /d "C:\Users\Joe\OneDrive - Healthcare Markets DBA\Desktop\Accounting Tools"

:: Open browser after 3 seconds (in background)
start "" /min powershell -NoProfile -WindowStyle Hidden -Command "Start-Sleep -Seconds 3; Start-Process 'http://127.0.0.1:5000'"

:: Start Flask server (blocks until stopped)
echo Starting CloseTool...
echo.
echo Open http://127.0.0.1:5000 in your browser if it doesn't open automatically.
echo Press Ctrl+C to stop the server.
echo.
py app.py

:: If server exits, pause so user can read any errors
echo.
echo --- Server stopped ---
pause >nul
