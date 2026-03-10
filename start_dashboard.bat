@echo off
echo ================================================================================
echo CloudWatch Log Analyzer - Live Monitoring Dashboard
echo ================================================================================
echo.
echo Starting dashboard with live monitoring...
echo.
echo Dashboard will be available at: http://localhost:5000
echo Live Monitoring page: http://localhost:5000/live-monitor
echo.
echo Press Ctrl+C to stop
echo.
echo ================================================================================
echo.

python dashboard.py

pause
