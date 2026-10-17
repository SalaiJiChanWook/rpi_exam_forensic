@echo off
setlocal
title RPi Exam Forensic Evidence Verifier & Viewer
color 0A

echo ========================================================
echo   RPi Offline Exam Forensic Inspector (Windows 11)
echo ========================================================
echo.

set /p ARCHIVE="Enter path to .tar.gz bundle: "
if not exist "%ARCHIVE%" (
    color 0C
    echo [!] File not found. Exiting...
    pause
    exit /b 1
)

:: Verify SHA-256 Hash
if exist "%ARCHIVE%.sha256" (
    echo [*] Verifying Evidence Archive Integrity...
    certutil -hashfile "%ARCHIVE%" SHA256
    echo.
    echo [*] Expected SHA-256:
    type "%ARCHIVE%.sha256"
) else (
    echo [!] Warning: No .sha256 file found alongside archive.
    certutil -hashfile "%ARCHIVE%" SHA256
)

echo.
echo ========================================================
echo Extract with 7-Zip to view artifacts:
echo   - forensic_report.html (Interactive Dashboard)
echo   - quick_summary.csv    (Excel / Spreadsheet Table)
echo   - security_findings.json
echo ========================================================
pause