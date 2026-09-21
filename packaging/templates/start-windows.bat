@echo off
setlocal
title Spreest - Panel ACB{{MODE_TITLE_BAT}}
{{MODE_ENV}}cd /d "%~dp0"
set "PY=%~dp0runtime\windows-x64\python.exe"
if not exist "%PY%" (
  echo Nie znaleziono pliku runtime\windows-x64\python.exe.
  echo Najpierw rozpakuj CALE archiwum ZIP ^(prawy przycisk - "Wyodrebnij wszystkie"^),
  echo a dopiero potem uruchom ten plik z rozpakowanego folderu.
  pause
  exit /b 1
)
"%PY%" -X utf8 -s -E "%~dp0app\acs_panel.py"
if errorlevel 1 pause
