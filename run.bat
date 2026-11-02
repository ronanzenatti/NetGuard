@echo off
title NetGuard - Monitor de Conexoes de Rede
cd /d "%~dp0"

if not exist ".venv\Scripts\python.exe" (
    echo [NetGuard] Ambiente virtual nao encontrado. Criando .venv...
    python -m venv .venv
    echo [NetGuard] Instalando dependencias mais recentes...
    .\.venv\Scripts\python.exe -m pip install --upgrade pip
    .\.venv\Scripts\python.exe -m pip install -r requirements.txt
)

echo [NetGuard] Iniciando o aplicativo com ambiente virtual...
start "" ".\.venv\Scripts\python.exe" "main.py"
exit

