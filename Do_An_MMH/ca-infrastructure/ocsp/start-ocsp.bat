@echo off
echo 🚀 Starting OpenSSL OCSP Responder on port 8888...
set SCRIPT_DIR=%~dp0
set PROJECT_ROOT=%SCRIPT_DIR%..\..

openssl ocsp -index "%PROJECT_ROOT%\ca-infrastructure\ocsp\index.txt" ^
-port 8888 ^
-rsigner "%PROJECT_ROOT%\ca-infrastructure\storage\ca-authority\subCA.pem" ^
-rkey "%PROJECT_ROOT%\ca-infrastructure\storage\ca-authority\subCA.key" ^
-CA "%PROJECT_ROOT%\ca-infrastructure\storage\ca-authority\subCA.pem" ^
-text
