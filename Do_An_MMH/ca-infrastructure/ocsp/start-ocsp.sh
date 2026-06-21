#!/bin/bash
# Lấy đường dẫn thư mục gốc của project
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
PROJECT_ROOT="$(cd "$DIR/../.." && pwd)"

echo "🚀 Starting OpenSSL OCSP Responder on port 8888..."

openssl ocsp -index "$PROJECT_ROOT/ca-infrastructure/ocsp/index.txt" \
-port 8888 \
-rsigner "$PROJECT_ROOT/ca-infrastructure/storage/ca-authority/subCA.pem" \
-rkey "$PROJECT_ROOT/ca-infrastructure/storage/ca-authority/subCA.key" \
-CA "$PROJECT_ROOT/ca-infrastructure/storage/ca-authority/subCA.pem" \
-text