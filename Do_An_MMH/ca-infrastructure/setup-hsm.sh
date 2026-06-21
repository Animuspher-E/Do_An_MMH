#!/bin/bash
# Script khởi tạo SoftHSM2 bền bỉ cho đồ án NT219

# Lấy đường dẫn thư mục gốc của project
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
PROJECT_ROOT="$(cd "$DIR/.." && pwd)"
STORAGE_DIR="$PROJECT_ROOT/ca-infrastructure/storage"

# 1. Tạo thư mục cấu hình nếu chưa có
mkdir -p "$STORAGE_DIR/softhsm2/tokens"

# 2. Thiết lập biến môi trường cho SoftHSM2
export SOFTHSM2_CONF="$STORAGE_DIR/softhsm2/softhsm2.conf"
echo "directories.tokendir = $STORAGE_DIR/softhsm2/tokens" > "$SOFTHSM2_CONF"

# 3. Khởi tạo Token (Slot 0) với nhãn CloudHSM
if command -v softhsm2-util &> /dev/null; then
    echo "⚒️  Đang khởi tạo SoftHSM Token..."
    softhsm2-util --init-token --free --label "CloudHSM" --so-pin 12345678 --pin 123456
else
    echo "⚠️  Cảnh báo: Lệnh softhsm2-util không tìm thấy. HSM chưa được cài đặt."
fi

# Tìm kiếm thư mục thư viện SoftHSM2 khả dụng trên hệ thống Linux
paths=(
    "/usr/lib/softhsm/libsofthsm2.so"
    "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so"
    "/usr/local/lib/softhsm/libsofthsm2.so"
)
LIB_PATH=""
for p in "${paths[@]}"; do
    if [ -f "$p" ]; then
        LIB_PATH="$p"
        break
    fi
done

if [ -z "$LIB_PATH" ]; then
    LIB_PATH="/usr/lib/softhsm/libsofthsm2.so" # default fallback
fi

# 4. Tạo cặp khóa RSA 2048-bit bên trong HSM
if command -v pkcs11-tool &> /dev/null; then
    echo "🔑 Đang tạo cặp khóa RSA trong HSM..."
    pkcs11-tool --module "$LIB_PATH" --login --pin 123456 --keypairgen --key-type EC:prime256v1 --label "mykey" --id 01
    echo "========================================"
    echo "🛡️  HSM SETUP COMPLETED"
    echo "========================================"
else
    echo "⚠️  Cảnh báo: Lệnh pkcs11-tool không tìm thấy. Không thể tạo khóa HSM."
fi
