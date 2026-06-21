#!/bin/bash
# Script khởi tạo SoftHSM2 bền bỉ cho đồ án NT219

# 1. Tạo thư mục cấu hình nếu chưa có
mkdir -p /app/storage/softhsm2/tokens

# 2. Thiết lập biến môi trường cho SoftHSM2
export SOFTHSM2_CONF=/app/storage/softhsm2/softhsm2.conf
echo "directories.tokendir = /app/storage/softhsm2/tokens" > $SOFTHSM2_CONF

# 3. Khởi tạo Token (Slot 0) với nhãn CloudHSM
# Sử dụng 'if command -v' để kiểm tra xem softhsm2-util đã được cài đặt chưa
if command -v softhsm2-util &> /dev/null; then
    echo "⚒️  Đang khởi tạo SoftHSM Token..."
    softhsm2-util --init-token --free --label "CloudHSM" --so-pin 12345678 --pin 123456
else
    echo "⚠️  Cảnh báo: Lệnh softhsm2-util không tìm thấy. HSM chưa được cài đặt."
fi

# 4. Tạo cặp khóa RSA 2048-bit bên trong HSM
if command -v pkcs11-tool &> /dev/null; then
    echo "🔑 Đang tạo cặp khóa RSA trong HSM..."
    pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so --login --pin 123456 --keypairgen --key-type rsa:2048 --label "mykey" --id 01
    echo "========================================"
    echo "🛡️  HSM SETUP COMPLETED"
    echo "========================================"
else
    echo "⚠️  Cảnh báo: Lệnh pkcs11-tool không tìm thấy. Không thể tạo khóa HSM."
fi
