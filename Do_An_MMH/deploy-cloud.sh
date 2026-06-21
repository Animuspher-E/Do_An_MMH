#!/bin/bash
# Script tự động triển khai Hệ thống Ký số hai lớp (Do_An_MMH) trên Ubuntu Server
# Hỗ trợ tự động cấu hình PM2, Systemd OPA, Systemd OCSP và Nginx Reverse Proxy.

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "================================================================="
echo "🚀 BẮT ĐẦU CÀI ĐẶT HỆ THỐNG KÝ SỐ TRÊN CLOUD VM (UBUNTU SERVER) 🚀"
echo "================================================================="

# 1. Cập nhật hệ thống
echo "Updating packages..."
sudo apt-get update -y

# 2. Cài đặt Node.js 20 LTS
echo "Installing Node.js 20..."
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt-get install -y nodejs

# 3. Cài đặt các công cụ và thư viện hạ tầng
echo "Installing Python, OpenSSL, SoftHSM2, Nginx, Certbot, SQLite3..."
sudo apt-get install -y python3 python3-pip python3-venv openssl softhsm2 opensc nginx certbot python3-certbot-nginx git sqlite3

# 4. Tải OPA (Open Policy Agent)
echo "Installing Open Policy Agent (OPA)..."
sudo curl -L -o /usr/local/bin/opa https://openpolicyagent.org/downloads/v0.61.0/opa_linux_amd64_static
sudo chmod +x /usr/local/bin/opa

# 5. Thiết lập thư mục và cấu hình Node.js backend
echo "Setting up Node.js Backend..."
cd "$SCRIPT_DIR/portal/backend"
npm install

# Xóa file SSL self-signed cũ nếu có để Node chạy HTTP cổng 3000 (Nginx sẽ xử lý HTTPS)
rm -f server.key server.cert

# 6. Thiết lập môi trường Python ảo cho ký PDF
echo "Setting up Python virtual environment..."
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r ../../tsp/python_core/requirements.txt
deactivate

# 7. Cấu hình SoftHSM2 và tạo CA
echo "Setting up SoftHSM2 and CA Authorities..."
cd "$SCRIPT_DIR"
chmod +x ca-infrastructure/setup-hsm.sh
./ca-infrastructure/setup-hsm.sh

# 8. Cấu hình PM2 để quản lý Node.js Backend
echo "Configuring PM2 for Node.js Server..."
sudo npm install -g pm2
cd "$SCRIPT_DIR/portal/backend"
# Xóa PM2 process cũ nếu tồn tại trước khi khởi chạy lại để tránh lỗi "Script already launched"
pm2 delete node-portal || true
# Chạy ứng dụng thông qua PM2 (Sử dụng HTTP_ONLY=true để tránh tự sinh SSL trên Node khi đã dùng Nginx)
OPA_URL="http://127.0.0.1:8181" HTTP_ONLY="true" pm2 start server.js --name "node-portal"
pm2 save
sudo env PATH=$PATH:/usr/bin pm2 startup systemd -u ubuntu --hp /home/ubuntu

# 9. Cấu hình dịch vụ Systemd cho OPA
echo "Configuring Systemd for OPA..."
sudo bash -c "cat > /etc/systemd/system/opa.service <<EOF
[Unit]
Description=Open Policy Agent Service
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/opa run --server --addr=127.0.0.1:8181 $SCRIPT_DIR/portal/policies
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF"

sudo systemctl daemon-reload
sudo systemctl enable opa
sudo systemctl restart opa

# 10. Cấu hình dịch vụ Systemd cho OCSP Responder
echo "Configuring Systemd for OCSP Responder..."
sudo bash -c "cat > /etc/systemd/system/ocsp.service <<EOF
[Unit]
Description=OpenSSL OCSP Responder
After=network.target

[Service]
Type=simple
WorkingDirectory=$SCRIPT_DIR
ExecStart=/bin/bash $SCRIPT_DIR/ca-infrastructure/ocsp/start-ocsp.sh
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF"

sudo systemctl daemon-reload
sudo systemctl enable ocsp
sudo systemctl restart ocsp

echo "================================================================="
echo "🎉 ĐÃ CÀI ĐẶT XONG CÁC DỊCH VỤ HẠ TẦNG (NODE, OPA, OCSP, SoftHSM) 🎉"
echo "================================================================="
echo "👉 CÁC BƯỚC TIẾP THEO BẠN CẦN LÀM:"
echo "1. Cấu hình Nginx Reverse Proxy:"
echo "   Sử dụng tên miền DuckDNS của bạn để cấu hình file /etc/nginx/sites-available/signing-system"
echo "2. Chạy Certbot để kích hoạt HTTPS Let's Encrypt:"
echo "   sudo certbot --nginx -d <your-domain>.duckdns.org"
echo "================================================================="
