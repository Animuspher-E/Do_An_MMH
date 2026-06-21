provider "aws" {
  region = "ap-southeast-1" # Khu vực Singapore (gần Việt Nam nhất để giảm độ trễ)
}

# 1. Tạo Security Group để mở các cổng cần thiết cho đồ án
resource "aws_security_group" "nt219_sg" {
  name        = "nt219-security-group"
  description = "Allow traffic for Web Portal, OPA, and OCSP Responder"

  # Cổng 22: SSH quản trị từ xa
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # Cổng 3000: Web Portal (Giao diện chính công dân & cán bộ)
  ingress {
    from_port   = 3000
    to_port     = 3000
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # Cổng 8888: OpenSSL OCSP Responder (Kiểm tra trạng thái thu hồi)
  ingress {
    from_port   = 8888
    to_port     = 8888
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # Cổng 8181: OPA Server (Mở ra ngoài để kiểm tra hoặc chặn lại nếu chạy nội bộ)
  ingress {
    from_port   = 8181
    to_port     = 8181
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # Cho phép mọi traffic đi ra ngoài
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# 2. Định nghĩa máy chủ ảo EC2 (Thuộc gói Free Tier của AWS)
resource "aws_instance" "nt219_server" {
  ami           = "ami-01811d4912b4ccb26" # Ubuntu 22.04 LTS tại ap-southeast-1
  instance_type = "t2.micro"             # Đủ điều kiện AWS Free Tier (Miễn phí 750 giờ/tháng)

  security_groups = [aws_security_group.nt219_sg.name]
  key_name        = "nt219-key" # Thay thế bằng tên Key Pair bạn tạo trên AWS Console

  # Script tự động chạy cài đặt toàn bộ môi trường khi máy ảo được khởi tạo
  user_data = <<-EOF
              #!/bin/bash
              sudo apt-get update -y
              
              # Cài đặt Node.js 20 LTS và NPM
              curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
              sudo apt-get install -y nodejs
              
              # Cài đặt Python3, Pip, Venv, OpenSSL, SoftHSM2, OpenSC
              sudo apt-get install -y python3 python3-pip python3-venv openssl softhsm2 opensc git
              
              # Tải và cài đặt Open Policy Agent (OPA)
              curl -L -o /usr/local/bin/opa https://openpolicyagent.org/downloads/v0.61.0/opa_linux_amd64_static
              chmod +x /usr/local/bin/opa
              
              echo "======== SETUP COMPLETED ========"
              EOF

  tags = {
    Name = "NT219-SigningSystem-Server"
  }
}

# 3. Xuất ra địa chỉ IP công cộng của máy chủ sau khi tạo xong
output "public_ip" {
  value       = aws_instance.nt219_server.public_ip
  description = "Địa chỉ IP Public của máy chủ EC2 để truy cập"
}
