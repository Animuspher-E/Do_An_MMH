# Hướng Dẫn Triển Khai Hệ Thống Ký Số Lên Cloud Miễn Phí & Cấu Hình HTTPS Hợp Lệ

Tài liệu này cung cấp hướng dẫn chi tiết từng bước giúp bạn triển khai hệ thống ký số hai lớp (`Do_An_MMH`) lên máy chủ đám mây miễn phí và thiết lập chứng chỉ **HTTPS xanh lá thực sự** (không bị cảnh báo bảo mật) một cách nhanh chóng nhất.

---

## 💡 Lựa chọn 1: Demo Nhanh Trong 5 Phút (Chạy Localhost - Public bằng HTTPS Tunnel)

Nếu bạn cần demo gấp cho giảng viên hoặc hội đồng nghiệm thu mà **không muốn đăng ký thẻ Visa, không muốn tạo máy ảo Cloud phức tạp**, bạn có thể đưa ứng dụng chạy tại localhost lên Internet dưới dạng HTTPS bằng **ngrok** hoàn toàn miễn phí.

### Bước 1: Khởi động các dịch vụ ở local
Đảm bảo bạn đã chạy đầy đủ các dịch vụ ở máy tính cá nhân bằng HTTP/HTTPS thông thường:
- **Web Portal Server**: Chạy trên cổng `3000`
- **OCSP Responder**: Chạy trên cổng `8888`
- **OPA Server**: Chạy trên cổng `8181`

### Bước 2: Cài đặt và chạy ngrok
1. Tải ngrok cho hệ điều hành của bạn từ trang chủ [ngrok.com](https://ngrok.com/) và đăng ký một tài khoản miễn phí để lấy **Authtoken**.
2. Thêm Authtoken vào máy của bạn:
   ```bash
   ngrok config add-authtoken <TOKEN_CỦA_BẠN>
   ```
3. Khởi tạo đường hầm HTTPS trỏ về Web Portal Server (cổng 3000):
   ```bash
   ngrok http 3000
   ```
   *Ngrok sẽ cung cấp cho bạn một URL có định dạng: `https://xxxx-xxxx-xxxx.ngrok-free.app`*

4. Khởi tạo đường hầm thứ hai cho OCSP Responder (cổng 8888) nếu bạn muốn xác thực chứng chỉ từ xa (mở một terminal mới):
   ```bash
   ngrok http 8888
   ```
   *Lấy URL HTTPS của OCSP, ví dụ: `https://yyyy-yyyy-yyyy.ngrok-free.app`*

### Bước 3: Cấu hình Client Agent kết nối đến Ngrok
Tại máy tính của Cán bộ (chạy Client Agent), cấu hình biến môi trường trỏ về URL ngrok của Portal:
- **Windows**:
  ```cmd
  set PORTAL_URL=https://xxxx-xxxx-xxxx.ngrok-free.app
  python agent.py
  ```
- **Linux/macOS**:
  ```bash
  export PORTAL_URL=https://xxxx-xxxx-xxxx.ngrok-free.app
  python agent.py
  ```
> [!TIP]
> Sử dụng ngrok là cách nhanh nhất và an toàn nhất để demo đồ án qua Internet vì bạn có ngay chứng chỉ HTTPS hợp lệ từ ngrok mà không cần cấu hình DNS hay cài đặt máy chủ.

---

## 🚀 Lựa chọn 2: Triển Khai Thực Tế Lên Cloud VM Miễn Phí + HTTPS Thật (Let's Encrypt)

Để triển khai một hệ thống chạy 24/7 chuyên nghiệp phục vụ đồ án, hãy thực hiện theo chuỗi 3 bước dưới đây: **Đăng ký Cloud -> Cấu hình Tên miền miễn phí -> Cài đặt HTTPS & Reverse Proxy**.

### BƯỚC 1: ĐĂNG KÝ VÀ KHỞI TẠO VPS CLOUD MIỄN PHÍ

Bạn có thể chọn một trong các nhà cung cấp đám mây lớn hỗ trợ sinh viên:

| Nhà cung cấp | Gói miễn phí (Free Tier) | Lưu ý |
| :--- | :--- | :--- |
| **Oracle Cloud** | **Always Free** (Được tạo tối đa 2 VM AMD hoặc 1 VM ARM cấu hình mạnh lên tới 4 OCPUs, 24GB RAM). | Rất khuyên dùng cho đồ án lâu dài. Đăng ký đôi khi hơi khó (cần thẻ Visa/Mastercard để xác minh $1). |
| **AWS (Amazon Web Services)** | **12 tháng miễn phí** với cấu hình máy ảo `t2.micro` hoặc `t3.micro` (1 vCPU, 1GB RAM). | Cực kỳ phổ biến. Dễ đăng ký hơn Oracle. Cần thẻ Visa để kích hoạt. |
| **Google Cloud (GCP)** | **Always Free** máy ảo `e2-micro` (chỉ áp dụng tại một số khu vực của Mỹ: Oregon, Iowa, South Carolina). | Miễn phí trọn đời nhưng dung lượng RAM hơi thấp (1GB RAM). |

> [!IMPORTANT]
> Khi tạo máy ảo trên Cloud, hệ điều hành khuyến nghị là **Ubuntu Server 22.04 LTS**.
> Nhớ cấu hình **Security Group / Firewall Rules** trên trang quản trị Cloud để mở các cổng sau ra Internet:
> - **22** (SSH quản trị)
> - **80** (HTTP - dùng để xác thực chứng chỉ SSL)
> - **443** (HTTPS - giao diện chính của hệ thống sau khi có SSL)
> - **8888** (OCSP Responder - để kiểm tra trạng thái chứng chỉ số)

---

### BƯỚC 2: KHỞI TẠO TÊN MIỀN MIỄN PHÍ VỚI DUCKDNS

Vì Let's Encrypt không cấp chứng chỉ HTTPS cho địa chỉ IP thô (raw IP), bạn bắt buộc phải có một tên miền trỏ về IP máy ảo Cloud của mình. **DuckDNS** là dịch vụ miễn phí và nhanh nhất để làm việc này.

1. Truy cập vào trang web [duckdns.org](https://www.duckdns.org/) và đăng nhập bằng tài khoản Google hoặc GitHub.
2. Tại mục **subdomains**, nhập tên miền mong muốn của bạn (ví dụ: `nt219-signing`) và nhấn **add domain**.
3. Điền địa chỉ **Public IP** của máy ảo Cloud của bạn vào ô IP và nhấn **update ip**.
4. Lúc này bạn đã sở hữu tên miền hoàn toàn miễn phí: `nt219-signing.duckdns.org` trỏ trực tiếp về máy chủ của bạn!

---

### BƯỚC 3: CÀI ĐẶT HỆ THỐNG TRÊN CLOUD & CẤU HÌNH HTTPS BẰNG NGINX REVERSE PROXY

Thay vì chạy HTTPS trực tiếp trên Node.js (dễ gặp lỗi quyền truy cập cổng 443 và lỗi chứng chỉ tự ký), mô hình chuẩn công nghiệp là: **Nginx đứng ở cổng 80/443 tiếp nhận HTTPS bảo mật, sau đó giải mã TLS và chuyển tiếp (Reverse Proxy) lưu lượng HTTP thông thường về Node.js (cổng 3000) đang chạy nội bộ.**

```
Internet (HTTPS) ---> Nginx (Port 443) ---> Node.js (Port 3000 - HTTP)
```

#### 1. Kết nối SSH vào máy ảo Cloud của bạn:
```bash
ssh -i "key-pair-cua-ban.pem" ubuntu@<PUBLIC_IP_MÁY_ẢO>
```

#### 2. Tải mã nguồn đồ án và chạy script cài đặt tự động:

Tôi đã chuẩn bị sẵn một script tự động [deploy-cloud.sh](file:///c:/Avalon/Code/NT219 Project/Do_An_MMH/Do_An_MMH/deploy-cloud.sh) trong thư mục gốc của dự án để tự động cấu hình toàn bộ hạ tầng (Node.js backend, môi trường ảo Python, SoftHSM2, OPA, OCSP, PM2). Bạn chỉ cần thực hiện:

- Clone mã nguồn đồ án của bạn vào thư mục `/home/ubuntu/Do_An_MMH`:
  ```bash
  git clone <URL_REPO_CỦA_BẠN> Do_An_MMH
  cd Do_An_MMH
  ```

- Phân quyền và chạy script cài đặt tự động:
  ```bash
  chmod +x deploy-cloud.sh
  ./deploy-cloud.sh
  ```

*Script sẽ tự động chạy trong khoảng 1-2 phút và cấu hình để các dịch vụ Web Portal, OPA, và OCSP chạy ngầm bền bỉ như các service hệ thống (tự động khởi động lại khi reboot).*

#### 5. Cấu hình Nginx làm Web Server và Reverse Proxy:

Tạo một cấu hình Nginx mới cho dự án:
```bash
sudo nano /etc/nginx/sites-available/signing-system
```
Dán cấu hình sau (thay đổi `nt219-signing.duckdns.org` thành tên miền của bạn):
```nginx
server {
    listen 80;
    server_name nt219-signing.duckdns.org;

    # Chuyển tiếp cổng 80/HTTPS -> Node.js Backend (Giao diện và API)
    location / {
        proxy_pass http://127.0.0.1:3000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_cache_bypass $http_upgrade;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # Tăng dung lượng tối đa file tải lên (Cần thiết khi upload file PDF lớn để ký)
        client_max_body_size 20M;
    }
}
```
Kích hoạt cấu hình mới và khởi động lại Nginx:
```bash
sudo ln -s /etc/nginx/sites-available/signing-system /etc/nginx/sites-enabled/
sudo rm -f /etc/nginx/sites-enabled/default
sudo nginx -t
sudo systemctl restart nginx
```

#### 6. Xin chứng chỉ SSL Let's Encrypt miễn phí và cấu hình HTTPS tự động:
Chạy Certbot để tự động đăng ký SSL và chèn cấu hình HTTPS vào Nginx:
```bash
sudo certbot --nginx -d nt219-signing.duckdns.org
```
*Nhập email của bạn, chọn đồng ý điều khoản, và chọn **`Redirect`** khi được hỏi để Certbot tự động cấu hình tự chuyển hướng tất cả lưu lượng HTTP thường sang HTTPS.*

Sau khi hoàn tất, hãy truy cập thử tên miền của bạn bằng trình duyệt:
👉 `https://nt219-signing.duckdns.org`
Bạn sẽ thấy biểu tượng **ổ khóa bảo mật màu xanh lá** (Chứng chỉ hợp lệ được cấp bởi Let's Encrypt).

---

### BƯỚC 4: LIÊN KẾT CLIENT AGENT Ở LOCAL VỚI CLOUD HTTPS

Trên máy tính cá nhân của Cán bộ (chạy Client Agent), bạn chỉ cần khởi tạo biến môi trường trỏ đến tên miền HTTPS của Cloud:

- **Windows**:
  ```cmd
  set PORTAL_URL=https://nt219-signing.duckdns.org
  python agent.py
  ```
- **Linux/macOS**:
  ```bash
  export PORTAL_URL=https://nt219-signing.duckdns.org
  python agent.py
  ```

Lúc này, toàn bộ quá trình ký số (gửi yêu cầu ký từ Web Portal trên Cloud xuống Local Agent, ký số bằng file khóa ảo `.p12` nội bộ, và gửi chữ ký ngược lại Cloud) sẽ diễn ra hoàn toàn qua giao thức **HTTPS bảo mật** mà không gặp bất kỳ lỗi Certificate Trust nào!
