# ARCHITECTURE - Digital Signature (NT219 Project)

Tài liệu này cung cấp cái nhìn tổng quan về kiến trúc của đồ án Ký số. 

## 1. Cấu Trúc Thư Mục (Directory Tree)

Hệ thống được tổ chức thành 4 phân khu rành mạch:
```text
NT219_Final_Project/
│
├── backend/                       # Giao diện lập trình cổng 3000 (Vai trò Hệ thống chính)
│   ├── package.json               # Liệt kê các thư viện npm (pdf-lib, express)
│   ├── server.js                  # Điểm khởi chạy của Backend (Chứa các API HTTP)
│   │
│   ├── models/                    # Tầng Cơ Sở Dữ Liệu
│   │   └── database.js            # Chứa các biến dữ liệu dạng HardCode (Mock Db)
│   │
│   └── utils/                     # Tầng Công Cụ Bổ Trợ
│       └── logger.js              # Mô-đun phụ trách ghi tệp Audit vào File (Lưu log giao dịch)
│
├── frontend/                      # Tầng UI hiển thị người dùng (Tách rời khỏi Backend Node)
│   └── index.html                 # Giao diện thao tác bằng HTML tĩnh
│
├── python_core/                   # Tầng Nghiệp Vụ Python Nâng Cao
│   ├── sign_pdf.py                # Trình điều khiển nhúng Cryptography PyHanko & FreeTSA 
│   ├── verify_pdf.py              # Bộ đánh giá mã hóa OCSP & TrustRoot Verification
│   ├── aes_gcm.py                 # Phục vụ mã hóa nội dung truyền tải bí mật
│   └── fix_*.py                   # Các file config hệ thống cấp độ thấp
│
└── storage/                       # Kho Lưu Trữ Dùng Chung (Ổ cứng)
    ├── ca-authority/              # Chứa file CA (Chữ ký nhà phát hành)
    ├── keystore/                  # Keys local
    └── signed_documents/          # Thư mục lưu sản phẩm PDF đầu ra
```


---

## 2. Mô Tả Vai Trò Các Thư Mục (Layered Roles)

- `backend/`: **Application/Gateway Layer** (Tầng Ứng dụng/Cổng Kết Nối). Nhiệm vụ của nó là lắng nghe kết nối HTTP qua Port 3000 (Cổng giao tiếp của Thiện), chặn và cho phép đường đi (Routing/Middleware), sau đó gọi vào Logic Nghiệp vụ.
- `python_core/`: **Core Domain Services** (Dịch vụ Đám Mây). Đóng vai trò là cỗ máy Mật mã tĩnh, chỉ được khởi động và sử dụng lệnh Console System từ NodeJS. Nổi bật nhất là tính năng cấy thẳng PKCS7 vào lòng file PDF - tính năng mà `pdf-lib` của Backend Web không khả thi.
- `storage/`: Đóng vai trò như **Database Filesystem**. Cả Node.js (Thiện) và Python (Thành) điều đọc và ghi vào đây nhằm giảm thiểu sự tranh chấp dữ liệu qua mạng bộ nhớ (RAM).
- `frontend/`: Cấu thành **Presentation Layer** (Tầng Biểu diễn) - Trạm đưa đón Request để truyền lên tầng Cổng. 

---

## 3. Bản Đồ Luồng Hoạt Động (Request Lifecycle)

### A. Sơ Đồ Cấu Trúc Khối (Architecture Flow Diagram)
```text
Người dùng Upload PDF
      │
      ▼
[ FRONTEND ] ────(HTTP POST `/api/upload-pdf`)─────┐
(index.html)                                       │ (1. Đọc Hash, Móc File)
      │                                            ▼
      │                                   [ BỘ LỌC CỔNG ] (Middleware OPA / DPoP)
      │                                            │ (2. Chặn Replay Attack)
      │                                            ▼
[ CỤM PYTHON ] ◀──(Call Sys)─── [ BACKEND CONTROLLER ] (server.js)
(sign_pdf.py)      (4. Hook Python)                │ (3. HSM Core PKCS11 của Node)
      │                                            ▼
      │                                 [ LƯU DỰ KIẾN (Temp) ]
      ▼                                      (pdf-lib rectangle seal)
[ DATABASE Ổ CỨNG ] ◀────────── (Ghi đè file thật)
(storage/signed_documents/X.pdf) 
```

### B. Giải Nghĩa Luồng Đi Lệnh `Upload & Sign` (Ký điện tử)
1. **[Request]** Người dùng (Citizen) đẩy một file PDF từ trang *index.html* qua giao thức Fetch. HTTP mang thông điệp `documentHash` lên Backend theo Endpoint `/api/remote-sign`.
2. **[Middleware Check]** NodeJS kiểm tra RAM `models/database.js` để tìm định danh của người dùng. Kiểm tra `nonce` đã tiêu thụ hay chưa.
3. **[Server PKCS11]** Node gọi lệnh thư viện `graphene-pk11` vào SoftHSM để đẻ ra mã Signature Base64 cục bộ (Logic cũ). Khắc chữ lên file PDF.
4. **[Python Microservices !Thành]** Ngôn ngữ Node có giới hạn về việc gói dữ liệu Timestamp PKCS7. Ở đây, Node khởi chạy Background Command (lệnh Python). Lệnh này đâm xuyên xuống thư mục `storage`, móc file PDF đó ra. `sign_pdf.py` sử dụng Cryptography đóng gói kỹ thuật cao và dán nhãn TS, sau đó ghi đè vô file `X.pdf`.
5. **[Response]** Node trả về thông điệp JSON báo hiệu File đúc thành công và gửi URL Tải về.

Hệ thống tuân thủ nghiêm ngặt mô hình rẽ nhánh, Node.js giữ vai trò Cổng (Router), Python giữ vai trò Cơ khí Chỉnh lý Mật Mã (Cryptography Worker). Code không hề giẫm vào vùng nhớ của nhau.
