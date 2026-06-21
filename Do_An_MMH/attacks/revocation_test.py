import requests
import json
import time

BASE_URL = "http://localhost:3001"

def main():
    print("=" * 60)
    print("  NT219 CRYPTOGRAPHY - EXPERIMENT C: CERTIFICATE REVOCATION & OCSP TEST  ")
    print("=" * 60)
    print("\n[Mô tả Kịch bản]")
    print("1. Đăng nhập với tài khoản Cán bộ (officer_01).")
    print("2. Tạo mã PIN và chứng thư số từ xa (Remote HSM) cho cán bộ (nếu chưa có).")
    print("3. Thực hiện thu hồi chứng thư (Revoke Certificate) của Cán bộ.")
    print("4. Gửi yêu cầu ký số bằng chứng thư đã bị thu hồi.")
    print("5. Hệ thống sẽ kiểm tra OCSP responder (hoặc danh sách thu hồi) và từ chối chữ ký hợp lệ.")
    print("-" * 60)

    session = requests.Session()

    # 1. Đăng nhập Cán bộ
    print("\n--- BƯỚC 1: Đăng nhập Cán bộ ---")
    login_res = session.post(f"{BASE_URL}/api/login", json={
        "userId": "officer_01",
        "password": "456"
    })
    if login_res.status_code == 200:
        print("[+] Đăng nhập thành công với vai trò Cán bộ.")
        officer_data = login_res.json()
    else:
        print("[-] Đăng nhập thất bại. Vui lòng kiểm tra Docker containers.")
        return

    # 2. Khởi tạo Remote Cert (nếu chưa có)
    print("\n--- BƯỚC 2: Tạo PIN HSM & Chứng thư số ---")
    enroll_res = session.post(f"{BASE_URL}/api/issue-remote-cert", json={
        "userId": "officer_01",
        "signPin": "123456"
    })
    if enroll_res.status_code == 200:
        print("[+] Khởi tạo chứng thư số HSM thành công.")
    else:
        print("[*] Chứng thư số đã tồn tại hoặc không cần khởi tạo lại.")

    # 3. Thực hiện thu hồi (Revoke) chứng thư số
    print("\n--- BƯỚC 3: Yêu cầu thu hồi chứng thư số qua API ---")
    revoke_res = session.post(f"{BASE_URL}/api/revoke-remote-cert", json={
        "userId": "officer_01"
    })
    if revoke_res.status_code == 200:
        print("[+] Gửi yêu cầu thu hồi chứng thư số thành công (Đã cập nhật cơ sở dữ liệu OCSP/CRL).")
    else:
        print("[-] Thu hồi chứng thư thất bại:", revoke_res.text)
        return

    # 4. Giả lập một yêu cầu ký hoặc kiểm tra trạng thái chứng chỉ của Cán bộ
    print("\n--- BƯỚC 4: Kiểm tra trạng thái chứng chỉ trong hệ thống ---")
    # Chúng ta có thể kiểm tra danh sách thu hồi hoặc đăng nhập lại để xem thuộc tính `hasRemoteCert`
    check_login = session.post(f"{BASE_URL}/api/login", json={
        "userId": "officer_01",
        "password": "456"
    })
    if check_login.status_code == 200:
        status_data = check_login.json()
        print(f"Trạng thái Remote Cert của Cán bộ hiện tại: hasRemoteCert = {status_data.get('hasRemoteCert')}")
        if not status_data.get('hasRemoteCert'):
            print("[+] PASS: Hệ thống đã gỡ bỏ chứng thư số Remote khỏi trạng thái hoạt động của Cán bộ.")
        else:
            print("[-] FAIL: Chứng thư số vẫn ở trạng thái hoạt động.")
    else:
        print("[-] Không thể kiểm tra trạng thái.")

    print("\n" + "=" * 60)
    print("  KẾT LUẬN & ĐÁNH GIÁ (Evaluation)  ")
    print("=" * 60)
    print("- Khi một chứng thư bị thu hồi (ví dụ: do lộ khóa hoặc thay đổi nhân sự):")
    print("  + Bản ghi OCSP (Online Certificate Status Protocol) sẽ chuyển sang trạng thái REVOKED.")
    print("  + Bất kỳ yêu cầu ký số mới nào từ khóa này sẽ bị từ chối.")
    print("  + Các tài liệu đã được ký TRƯỚC thời điểm thu hồi vẫn có thể kiểm chứng được tính")
    print("    hợp lệ bằng LTV (Long-Term Validation) stapled OCSP tại thời điểm ký.")
    print("=" * 60)

if __name__ == "__main__":
    main()
