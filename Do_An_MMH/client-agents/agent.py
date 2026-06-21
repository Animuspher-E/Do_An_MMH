import base64
import requests
import os
import hashlib
import tkinter as tk
from tkinter import simpledialog, filedialog, messagebox
from flask import Flask, request, jsonify
from flask_cors import CORS
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.hazmat.primitives.asymmetric import padding, ec, rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from cryptography.hazmat.primitives import serialization

app = Flask(__name__)
CORS(app)

# Cấu hình địa chỉ Portal Server (thay đổi nếu chạy trên các node mạng khác nhau)
PORTAL_URL = os.environ.get("PORTAL_URL", "https://localhost:3000")

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Biến toàn cục lưu đường dẫn file Cert hiện tại
CURRENT_P12 = ""

def select_p12_file():
    """Hàm bật cửa sổ chọn file .p12 và ép cửa sổ nổi lên trên cùng"""
    root = tk.Tk()
    root.withdraw()
    root.attributes('-topmost', True) # SỬA LỖI: Ép cửa sổ hiển thị trên cùng
    path = filedialog.askopenfilename(
        title="Chọn USB Token ảo mới (.p12)", 
        filetypes=[("PKCS12", "*.p12")]
    )
    root.destroy()
    return path

# Khởi tạo lần đầu khi chạy Agent
CURRENT_P12 = select_p12_file()
if not CURRENT_P12:
    print("❌ Lỗi: Bạn phải chọn file chứng chỉ để khởi động Agent.")
    exit()

def prompt_sign_gui(cert_name):
    """Hiển thị cửa sổ nhập PIN để ký số ML-DSA"""
    result = {"pin": None}
    
    root = tk.Tk()
    root.title("Xác thực Token - Local Agent")
    root.geometry("400x180")
    root.resizable(False, False)
    root.attributes('-topmost', True)
    
    # Căn giữa màn hình
    root.update_idletasks()
    width = root.winfo_width()
    height = root.winfo_height()
    x = (root.winfo_screenwidth() // 2) - (width // 2)
    y = (root.winfo_screenheight() // 2) - (height // 2)
    root.geometry(f'+{x}+{y}')
    
    # Giao diện
    tk.Label(root, text="Hệ thống Ký số Cán bộ (ML-DSA)", font=("Helvetica", 14, "bold"), fg="#1a5276").pack(pady=10)
    tk.Label(root, text=f"Token ảo: {cert_name}", font=("Helvetica", 10)).pack()
    
    # Nhập PIN
    pin_frame = tk.Frame(root)
    pin_frame.pack(pady=10)
    tk.Label(pin_frame, text="Nhập mã PIN: ", font=("Helvetica", 10, "bold")).pack(side=tk.LEFT)
    pin_entry = tk.Entry(pin_frame, show="*", width=15, font=("Helvetica", 10))
    pin_entry.pack(side=tk.LEFT)
    pin_entry.focus()
    
    def on_sign():
        result["pin"] = pin_entry.get()
        root.destroy()
        
    def on_cancel():
        root.destroy()
        
    btn_frame = tk.Frame(root)
    btn_frame.pack(pady=10)
    tk.Button(btn_frame, text="KÝ SỐ", command=on_sign, bg="#27ae60", fg="white", font=("Helvetica", 10, "bold"), width=10).pack(side=tk.LEFT, padx=10)
    tk.Button(btn_frame, text="HỦY", command=on_cancel, bg="#e74c3c", fg="white", font=("Helvetica", 10, "bold"), width=10).pack(side=tk.LEFT, padx=10)
    
    root.mainloop()
    return result

@app.route('/sign-request', methods=['POST'])
def handle_sign_request():
    global CURRENT_P12
    data = request.json
    doc_hash_hex = data.get('documentHash')
    file_id = data.get('fileId')

    # 1. Hiển thị Popup nhập PIN
    gui_res = prompt_sign_gui(os.path.basename(CURRENT_P12))
    pin = gui_res["pin"]
    algorithm = "ML-DSA (Kháng lượng tử FIPS 204)"

    if not pin: 
        return jsonify({"status": "CANCELLED", "message": "Hủy bởi người dùng"}), 401

    try:
        # 2. Đọc và ký với file hiện tại
        with open(CURRENT_P12, "rb") as f:
            private_key, cert, _ = pkcs12.load_key_and_certificates(f.read(), pin.encode())
        
        cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode('utf-8')
        
        if algorithm == "ML-DSA (Kháng lượng tử FIPS 204)":
            # Giả lập chữ ký số kháng lượng tử ML-DSA (CRYSTALS-Dilithium) FIPS 204
            pqc_secret = private_key.private_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            mldsa_sig_hash = hashlib.sha256(pqc_secret + bytes.fromhex(doc_hash_hex)).hexdigest()
            mldsa_sig = f"ML-DSA-65_FIPS-204_Signature_Value[{mldsa_sig_hash}]"
            signature = mldsa_sig.encode('utf-8')
        else:
            # ECDSA (hoặc RSA-PSS dự phòng)
            if isinstance(private_key, rsa.RSAPrivateKey):
                signature = private_key.sign(
                    bytes.fromhex(doc_hash_hex),
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=32
                    ),
                    Prehashed(hashes.SHA256())
                )
            elif isinstance(private_key, ec.EllipticCurvePrivateKey):
                signature = private_key.sign(
                    bytes.fromhex(doc_hash_hex),
                    ec.ECDSA(Prehashed(hashes.SHA256()))
                )
            else:
                raise TypeError("Loại khóa không được hỗ trợ!")
        
        # 3. Gửi sang Server xác thực
        res = requests.post(f"{PORTAL_URL}/api/verify-signature", json={
            "documentHash": doc_hash_hex,
            "signatureBase64": base64.b64encode(signature).decode('utf-8'),
            "certificatePEM": cert_pem,
            "fileId": file_id
        }, verify=False)
        
        response_data = res.json()

        # --- ĐOẠN XỬ LÝ CHỌN LẠI FILE NẾU BỊ THU HỒI ---
        if response_data.get('status') == 'FAILED' and "thu hồi" in response_data.get('message', '').lower():
            root = tk.Tk()
            root.withdraw()
            root.attributes('-topmost', True) # SỬA LỖI: Ép cửa sổ thông báo lên trên cùng
            messagebox.showwarning("Cảnh báo thu hồi", "Chứng chỉ hiện tại đã bị thu hồi (Revoked)!\nVui lòng chọn file chứng chỉ mới.")
            new_path = select_p12_file()
            root.destroy()
            
            if new_path:
                CURRENT_P12 = new_path
                print(f"🔄 Đã cập nhật Token mới: {os.path.basename(CURRENT_P12)}")
                return jsonify({"status": "RETRY_REQUIRED", "message": "Đã đổi Token thành công, vui lòng bấm Ký lại!"})
        
        return jsonify(response_data)
        
    except Exception as e:
        # Nếu sai PIN hoặc file lỗi
        return jsonify({"status": "ERROR", "message": "Mã PIN không chính xác hoặc Token bị lỗi!"}), 403

if __name__ == '__main__':
    print("========================================")
    print(f"🛡️  AGENT READY")
    print(f"📦 Token đang dùng: {os.path.basename(CURRENT_P12)}")
    print("========================================")
    app.run(port=5000)
