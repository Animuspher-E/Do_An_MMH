import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def generate_key():
    return AESGCM.generate_key(bit_length=256)

def encrypt_file(key: bytes, in_filename: str, out_filename: str):
    aesgcm = AESGCM(key)
    nonce = os.urandom(12) # Sinh Nonce ngẫu nhiên (96-bit là chuẩn an toàn cho AES-GCM)
    
    with open(in_filename, 'rb') as f:
        data = f.read()
        
    # Dữ liệu mã hoá sẽ tự dính kèm luôn chuỗi tag xác thực toàn vẹn (Authentication Tag) ở đuôi
    ciphertext = aesgcm.encrypt(nonce, data, None)
    
    with open(out_filename, 'wb') as f:
        f.write(nonce)
        f.write(ciphertext)
    print(f"File {in_filename} encrypted to {out_filename} successfully.")

def decrypt_file(key: bytes, in_filename: str, out_filename: str):
    aesgcm = AESGCM(key)
    
    with open(in_filename, 'rb') as f:
        content = f.read()
        
    nonce = content[:12]
    ciphertext = content[12:]
    
    try:
        # Giải mã và xác thực. Nếu tag bị đổi hoặc sai key, sẽ ném ra exception ngay lập tức
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        with open(out_filename, 'wb') as f:
            f.write(plaintext)
        print(f"File {in_filename} decrypted to {out_filename} successfully.")
    except Exception as e:
        print(f"Decryption failed (Tamper detected or Wrong Key!): {e}")

if __name__ == "__main__":
    # Quá trình mô phỏng chạy thử module bảo mật kênh truyền (Task B3 target)
    print("=== AES-GCM Encrypt/Decrypt Simulation ===")
    test_key = generate_key()
    
    # tạo file trắng giả lập để test lập trình
    with open("dummy.pdf", "w") as f:
        f.write("Fake PDF Document Content")
        
    encrypt_file(test_key, "dummy.pdf", "dummy.pdf.enc")
    decrypt_file(test_key, "dummy.pdf.enc", "dummy_restored.pdf")
