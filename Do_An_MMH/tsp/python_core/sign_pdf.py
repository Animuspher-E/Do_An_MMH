import sys
import os
import io

# Cấu hình UTF-8 cho stdout/stderr để tránh lỗi UnicodeEncodeError trên Windows
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')
if hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8')

def sign_pdf_with_p12(input_pdf_path, output_pdf_path, p12_path, p12_password):
    print(f"--- Bắt đầu ký PDF ---")
    
    try:
        from pyhanko.sign import signers
        from pyhanko.sign.timestamps import HTTPTimeStamper
        from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter

        if not os.path.exists(input_pdf_path) or not os.path.exists(p12_path):
            print("Lỗi: Không tìm thấy file đầu vào hoặc file P12")
            return False

        print("Đang nạp chứng chỉ...")
        signer = signers.SimpleSigner.load_pkcs12(
            pfx_file=p12_path,
            passphrase=p12_password
        )

        print("Đang ký...")
        with open(input_pdf_path, 'rb') as doc:
            pdf_writer = IncrementalPdfFileWriter(doc)
            
            # FIX ĐÚNG: Dùng output=BytesIO() để bắt toàn bộ kết quả ký
            out_buf = io.BytesIO()
            try:
                print("Đang kết nối TSA...")
                timestamper = HTTPTimeStamper(
                    "http://freetsa.org/tsr"
                )

                signers.sign_pdf(
                    pdf_writer,
                    signers.PdfSignatureMetadata(field_name='Signature1'),
                    signer=signer,
                    timestamper=timestamper,
                    in_place=False,
                    output=out_buf
                )
            except Exception:
                print("⚠️ Chuyển sang chế độ ký dự phòng")
                # Khởi tạo lại buffer nếu lệnh ký TSA bị lỗi giữa chừng
                out_buf = io.BytesIO()
                signers.sign_pdf(
                    pdf_writer,
                    signers.PdfSignatureMetadata(field_name='Signature1'),
                    signer=signer,
                    in_place=False,
                    output=out_buf
                )
        
        # Ghi buffer ra file đầu ra
        out_buf.seek(0)
        with open(output_pdf_path, 'wb') as f:
            f.write(out_buf.read())
                
        print(f"✅ Ký thành công: {output_pdf_path}")
        return True

    except Exception as e:
        print(f"❌ LỖI: {str(e)}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    if len(sys.argv) >= 5:
        # sys.argv[4] là password, cần encode sang bytes cho SimpleSigner
        success = sign_pdf_with_p12(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4].encode())
        sys.exit(0 if success else 1)
    else:
        sys.exit(1)