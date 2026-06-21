import sys
import os
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign.validation import ValidationContext, validate_pdf_signature
from pyhanko.keys import load_certs_from_pemder
import logging
logging.disable(logging.CRITICAL)

script_dir = os.path.dirname(os.path.abspath(__file__))
CA_DIR = os.path.abspath(os.path.join(script_dir, "../../ca-infrastructure/storage/ca-authority"))

def verify_pdf(pdf_path):
    try:
        trust_roots_list = []
        root_ca = os.path.join(CA_DIR, "rootCA.pem")
        sub_ca = os.path.join(CA_DIR, "subCA.pem")
        if os.path.exists(root_ca):
            trust_roots_list.extend(load_certs_from_pemder([root_ca]))
        if os.path.exists(sub_ca):
            trust_roots_list.extend(load_certs_from_pemder([sub_ca]))

        with open(pdf_path, 'rb') as doc:
            pdf_reader = PdfFileReader(doc)
            embedded_sigs = pdf_reader.embedded_signatures
            if not embedded_sigs:
                print("❌ Kết quả: Không tìm thấy chữ ký số.")
                return False
                
            all_valid = True
            for i, sig in enumerate(embedded_sigs):
                print(f"\n--- Đang kiểm tra Chữ ký {i+1} ---")
                
                context = ValidationContext(
                    trust_roots=trust_roots_list,
                    allow_fetching=False
                )
                
                import io as _io
                old_stderr = sys.stderr
                sys.stderr = _io.StringIO()
                try:
                    status = validate_pdf_signature(sig, context)
                finally:
                    sys.stderr = old_stderr
                try:
                    print("Timestamp valid:", status.timestamp_validity is not None)
                except Exception as e:
                    print("Timestamp check error:", e)
                print(f"Toàn vẹn dữ liệu (Intact): {'Hợp lệ' if status.intact else 'Bị sửa đổi'}")
                print(f"Xác thực mật mã (Valid): {'Thành công' if status.valid else 'Thất bại'}")
                
                # Trích xuất tên người ký từ nhiều nguồn
                signer_name = None
                try:
                    # Thử qua embedded sig object
                    cert = sig.signer_cert
                    if cert is not None:
                        # Ưu tiên lấy Common Name (CN)
                        cn = cert.subject.human_friendly
                        signer_name = cn
                except Exception:
                    pass
                
                if not signer_name:
                    try:
                        # Thử qua CMS structure
                        signed_data = sig.signed_data
                        cert_list = getattr(signed_data, 'certs', None) or signed_data.get('certificates', None)
                        if cert_list:
                            signer_name = cert_list[0].chosen.subject.human_friendly
                    except Exception:
                        pass
                
                print(f"Người ký (Signer): {signer_name if signer_name else 'Không xác định'}")
                
                if not (status.intact and status.valid):
                    all_valid = False

            if all_valid:
                print("\n==> Result: VALID")
                return True
            else:
                print("\n==> Result: INVALID")
                return False
                    
    except Exception as e:
        print(f"❌ LỖI HỆ THỐNG KHI XÁC THỰC: {str(e)}")
        print("\n==> Result: INVALID")
        return False

if __name__ == "__main__":
    if len(sys.argv) > 1:
        verify_pdf(sys.argv[1])
    else:
        sys.exit(1)
