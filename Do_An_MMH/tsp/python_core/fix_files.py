from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography import x509
from cryptography.x509.oid import NameOID
import datetime

key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, u"Thanh Test")])
cert = x509.CertificateBuilder().subject_name(
    subject
).issuer_name(
    issuer
).public_key(
    key.public_key()
).serial_number(
    123456789  # matching the mock OCSP in verify_pdf
).not_valid_before(
    datetime.datetime.now(datetime.timezone.utc)
).not_valid_after(
    datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=10)
).sign(key, hashes.SHA256())

import cryptography.hazmat.primitives.serialization.pkcs12 as pkcs12
p12 = pkcs12.serialize_key_and_certificates(b"test", key, cert, None, serialization.BestAvailableEncryption(b"secret"))
with open("test_cert.p12", "wb") as f:
    f.write(p12)
print("Updated test_cert.p12 with cryptography")

# Sinh một tệp PDF chuẩn từ chuỗi base64 để phục vụ việc test ký số
import base64
valid_pdf_b64 = "JVBERi0xLjEKJcKlwrQKMSAwIG9iagogIDw8IC9UeXBlIC9DYXRhbG9nCiAgICAgL1BhZ2VzIDIgMCBSCiAgPj4KZW5kb2JqCjIgMCBvYmoKICA8PCAvVHlwZSAvUGFnZXMKICAgICAvS2lkcyBbMyAwIFJdCiAgICAgL0NvdW50IDEKICAgICAvTWVkaWFCb3ggWzAgMCAzMDAgMTQ0XQogID4+CmVuZG9iagozIDAgb2JqCiAgPDwgL1R5cGUgL1BhZ2UKICAgICAvUGFyZW50IDIgMCBSCiAgICAgL1Jlc291cmNlcwogICAgICA8PCAvRm9udAogICAgICAgICAgIDw8IC9GMQogICAgICAgICAgICAgICA8PCAvVHlwZSAvRm9udAogICAgICAgICAgICAgICAgICAvU3VidHlwZSAvVHlwZTEKICAgICAgICAgICAgICAgICAgL0Jhc2VGb250IC9UaW1lcy1Sb21hbgogICAgICAgICAgICAgICA+PgogICAgICAgICAgID4+CiAgICAgID4+CiAgICAgL0NvbnRlbnRzIDQgMCBSCiAgPj4KZW5kb2JqCjQgMCBvYmoKICA8PCAvTGVuZ3RoIDU2ID4+CnN0cmVhbQogIEJUCiAgICAvRjEgMTggVGYKICAgIDAgMHRkCiAgICAoSGVsbG8gV29ybGQpIFRqCiAgRVQKZW5kc3RyZWFtCmVuZG9iagp4cmVmCjAgNQowMDAwMDAwMDAwIDY1NTM1IGYgCjAwMDAwMDAwMTggMDAwMDAgbiAKMDAwMDAwMDA3NyAwMDAwMCBuIAowMDAwMDAwMTc4IDAwMDAwIG4gCjAwMDAwMDA0NTggMDAwMDAgbiAKdHJhaWxlcgogIDw8ICAvUm9vdCAxIDAgUgogICAgICAvU2l6ZSA1CiAgPj4Kc3RhcnR4cmVmCjU2NQolJUVPRgo="
with open("test_in.pdf", "wb") as f:
    f.write(base64.b64decode(valid_pdf_b64))
print("Updated test_in.pdf to a valid structure")
