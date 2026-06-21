import time
import uuid
import json
import base64
import requests
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

BASE_URL = "http://localhost:3001"
TARGET_URL = f"{BASE_URL}/api/officer-remote-sign"


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def make_dpop_proof():
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    numbers = public_key.public_numbers()

    jwk = {
        "kty": "EC",
        "crv": "P-256",
        "x": b64url(numbers.x.to_bytes(32, "big")),
        "y": b64url(numbers.y.to_bytes(32, "big")),
        "alg": "ES256",
        "use": "sig"
    }

    header = {
        "typ": "dpop+jwt",
        "alg": "ES256",
        "jwk": jwk
    }

    payload = {
        "htm": "POST",
        "htu": TARGET_URL,
        "iat": int(time.time()),
        "jti": str(uuid.uuid4())
    }

    encoded_header = b64url(json.dumps(header, separators=(",", ":")).encode())
    encoded_payload = b64url(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{encoded_header}.{encoded_payload}".encode()

    der_sig = private_key.sign(signing_input, ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der_sig)

    raw_sig = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    encoded_sig = b64url(raw_sig)

    return f"{encoded_header}.{encoded_payload}.{encoded_sig}", payload["jti"]


def main():
    print("=== TRUE REPLAY ATTACK TEST WITH DPoP JTI ===")

    dpop_proof, jti = make_dpop_proof()

    payload = {
        "fileId": "FAKE_FILE_ID_FOR_REPLAY_TEST",
        "officerId": "officer_01",
        "hsmPin": "123456"
    }

    headers = {
        "Content-Type": "application/json",
        "DPoP": dpop_proof
    }

    print(f"DPoP jti dùng để replay: {jti}")
    print()

    print("Gửi request lần 1 với DPoP proof hợp lệ...")
    r1 = requests.post(TARGET_URL, json=payload, headers=headers)
    print("Lần 1 HTTP Status:", r1.status_code)
    print("Lần 1 Response:", r1.text)
    print()

    print("Gửi lại request lần 2 với CÙNG DPoP proof và CÙNG jti...")
    r2 = requests.post(TARGET_URL, json=payload, headers=headers)
    print("Lần 2 HTTP Status:", r2.status_code)
    print("Lần 2 Response:", r2.text)
    print()

    if r2.status_code == 401 and "Replay Attack Blocked" in r2.text:
        print("PASS: Replay attack bị chặn do DPoP jti đã được sử dụng.")
    else:
        print("FAIL: Replay attack chưa bị chặn đúng kỳ vọng.")


if __name__ == "__main__":
    main()