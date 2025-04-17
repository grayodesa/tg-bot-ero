"""
Utility script to generate JWT tokens for admin users.
Usage:
  python gen_token.py <ADMIN_ID>
Set environment variable JWT_SECRET to the secret used by the app.
"""
import os
import sys
import json
import base64
import hmac
import hashlib

def base64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode('utf-8')

def generate_token(admin_id: int, secret: str) -> str:
    header = {"alg": "HS256", "typ": "JWT"}
    payload = {"admin_id": admin_id}
    header_b64 = base64url_encode(json.dumps(header).encode())
    payload_b64 = base64url_encode(json.dumps(payload).encode())
    signing_input = f"{header_b64}.{payload_b64}".encode()
    signature = hmac.new(secret.encode(), signing_input, hashlib.sha256).digest()
    signature_b64 = base64url_encode(signature)
    return f"{header_b64}.{payload_b64}.{signature_b64}"

def main():
    if len(sys.argv) != 2:
        print("Usage: python gen_token.py <ADMIN_ID>")
        sys.exit(1)
    try:
        admin_id = int(sys.argv[1])
    except ValueError:
        print("ADMIN_ID must be an integer.")
        sys.exit(1)
    secret = os.getenv('JWT_SECRET')
    if not secret:
        print("Error: JWT_SECRET environment variable not set.")
        sys.exit(1)
    token = generate_token(admin_id, secret)
    print(token)

if __name__ == "__main__":
    main()