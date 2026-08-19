"""
End-to-End backend test script to verify Zero-Knowledge API endpoints with unique test namespaces:
- User Registration (salt, auth_hash, public_key_jwk, encrypted_private_key)
- Salt lookup
- Login authentication
- Public key directory querying
- File upload with blind blob storage and wrapped keys
- File info & encrypted blob streaming
"""

import os
import sys
import json
import base64
import secrets
from fastapi.testclient import TestClient

# Ensure backend directory is in python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "backend"))

from main import app
import database

client = TestClient(app)

def run_tests():
    print("========================================")
    print(" Running ZeroVault Backend System Tests")
    print("========================================")

    tag = secrets.token_hex(4)
    alice_name = f"alice_{tag}"
    bob_name = f"bob_{tag}"

    # 1. Register User 'alice'
    alice_salt = base64.b64encode(secrets.token_bytes(16)).decode('utf-8')
    alice_auth_hash = secrets.token_hex(32)
    alice_pubkey = json.dumps({"kty": "RSA", "n": f"mock_n_{alice_name}", "e": "AQAB"})
    alice_enc_privkey = json.dumps({"ciphertext": "mock_cipher_priv", "iv": "mock_iv_priv"})

    print(f"[1] Testing User Registration (/api/register) for {alice_name}...")
    res = client.post("/api/register", json={
        "username": alice_name,
        "salt": alice_salt,
        "auth_hash": alice_auth_hash,
        "public_key_jwk": alice_pubkey,
        "encrypted_private_key": alice_enc_privkey
    })
    assert res.status_code == 200, f"Registration failed: {res.text}"
    alice_data = res.json()
    alice_token = alice_data["access_token"]
    print("    [OK] Alice registered successfully. JWT Token acquired.")

    # 2. Register User 'bob'
    print(f"[2] Registering second user '{bob_name}'...")
    bob_salt = base64.b64encode(secrets.token_bytes(16)).decode('utf-8')
    bob_auth_hash = secrets.token_hex(32)
    bob_pubkey = json.dumps({"kty": "RSA", "n": f"mock_n_{bob_name}", "e": "AQAB"})
    bob_enc_privkey = json.dumps({"ciphertext": "mock_cipher_bob", "iv": "mock_iv_bob"})

    res = client.post("/api/register", json={
        "username": bob_name,
        "salt": bob_salt,
        "auth_hash": bob_auth_hash,
        "public_key_jwk": bob_pubkey,
        "encrypted_private_key": bob_enc_privkey
    })
    assert res.status_code == 200
    bob_token = res.json()["access_token"]
    print("    [OK] Bob registered successfully.")

    # 3. Test Salt Lookup
    print(f"[3] Testing Salt Lookup (/api/users/{alice_name}/salt)...")
    res = client.get(f"/api/users/{alice_name}/salt")
    assert res.status_code == 200
    assert res.json()["salt"] == alice_salt
    print("    [OK] Correct salt returned.")

    # 4. Test Login
    print("[4] Testing User Login (/api/login)...")
    res = client.post("/api/login", json={
        "username": alice_name,
        "auth_hash": alice_auth_hash
    })
    assert res.status_code == 200
    assert res.json()["username"] == alice_name
    print("    [OK] Authenticated login successful.")

    # 5. Test Public Key Discovery (mock keys are now correctly rejected by server)
    print(f"[5] Testing Public Key Directory (/api/users/{bob_name}/public-key)...")
    res = client.get(f"/api/users/{bob_name}/public-key")
    assert res.status_code == 400, f"Expected 400 for mock key, got {res.status_code}"
    assert "invalid RSA public key" in res.json()["detail"]
    print("    [OK] Mock public key correctly rejected by server.")

    # 6. Test Encrypted File Upload (Blind Storage)
    print("[6] Testing Blind Encrypted File Upload (/api/upload)...")
    dummy_encrypted_bytes = b"\x00\x01\x02\x03\x04\x05\x06\x07_CIPHERTEXT_PAYLOAD"
    dummy_iv = base64.b64encode(secrets.token_bytes(12)).decode('utf-8')
    dummy_meta = json.dumps({"ciphertext": "meta_cipher", "iv": "meta_iv"})
    dummy_wrapped_keys = json.dumps([
        {"recipient_username": alice_name, "wrapped_key": "wrapped_for_alice"},
        {"recipient_username": bob_name, "wrapped_key": "wrapped_for_bob"}
    ])

    res = client.post(
        "/api/upload",
        headers={"Authorization": f"Bearer {alice_token}"},
        files={"file": ("encrypted.bin", dummy_encrypted_bytes, "application/octet-stream")},
        data={
            "iv": dummy_iv,
            "encrypted_metadata": dummy_meta,
            "wrapped_keys": dummy_wrapped_keys
        }
    )
    assert res.status_code == 200, f"Upload failed: {res.text}"
    file_id = res.json()["file_id"]
    print(f"    [OK] File uploaded and stored blindly with ID: {file_id}")

    # 7. Test Vault Retrieval
    print("[7] Testing Vault Listing (/api/vault)...")
    res = client.get("/api/vault", headers={"Authorization": f"Bearer {alice_token}"})
    assert res.status_code == 200
    vault_data = res.json()
    assert len(vault_data["owned_files"]) >= 1
    assert vault_data["owned_files"][0]["file_id"] == file_id
    print("    [OK] Alice's vault contains uploaded file record.")

    # 8. Test Bob's Shared Files
    print("[8] Testing Shared Files from Recipient (Bob's Vault)...")
    res = client.get("/api/vault", headers={"Authorization": f"Bearer {bob_token}"})
    assert res.status_code == 200
    bob_vault = res.json()
    assert len(bob_vault["shared_files"]) >= 1
    assert bob_vault["shared_files"][0]["file_id"] == file_id
    assert bob_vault["shared_files"][0]["wrapped_key"] == "wrapped_for_bob"
    print("    [OK] Bob received shared file with his specific wrapped DEK.")

    # 9. Test Encrypted Blob Streaming
    print("[9] Testing Encrypted Blob Download (/api/files/{id}/download)...")
    res = client.get(f"/api/files/{file_id}/download")
    assert res.status_code == 200
    assert res.content == dummy_encrypted_bytes
    print("    [OK] Exact ciphertext payload returned to client.")

    print("\n========================================")
    print(" ALL ZERO-KNOWLEDGE API TESTS PASSED! ")
    print("========================================")

if __name__ == "__main__":
    run_tests()
