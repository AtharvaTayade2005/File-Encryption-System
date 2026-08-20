# ZeroVault — Zero-Knowledge Encrypted File Sharing System

A production-grade, zero-knowledge blind file vault leveraging the native **Web Crypto API** (PBKDF2, AES-256-GCM, RSA-OAEP) and a FastAPI backend.

---

## 🔒 Security & Architecture Guarantees

- **Zero-Knowledge Blind Storage**: The backend server never receives plaintext files, user passphrases, unencrypted Data Encryption Keys (DEKs), or raw RSA private keys.
- **Client-Side PBKDF2-HMAC-SHA256**: 100,000 rounds used on the client to derive:
  - `auth_hash`: 256-bit authentication hash sent to the server.
  - `KEK` (Key Encryption Key): AES-256-GCM key retained strictly in browser RAM to encrypt/decrypt the user's private key.
- **Asymmetric Key Exchange (RSA-OAEP 2048-bit)**: Used for sharing files directly with registered recipients via public-key wrapped DEKs.
- **Authenticated Symmetric Encryption (AES-256-GCM)**: File payloads and metadata are encrypted with fresh 256-bit DEKs and 12-byte IVs with 128-bit authentication tags.
- **Anonymous URL Fragment Links**: Shareable URLs format DEK inside URL fragment/hash queries (`/#/download/<id>?key=<DEK>`) — the key is never transmitted over HTTP to the server.

---

## 🚀 Quickstart

### Prerequisites
- Python 3.10+ (tested on Python 3.14)
- Modern web browser with Web Crypto API support

### 1. Install Dependencies
```bash
pip install -r backend/requirements.txt
```

### 2. Run the System
```bash
python run.py
```
Or start the FastAPI server directly:
```bash
uvicorn backend.main:app --host 127.0.0.1 --port 8000 --reload
```
Navigate to `http://127.0.0.1:8000` in your browser.

---

## 🧪 Running Tests

Execute the automated end-to-end backend test suite:
```bash
python test_system.py
```

Run the Node.js WebCrypto cryptographic validation:
```bash
node test_webcrypto.js
```

---

## 📂 Project Structure

```
├── backend/
│   ├── database.py       # SQLAlchemy 2.0 DB initialization & session management
│   ├── main.py           # FastAPI Zero-Knowledge REST API endpoints & static file serving
│   ├── models.py         # SQLAlchemy models & Pydantic validation schemas
│   └── requirements.txt  # Python package dependencies
├── crypto/
│   └── webcrypto.js      # Core Web Crypto engine (PBKDF2, AES-GCM, RSA-OAEP)
├── docs/
│   └── THREAT_MODEL.md   # Detailed cryptographic threat model & security specifications
├── frontend/
│   ├── app.js            # Frontend single-page application controller & RAM key management
│   ├── index.html        # Glassmorphic dashboard UI & modal interfaces
│   └── styles.css        # Custom CSS variables, dark theme & animations
├── run.py                # Single-command launcher script
├── test_system.py        # Automated API test suite
└── test_webcrypto.js     # WebCrypto test runner
```

---

## 📄 License
MIT License
