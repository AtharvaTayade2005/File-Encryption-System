# ZeroVault Formal Threat Model & Security Specification

## 1. System Overview & Cryptographic Architecture

ZeroVault is a zero-knowledge encrypted file sharing system engineered to ensure that neither intermediate networks nor the hosting infrastructure can access user data, plaintexts, or private decryption keys.

### Cryptographic Primitives
1. **PBKDF2-HMAC-SHA256**: 100,000 iterations for client-side password derivation. Derives 512 bits:
   - First 256 bits: `auth_hash` (sent to server for authentication).
   - Second 256 bits: `KEK` (Key Encryption Key, strictly client-side AES-256-GCM key).
2. **AES-256-GCM (Authenticated Encryption)**:
   - 256-bit randomly generated Data Encryption Key (DEK) per file.
   - 12-byte random Initialization Vector (IV) per encryption operation.
   - 128-bit authentication tag appended automatically to detect ciphertext tampering.
3. **RSA-OAEP (2048-bit Modulus, SHA-256 Digest)**:
   - Asymmetric keypair used to wrap/unwrap DEKs for targeted user-to-user sharing.
4. **URL Fragment Anchor (`#key=...`)**:
   - RFC 3986 client-side anchor mechanism for direct link sharing without disclosing keys to server access logs or upstream proxies.

---

## 2. Trust Boundaries & Data Storage Audit

The table below catalogs every column and entity stored on the server side and proves its zero-knowledge integrity:

| Table | Column / Attribute | Data Type / Value | Server Readability | Cryptographic Security Proof |
| :--- | :--- | :--- | :--- | :--- |
| **`users`** | `id` | UUIDv4 | Opaque identifier | No sensitive data. |
| **`users`** | `username` | String | Plaintext | Public identifier for user discovery and sharing. |
| **`users`** | `salt` | Base64 (16 bytes) | Public random salt | High-entropy random salt required for PBKDF2; reveals zero information about the password. |
| **`users`** | `auth_hash` | Bcrypt(SHA256(PBKDF2)) | Salted hash | Double-hashed (PBKDF2 client-side + Bcrypt server-side). Raw passphrase never leaves browser. |
| **`users`** | `public_key_jwk` | JSON Web Key (RSA) | Public Key | Public asymmetric key intended to be queried by any sender to wrap DEKs. |
| **`users`** | `encrypted_private_key` | JSON `{ ciphertext, iv }` | Encrypted Ciphertext | RSA private key encrypted via AES-256-GCM using client's `KEK`. Uncrackable without user's passphrase. |
| **`files`** | `id` | UUIDv4 | Random ID | Unique resource locator. |
| **`files`** | `encrypted_blob_path` | Disk Path (`.enc`) | Raw Ciphertext | Encrypted via AES-256-GCM with a single-use random 256-bit DEK. IND-CPA and IND-CCA2 secure. |
| **`files`** | `iv` | Base64 (12 bytes) | Nonce | Public random IV. Never reused across keys. |
| **`files`** | `encrypted_metadata` | JSON `{ ciphertext, iv }` | Encrypted Ciphertext | File name, MIME type, and timestamp encrypted with DEK. Server cannot index or read filenames. |
| **`files`** | `file_size` | Integer | Byte count | Ciphertext length (padded/exact). |
| **`shared_keys`**| `wrapped_key` | Base64 | Encrypted Key Blob | DEK encrypted via RSA-OAEP with recipient's public key. Decryptable only with recipient's private key. |

---

## 3. Attack Vector Analysis & Mitigations

### 3.1. Compromised Database / Malicious Database Administrator (DBA)
* **Threat**: An attacker dumps all SQLite databases and file upload storage (`./uploads/`).
* **Cryptographic Resistance**: 
  - All files on disk are AES-256-GCM ciphertexts.
  - All DEKs are wrapped with RSA-OAEP or omitted completely (anonymous links).
  - All user private keys are encrypted with KEKs derived from 100,000 PBKDF2 rounds.
  - Authentication hashes in the database are Bcrypt-hashed client hashes, preventing pass-the-hash or dictionary attacks.
* **Outcome**: Plaintext compromise is computationally infeasible without factoring 2048-bit RSA or breaking AES-256.

### 3.2. Passive Network Eavesdropping & MitM
* **Threat**: Adversary intercepts network traffic between browser and server.
* **Cryptographic Resistance**:
  - Transport layer protected via TLS 1.3.
  - Application layer double-encryption: Payload is encrypted before `POST /api/upload` is dispatched. Even in the presence of TLS termination or rogue root CAs, the data remains ciphertext.

### 3.3. Server Operator Interception & Log Extraction (Anonymous Link Sharing)
* **Threat**: Server operator inspects HTTP access logs to capture shared decryption keys.
* **Cryptographic Resistance**:
  - The anonymous share URL is constructed as:
    `https://vault.domain.com/#/download/<file_id>#key=<BASE64URL_DEK>`
  - Per W3C HTTP/1.1 and RFC 3986 §3.5:
    > *"The fragment identifier is not sent in the URI of a request message."*
  - The browser's network stack strips everything starting from `#` before building the TCP packet. Server access logs only record `GET /api/files/<file_id>/download`.
  - The raw DEK never appears in reverse proxy logs, CDNs, or server memory.

### 3.4. Malicious JavaScript Injection & XSS (Client Compromise)
* **Threat**: Malicious scripts injected into client DOM to capture unencrypted keys in memory.
* **Mitigation**:
  - Production deployments enforce strict Content Security Policy (CSP):
    `Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none';`
  - In-memory variables are isolated inside the `ZeroVaultApp` instance and wiped on session termination.

---

## 4. Formal Zero-Knowledge Security Summary
- $\text{Pr}[\mathcal{A}(\text{Database Dump}) \to \text{Plaintext}] = \text{negl}(\lambda)$
- $\text{Pr}[\mathcal{A}(\text{Server Request Logs}) \to \text{DEK}_{\text{link}}] = 0$ (Guaranteed by RFC 3986 fragment isolation)
- $\text{Pr}[\mathcal{A}(\text{Server Salt \& AuthHash}) \to \text{Passphrase}] \le \text{Bcrypt/PBKDF2 Inversion Cost}$
