/**
 * ============================================================================
 * Zero-Knowledge Cryptographic Engine (Web Crypto API)
 * ============================================================================
 * 
 * Standards & Primitives:
 * - PBKDF2-HMAC-SHA256: 100,000 iterations for master key separation (authHash vs KEK)
 * - Optional File Password Layer: PBKDF2-derived AES-256-GCM wrapping of the DEK
 * - RSA-OAEP (2048-bit, SHA-256): Asymmetric DEK wrapping for targeted user sharing
 * - AES-256-GCM (12-byte IV): Authenticated symmetric encryption for files, metadata, and private keys
 * - Base64 / Base64URL: Encodings for network transmission & URL fragment sharing
 * 
 * Security Guarantee:
 * - Server NEVER receives: plaintext files, raw passwords, unencrypted DEKs, or decrypted RSA private keys.
 */

class CryptoEngine {
    constructor() {
        if (!window.crypto || !window.crypto.subtle) {
            throw new Error("Web Crypto API (window.crypto.subtle) is not supported in this browser or context.");
        }
    }

    // ========================================================================
    // 1. Binary / Encoding Utilities (ArrayBuffer <-> Base64 / Base64URL / Hex)
    // ========================================================================

    /**
     * Converts an ArrayBuffer or Uint8Array to standard Base64 string.
     * @param {ArrayBuffer|Uint8Array} buffer 
     * @returns {string} Base64 string
     */
    static bufferToBase64(buffer) {
        const bytes = new Uint8Array(buffer);
        let binary = '';
        const len = bytes.byteLength;
        for (let i = 0; i < len; i++) {
            binary += String.fromCharCode(bytes[i]);
        }
        return window.btoa(binary);
    }

    /**
     * Converts a Base64 string to Uint8Array.
     * @param {string} base64 
     * @returns {Uint8Array}
     */
    static base64ToBuffer(base64) {
        const binary = window.atob(base64);
        const bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) {
            bytes[i] = binary.charCodeAt(i);
        }
        return bytes;
    }

    /**
     * Converts an ArrayBuffer or Uint8Array to URL-safe Base64 (Base64URL) string.
     * @param {ArrayBuffer|Uint8Array} buffer 
     * @returns {string} Base64URL string (safe for URL hash fragments)
     */
    static bufferToBase64Url(buffer) {
        return CryptoEngine.bufferToBase64(buffer)
            .replace(/\+/g, '-')
            .replace(/\//g, '_')
            .replace(/=+$/, '');
    }

    /**
     * Converts a URL-safe Base64 (Base64URL) string back to Uint8Array.
     * @param {string} base64url 
     * @returns {Uint8Array}
     */
    static base64UrlToBuffer(base64url) {
        let base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
        while (base64.length % 4) {
            base64 += '=';
        }
        return CryptoEngine.base64ToBuffer(base64);
    }

    /**
     * Converts an ArrayBuffer to a Hexadecimal string.
     * @param {ArrayBuffer|Uint8Array} buffer 
     * @returns {string} Hex string
     */
    static bufferToHex(buffer) {
        const bytes = new Uint8Array(buffer);
        return Array.from(bytes)
            .map(b => b.toString(16).padStart(2, '0'))
            .join('');
    }

    /**
     * Generates cryptographically secure random bytes.
     * @param {number} length 
     * @returns {Uint8Array}
     */
    static getRandomBytes(length) {
        const bytes = new Uint8Array(length);
        window.crypto.getRandomValues(bytes);
        return bytes;
    }

    // ========================================================================
    // 2. Client-Side Master Key Derivation (PBKDF2-SHA256)
    // ========================================================================

    /**
     * Derives:
     * 1. authHash (Hex string, 256-bit): Sent to server for authentication (zero password leak)
     * 2. kek (CryptoKey, AES-256-GCM): Kept in browser memory to encrypt/decrypt private keys
     * 
     * Uses PBKDF2 with SHA-256 and 100,000 iterations to derive 512 bits of pseudorandom material.
     * 
     * @param {string} passphrase - User's plain password
     * @param {string|Uint8Array} salt - 16-byte salt (Base64 or Uint8Array)
     * @returns {Promise<{ authHash: string, kek: CryptoKey, saltBase64: string }>}
     */
    async deriveMasterKeys(passphrase, salt) {
        let saltBytes;
        if (typeof salt === 'string') {
            saltBytes = CryptoEngine.base64ToBuffer(salt);
        } else if (salt instanceof Uint8Array) {
            saltBytes = salt;
        } else {
            // Generate a fresh 16-byte random salt if not provided
            saltBytes = CryptoEngine.getRandomBytes(16);
        }

        const enc = new TextEncoder();
        const passphraseBytes = enc.encode(passphrase);

        // 1. Import raw passphrase as a key for PBKDF2
        const baseKey = await window.crypto.subtle.importKey(
            "raw",
            passphraseBytes,
            { name: "PBKDF2" },
            false,
            ["deriveBits"]
        );

        // 2. Derive 512 bits (64 bytes) using PBKDF2-HMAC-SHA256 with 100,000 iterations
        const derivedBits = await window.crypto.subtle.deriveBits(
            {
                name: "PBKDF2",
                salt: saltBytes,
                iterations: 100000,
                hash: "SHA-256"
            },
            baseKey,
            512
        );

        const derivedArray = new Uint8Array(derivedBits);

        // First 32 bytes (256 bits) -> authHash (used for API authentication)
        const authHashBytes = derivedArray.slice(0, 32);
        const authHash = CryptoEngine.bufferToHex(authHashBytes);

        // Second 32 bytes (256 bits) -> KEK (Key Encryption Key for encrypting RSA private key)
        const kekBytes = derivedArray.slice(32, 64);
        const kek = await window.crypto.subtle.importKey(
            "raw",
            kekBytes,
            { name: "AES-GCM", length: 256 },
            false,
            ["encrypt", "decrypt"]
        );

        return {
            authHash,
            kek,
            saltBase64: CryptoEngine.bufferToBase64(saltBytes)
        };
    }

    /**
     * Derives an AES-256-GCM Key directly from a custom File Access Password using PBKDF2.
     * Used for double-encryption / password-protected file sharing.
     * 
     * @param {string} filePassword 
     * @param {string|Uint8Array} salt 
     * @returns {Promise<{ key: CryptoKey, saltBase64: string }>}
     */
    async deriveKeyFromFilePassword(filePassword, salt = null) {
        let saltBytes = salt ? (typeof salt === 'string' ? CryptoEngine.base64ToBuffer(salt) : salt) : CryptoEngine.getRandomBytes(16);
        const enc = new TextEncoder();
        const baseKey = await window.crypto.subtle.importKey(
            "raw",
            enc.encode(filePassword),
            { name: "PBKDF2" },
            false,
            ["deriveKey"]
        );

        const key = await window.crypto.subtle.deriveKey(
            {
                name: "PBKDF2",
                salt: saltBytes,
                iterations: 100000,
                hash: "SHA-256"
            },
            baseKey,
            { name: "AES-GCM", length: 256 },
            false,
            ["encrypt", "decrypt"]
        );

        return {
            key,
            saltBase64: CryptoEngine.bufferToBase64(saltBytes)
        };
    }

    // ========================================================================
    // 3. Asymmetric Keypair Generation & Local Key Storage
    // ========================================================================

    /**
     * Generates an RSA-OAEP 2048-bit keypair for the user.
     * - Public key is exported as JWK (safe for server and public directory).
     * - Private key is exported as JWK string and encrypted with user's KEK via AES-256-GCM.
     * 
     * @param {CryptoKey} kek - User's local AES-GCM Key Encryption Key
     * @returns {Promise<{ publicKeyJwk: object, encryptedPrivateKey: { ciphertext: string, iv: string }, rawPrivateKey: CryptoKey }>}
     */
    async generateAsymmetricKeyPair(kek) {
        // 1. Generate RSA-OAEP 2048-bit KeyPair
        const keyPair = await window.crypto.subtle.generateKey(
            {
                name: "RSA-OAEP",
                modulusLength: 2048,
                publicExponent: new Uint8Array([0x01, 0x00, 0x01]), // 65537
                hash: "SHA-256"
            },
            true, // extractable
            ["wrapKey", "unwrapKey", "encrypt", "decrypt"]
        );

        // 2. Export Public Key as JWK
        const publicKeyJwk = await window.crypto.subtle.exportKey("jwk", keyPair.publicKey);

        // 3. Export Private Key as JWK
        const privateKeyJwk = await window.crypto.subtle.exportKey("jwk", keyPair.privateKey);
        const privateKeyJsonString = JSON.stringify(privateKeyJwk);
        const enc = new TextEncoder();
        const privateKeyBuffer = enc.encode(privateKeyJsonString);

        // 4. Encrypt Private Key with KEK via AES-256-GCM
        const iv = CryptoEngine.getRandomBytes(12);
        const encryptedPrivateKeyBuffer = await window.crypto.subtle.encrypt(
            {
                name: "AES-GCM",
                iv: iv
            },
            kek,
            privateKeyBuffer
        );

        return {
            publicKeyJwk,
            encryptedPrivateKey: {
                ciphertext: CryptoEngine.bufferToBase64(encryptedPrivateKeyBuffer),
                iv: CryptoEngine.bufferToBase64(iv)
            },
            rawPrivateKey: keyPair.privateKey
        };
    }

    /**
     * Decrypts user's stored encrypted private key blob using their KEK.
     * 
     * @param {{ ciphertext: string, iv: string }} encryptedBlob 
     * @param {CryptoKey} kek 
     * @returns {Promise<CryptoKey>} Decrypted RSA-OAEP private key
     */
    async decryptPrivateKey(encryptedBlob, kek) {
        const ciphertextBuffer = CryptoEngine.base64ToBuffer(encryptedBlob.ciphertext);
        const ivBuffer = CryptoEngine.base64ToBuffer(encryptedBlob.iv);

        const decryptedBuffer = await window.crypto.subtle.decrypt(
            {
                name: "AES-GCM",
                iv: ivBuffer
            },
            kek,
            ciphertextBuffer
        );

        const dec = new TextDecoder();
        let privateKeyJson = JSON.parse(dec.decode(decryptedBuffer));
        while (typeof privateKeyJson === 'string') {
            try {
                privateKeyJson = JSON.parse(privateKeyJson);
            } catch (e) {
                break;
            }
        }

        return await window.crypto.subtle.importKey(
            "jwk",
            privateKeyJson,
            {
                name: "RSA-OAEP",
                hash: "SHA-256"
            },
            true,
            ["unwrapKey", "decrypt"]
        );
    }

    // ========================================================================
    // 4. Client-Side File & Metadata Encryption (AES-256-GCM)
    // ========================================================================

    /**
     * Encrypts a file's ArrayBuffer using a freshly generated AES-256-GCM DEK.
     * Also encrypts file metadata (name, mimeType, size) with the same DEK.
     * 
     * @param {ArrayBuffer} fileArrayBuffer - Plaintext file bytes
     * @param {string} fileName - Original file name
     * @param {string} mimeType - Original file MIME type
     * @param {string|null} filePassword - Optional additional file access password (Double Encryption)
     * @returns {Promise<{ ciphertextBlob: Blob, ivBase64: string, rawDekBuffer: ArrayBuffer, rawDekBase64Url: string, encryptedMetadata: { ciphertext: string, iv: string }, passwordProtected: boolean, passwordSalt: string|null, passwordIv: string|null }>}
     */
    async encryptFile(fileArrayBuffer, fileName = "file.bin", mimeType = "application/octet-stream", filePassword = null) {
        // 1. Generate fresh 256-bit AES-GCM Data Encryption Key (DEK)
        const dek = await window.crypto.subtle.generateKey(
            {
                name: "AES-GCM",
                length: 256
            },
            true,
            ["encrypt", "decrypt"]
        );

        // 2. Export raw DEK (32 bytes)
        const rawDekBuffer = await window.crypto.subtle.exportKey("raw", dek);
        const rawDekBase64Url = CryptoEngine.bufferToBase64Url(rawDekBuffer);

        // 3. Generate random 12-byte IV for file payload
        const fileIv = CryptoEngine.getRandomBytes(12);

        // 4. Encrypt file ArrayBuffer (AES-256-GCM computes 128-bit authentication tag automatically)
        const ciphertextBuffer = await window.crypto.subtle.encrypt(
            {
                name: "AES-GCM",
                iv: fileIv
            },
            dek,
            fileArrayBuffer
        );

        // Optional: If a file password is set, wrap/encrypt the DEK with a PBKDF2 key derived from that password
        let passwordProtected = false;
        let passwordSalt = null;
        let passwordIv = null;
        let passwordWrappedDek = null;

        if (filePassword && filePassword.trim().length > 0) {
            passwordProtected = true;
            const { key: pwKey, saltBase64: pSalt } = await this.deriveKeyFromFilePassword(filePassword.trim());
            passwordSalt = pSalt;
            const pIv = CryptoEngine.getRandomBytes(12);
            passwordIv = CryptoEngine.bufferToBase64(pIv);

            const encDek = await window.crypto.subtle.encrypt(
                { name: "AES-GCM", iv: pIv },
                pwKey,
                rawDekBuffer
            );
            passwordWrappedDek = CryptoEngine.bufferToBase64(encDek);
        }

        // 5. Encrypt metadata object (fileName, mimeType, size, password status) to keep it zero-knowledge
        const metaIv = CryptoEngine.getRandomBytes(12);
        const metaObj = {
            fileName: fileName,
            mimeType: mimeType,
            fileSize: fileArrayBuffer.byteLength,
            encryptedAt: new Date().toISOString(),
            passwordProtected: passwordProtected,
            passwordSalt: passwordSalt,
            passwordIv: passwordIv,
            passwordWrappedDek: passwordWrappedDek
        };
        const metaBytes = new TextEncoder().encode(JSON.stringify(metaObj));
        const encryptedMetaBuffer = await window.crypto.subtle.encrypt(
            {
                name: "AES-GCM",
                iv: metaIv
            },
            dek,
            metaBytes
        );

        return {
            ciphertextBlob: new Blob([ciphertextBuffer], { type: "application/octet-stream" }),
            ivBase64: CryptoEngine.bufferToBase64(fileIv),
            rawDekBuffer,
            rawDekBase64Url,
            encryptedMetadata: {
                ciphertext: CryptoEngine.bufferToBase64(encryptedMetaBuffer),
                iv: CryptoEngine.bufferToBase64(metaIv)
            },
            passwordProtected,
            passwordSalt,
            passwordIv,
            passwordWrappedDek
        };
    }

    // ========================================================================
    // 5. Key Wrapping & Unwrapping (RSA-OAEP)
    // ========================================================================

    /**
     * Wraps (encrypts) a raw DEK with a recipient's RSA-OAEP public key.
     * Sanitizes JWK object to ensure only valid public key parameters and key_ops are imported.
     * 
     * @param {ArrayBuffer|Uint8Array} rawDekBuffer - 32-byte AES DEK
     * @param {object|string} recipientPublicKeyJwk - Target user's RSA-OAEP public key JWK
     * @returns {Promise<string>} Base64-encoded wrapped DEK
     */
    async wrapKeyForRecipient(rawDekBuffer, recipientPublicKeyJwk) {
        let jwk = recipientPublicKeyJwk;
        while (typeof jwk === 'string') {
            try {
                jwk = JSON.parse(jwk);
            } catch (e) {
                break;
            }
        }

        if (!jwk || typeof jwk !== 'object' || !jwk.n || !jwk.e) {
            throw new Error("Invalid RSA public key parameters received for recipient. The key is missing required fields (kty, n, e).");
        }

        // Validate that 'n' (RSA modulus) is a valid Base64URL-encoded value and not a mock/placeholder.
        // A real RSA-2048 modulus is 256 bytes = ~342 Base64 characters minimum.
        const modulusStr = jwk.n;
        const isValidBase64Url = /^[A-Za-z0-9_-]+$/.test(modulusStr);
        if (!isValidBase64Url || modulusStr.length < 100) {
            throw new Error(
                `Recipient's RSA public key has an invalid modulus (length=${modulusStr.length}). ` +
                `This user may have been created by a test script with a mock/placeholder key. ` +
                `Please share with a user who registered through the browser UI with a real keypair.`
            );
        }

        // Clean JWK strictly for RSA public key import
        const cleanJwk = {
            kty: jwk.kty || "RSA",
            n: jwk.n,
            e: jwk.e
        };

        // Import recipient's public key for encryption
        let publicKey;
        try {
            publicKey = await window.crypto.subtle.importKey(
                "jwk",
                cleanJwk,
                {
                    name: "RSA-OAEP",
                    hash: "SHA-256"
                },
                false,
                ["encrypt"]
            );
        } catch (importErr) {
            const detail = importErr.message || importErr.name || String(importErr);
            throw new Error(`Failed to import recipient's RSA public key: ${detail}. The key may be corrupted or generated by a test script.`);
        }

        // Encrypt the 32-byte DEK with RSA-OAEP
        let wrappedBuffer;
        try {
            wrappedBuffer = await window.crypto.subtle.encrypt(
                {
                    name: "RSA-OAEP"
                },
                publicKey,
                rawDekBuffer
            );
        } catch (encryptErr) {
            const detail = encryptErr.message || encryptErr.name || String(encryptErr);
            throw new Error(`RSA-OAEP encryption of DEK failed: ${detail}`);
        }

        return CryptoEngine.bufferToBase64(wrappedBuffer);
    }

    /**
     * Unwraps (decrypts) a wrapped DEK using the recipient's RSA-OAEP private key.
     * 
     * @param {string|ArrayBuffer} wrappedDek - Base64 or ArrayBuffer of RSA-encrypted DEK
     * @param {CryptoKey} privateKey - Recipient's unlocked RSA-OAEP private key
     * @returns {Promise<ArrayBuffer>} Raw 32-byte DEK ArrayBuffer
     */
    async unwrapKeyWithPrivateKey(wrappedDek, privateKey) {
        let wrappedBuffer;
        if (typeof wrappedDek === 'string') {
            wrappedBuffer = CryptoEngine.base64ToBuffer(wrappedDek);
        } else {
            wrappedBuffer = wrappedDek;
        }

        // Decrypt the DEK using RSA-OAEP
        return await window.crypto.subtle.decrypt(
            {
                name: "RSA-OAEP"
            },
            privateKey,
            wrappedBuffer
        );
    }

    /**
     * Unwraps a password-protected DEK using a user-supplied file password.
     * 
     * @param {string} passwordWrappedDekBase64 
     * @param {string} passwordSaltBase64 
     * @param {string} passwordIvBase64 
     * @param {string} filePassword 
     * @returns {Promise<ArrayBuffer>}
     */
    async unwrapDekWithFilePassword(passwordWrappedDekBase64, passwordSaltBase64, passwordIvBase64, filePassword) {
        const { key } = await this.deriveKeyFromFilePassword(filePassword, passwordSaltBase64);
        const ciphertextBuffer = CryptoEngine.base64ToBuffer(passwordWrappedDekBase64);
        const ivBuffer = CryptoEngine.base64ToBuffer(passwordIvBase64);

        return await window.crypto.subtle.decrypt(
            { name: "AES-GCM", iv: ivBuffer },
            key,
            ciphertextBuffer
        );
    }

    // ========================================================================
    // 6. Decryption of File and Metadata (AES-256-GCM)
    // ========================================================================

    /**
     * Decrypts encrypted metadata using raw DEK.
     * 
     * @param {{ ciphertext: string, iv: string }} encryptedMetadata 
     * @param {ArrayBuffer|Uint8Array|CryptoKey} dek 
     * @returns {Promise<{ fileName: string, mimeType: string, fileSize: number, encryptedAt: string, passwordProtected: boolean, passwordSalt: string|null, passwordIv: string|null, passwordWrappedDek: string|null }>}
     */
    async decryptMetadata(encryptedMetadata, dek) {
        let aesKey = dek;
        if (!(dek instanceof CryptoKey)) {
            aesKey = await window.crypto.subtle.importKey(
                "raw",
                dek,
                { name: "AES-GCM", length: 256 },
                false,
                ["decrypt"]
            );
        }

        const ciphertextBuffer = CryptoEngine.base64ToBuffer(encryptedMetadata.ciphertext);
        const ivBuffer = CryptoEngine.base64ToBuffer(encryptedMetadata.iv);

        const decryptedBuffer = await window.crypto.subtle.decrypt(
            {
                name: "AES-GCM",
                iv: ivBuffer
            },
            aesKey,
            ciphertextBuffer
        );

        const dec = new TextDecoder();
        return JSON.parse(dec.decode(decryptedBuffer));
    }

    /**
     * Decrypts an encrypted file's ArrayBuffer using the DEK and IV.
     * 
     * @param {ArrayBuffer} ciphertextArrayBuffer - Encrypted file bytes
     * @param {ArrayBuffer|Uint8Array|CryptoKey} dek - 256-bit AES DEK (raw buffer or CryptoKey)
     * @param {string|Uint8Array} iv - 12-byte IV (Base64 string or Uint8Array)
     * @returns {Promise<ArrayBuffer>} Plaintext file ArrayBuffer
     */
    async decryptFileBuffer(ciphertextArrayBuffer, dek, iv) {
        let aesKey = dek;
        if (!(dek instanceof CryptoKey)) {
            aesKey = await window.crypto.subtle.importKey(
                "raw",
                dek,
                { name: "AES-GCM", length: 256 },
                false,
                ["decrypt"]
            );
        }

        let ivBuffer;
        if (typeof iv === 'string') {
            ivBuffer = CryptoEngine.base64ToBuffer(iv);
        } else {
            ivBuffer = iv;
        }

        // Authenticated AES-GCM Decryption (throws if tampered or key incorrect)
        return await window.crypto.subtle.decrypt(
            {
                name: "AES-GCM",
                iv: ivBuffer
            },
            aesKey,
            ciphertextArrayBuffer
        );
    }

    /**
     * Decrypts file and triggers browser download dialog.
     * 
     * @param {ArrayBuffer} ciphertextArrayBuffer 
     * @param {ArrayBuffer|Uint8Array|CryptoKey} dek 
     * @param {string|Uint8Array} iv 
     * @param {string} fileName 
     * @param {string} mimeType 
     * @returns {Promise<Blob>}
     */
    async decryptAndDownloadFile(ciphertextArrayBuffer, dek, iv, fileName = "decrypted_file", mimeType = "application/octet-stream") {
        const plaintextBuffer = await this.decryptFileBuffer(ciphertextArrayBuffer, dek, iv);
        const blob = new Blob([plaintextBuffer], { type: mimeType });

        // Trigger browser save
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = fileName;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        setTimeout(() => URL.revokeObjectURL(url), 10000);

        return blob;
    }
}

// Export for module systems and global window usage
if (typeof module !== 'undefined' && module.exports) {
    module.exports = CryptoEngine;
} else {
    window.CryptoEngine = CryptoEngine;
}
