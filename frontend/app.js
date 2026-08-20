/**
 * ============================================================================
 * ZeroVault Frontend UI & Cryptographic Controller
 * ============================================================================
 * 
 * Bridges HTML UI with CryptoEngine and FastAPI Zero-Knowledge backend.
 * Handles client-side key derivation, in-memory private key management,
 * URL fragment hash routing (#/download/:id#key=...), password-protected file layers,
 * and manual client-side file decryption tool.
 */

class ZeroVaultApp {
    constructor() {
        this.crypto = new CryptoEngine();
        this.currentUser = null;
        this.unlockedPrivateKey = null; // Stored strictly in browser RAM for the active session
        this.authMode = 'login'; // 'login' or 'register'
        this.selectedFile = null;
        this.activeShareFile = null; // For vault file sharing modal

        this.init();
    }

    async init() {
        this.bindEvents();
        this.checkUrlFragmentRoute();
        await this.checkExistingSession();
    }

    // ========================================================================
    // Logging / Terminal Visualization
    // ========================================================================

    log(message, type = "info") {
        const terminal = document.getElementById("terminal-log");
        if (!terminal) return;
        const line = document.createElement("div");
        const timestamp = new Date().toLocaleTimeString();

        let colorClass = "terminal-line-info";
        if (type === "success") colorClass = "terminal-line-success";
        if (type === "warn") colorClass = "terminal-line-warn";
        if (type === "crypto") colorClass = "terminal-line-crypto";

        line.className = colorClass;
        line.textContent = `[${timestamp}] ${message}`;
        terminal.appendChild(line);
        terminal.scrollTop = terminal.scrollHeight;
    }

    // ========================================================================
    // Event Listeners & Drag-Drop Bindings
    // ========================================================================

    bindEvents() {
        // Auth Mode Toggle
        document.getElementById("btn-toggle-auth-mode")?.addEventListener("click", () => {
            this.authMode = this.authMode === "login" ? "register" : "login";
            this.updateAuthModalUI();
        });

        // Auth Form Submit
        document.getElementById("auth-form")?.addEventListener("submit", (e) => {
            e.preventDefault();
            this.handleAuthSubmit();
        });

        // Logout
        document.getElementById("btn-logout")?.addEventListener("click", () => {
            this.logout();
        });

        // Drag & Drop File Zone
        const dropZone = document.getElementById("drop-zone");
        const fileInput = document.getElementById("file-input");

        if (dropZone && fileInput) {
            dropZone.addEventListener("click", () => fileInput.click());

            fileInput.addEventListener("change", (e) => {
                if (e.target.files && e.target.files.length > 0) {
                    this.handleFileSelected(e.target.files[0]);
                }
            });

            ['dragenter', 'dragover'].forEach(eventName => {
                dropZone.addEventListener(eventName, (e) => {
                    e.preventDefault();
                    dropZone.classList.add('dropzone-active');
                }, false);
            });

            ['dragleave', 'drop'].forEach(eventName => {
                dropZone.addEventListener(eventName, (e) => {
                    e.preventDefault();
                    dropZone.classList.remove('dropzone-active');
                }, false);
            });

            dropZone.addEventListener('drop', (e) => {
                const dt = e.dataTransfer;
                const files = dt.files;
                if (files && files.length > 0) {
                    this.handleFileSelected(files[0]);
                }
            }, false);
        }

        // Sharing Mode Radios
        const shareRadios = document.getElementsByName("share-mode");
        shareRadios.forEach(radio => {
            radio.addEventListener("change", (e) => {
                const recBox = document.getElementById("recipient-selection-box");
                if (e.target.value === "user") {
                    recBox?.classList.remove("hidden");
                    this.loadAvailableUsers();
                } else {
                    recBox?.classList.add("hidden");
                }
            });
        });

        // Start Encrypt & Upload
        document.getElementById("btn-start-encrypt")?.addEventListener("click", () => {
            this.handleEncryptAndUpload();
        });

        // Vault Share Modal Buttons
        document.getElementById("btn-gen-vault-link")?.addEventListener("click", () => {
            this.generateVaultFileShareLink();
        });

        document.getElementById("btn-vault-share-user")?.addEventListener("click", () => {
            this.shareVaultFileWithUser();
        });

        // Manual Decrypt Button
        document.getElementById("btn-manual-decrypt")?.addEventListener("click", () => {
            this.handleManualDecrypt();
        });

        // Window hash change listener for link decryption
        window.addEventListener("hashchange", () => {
            this.checkUrlFragmentRoute();
        });
    }

    // ========================================================================
    // Navigation & Tabs
    // ========================================================================

    navigate(view) {
        if (view === "vault") {
            window.location.hash = "";
            document.getElementById("view-download")?.classList.add("hidden");
            document.getElementById("view-dashboard")?.classList.remove("hidden");
            this.switchTab("vault");
        }
    }

    switchTab(tab) {
        const tabs = ["vault", "upload", "shared", "manual"];
        tabs.forEach(t => {
            const btn = document.getElementById(`tab-btn-${t}`);
            const content = document.getElementById(`tab-content-${t}`);
            if (t === tab) {
                btn?.classList.add("tab-btn-active");
                content?.classList.remove("hidden");
            } else {
                btn?.classList.remove("tab-btn-active");
                content?.classList.add("hidden");
            }
        });

        if (tab === "vault" || tab === "shared") {
            this.refreshVault();
        }
        if (tab === "upload") {
            this.loadAvailableUsers();
        }
    }

    // ========================================================================
    // Authentication & Key Management
    // ========================================================================

    showAuthModal(mode = 'login') {
        this.authMode = mode;
        this.updateAuthModalUI();
        document.getElementById("auth-modal")?.classList.remove("hidden");
    }

    closeAuthModal() {
        document.getElementById("auth-modal")?.classList.add("hidden");
        document.getElementById("auth-status-box")?.classList.add("hidden");
    }

    updateAuthModalUI() {
        const title = document.getElementById("auth-modal-title");
        const desc = document.getElementById("auth-modal-desc");
        const submitBtn = document.getElementById("btn-auth-submit");
        const toggleBtn = document.getElementById("btn-toggle-auth-mode");

        if (this.authMode === "login") {
            title.textContent = "Log in";
            desc.textContent = "Your password never leaves your device — it's used locally to derive your encryption keys.";
            submitBtn.textContent = "Log in";
            toggleBtn.textContent = "Don't have an account? Sign up";
        } else {
            title.textContent = "Create your account";
            desc.textContent = "We'll generate your encryption keys right here in your browser. Your password never leaves your device.";
            submitBtn.textContent = "Create account";
            toggleBtn.textContent = "Already have an account? Log in";
        }
    }

    async handleAuthSubmit() {
        const username = document.getElementById("auth-username").value.trim();
        const passphrase = document.getElementById("auth-password").value;
        const statusBox = document.getElementById("auth-status-box");
        const statusText = document.getElementById("auth-status-text");

        if (!username || !passphrase) {
            alert("Please enter both username and passphrase.");
            return;
        }

        statusBox.classList.remove("hidden");

        try {
            if (this.authMode === "register") {
                statusText.textContent = "1/3 Deriving Master Keys via PBKDF2 (100,000 rounds)...";
                this.log(`[AUTH] Starting PBKDF2 key derivation for '${username}' (100k rounds)...`, "crypto");

                // 1. Derive master keys (authHash + KEK)
                const { authHash, kek, saltBase64 } = await this.crypto.deriveMasterKeys(passphrase);
                this.log(`[AUTH] Master keys derived. authHash generated. KEK locked in RAM.`, "crypto");

                // 2. Generate RSA-OAEP Keypair and encrypt private key with KEK
                statusText.textContent = "2/3 Generating RSA-2048 Asymmetric Keypair...";
                this.log(`[AUTH] Generating RSA-OAEP 2048-bit keypair...`, "crypto");
                const { publicKeyJwk, encryptedPrivateKey, rawPrivateKey } = await this.crypto.generateAsymmetricKeyPair(kek);
                this.log(`[AUTH] Private key encrypted with KEK via AES-256-GCM.`, "crypto");

                // 3. Register with backend
                statusText.textContent = "3/3 Registering with Zero-Knowledge backend...";
                const res = await fetch("/api/register", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({
                        username,
                        salt: saltBase64,
                        auth_hash: authHash,
                        public_key_jwk: typeof publicKeyJwk === 'string' ? publicKeyJwk : JSON.stringify(publicKeyJwk),
                        encrypted_private_key: JSON.stringify(encryptedPrivateKey)
                    })
                });

                if (!res.ok) {
                    const err = await res.json();
                    throw new Error(err.detail || "Registration failed");
                }

                const data = await res.json();
                let parsedPubJwk = data.public_key_jwk;
                while (typeof parsedPubJwk === 'string') {
                    try { parsedPubJwk = JSON.parse(parsedPubJwk); } catch (e) { break; }
                }

                this.currentUser = {
                    userId: data.user_id,
                    username: data.username,
                    publicKeyJwk: parsedPubJwk,
                    token: data.access_token
                };
                this.unlockedPrivateKey = rawPrivateKey;
                sessionStorage.setItem("zero_token", data.access_token);
                sessionStorage.setItem("zero_user", JSON.stringify(this.currentUser));

                this.log(`[AUTH] User '${username}' registered and authenticated successfully.`, "success");
                this.closeAuthModal();
                this.updateUserSessionUI();
                this.refreshVault();

            } else {
                // LOGIN FLOW
                statusText.textContent = "1/3 Fetching user salt...";
                this.log(`[AUTH] Fetching salt for '${username}'...`, "info");
                const saltRes = await fetch(`/api/users/${encodeURIComponent(username)}/salt`);
                if (!saltRes.ok) {
                    throw new Error("User not found or network error.");
                }
                const { salt } = await saltRes.json();

                // Derive keys with existing salt
                statusText.textContent = "2/3 Reconstructing keys via PBKDF2 (100,000 rounds)...";
                this.log(`[AUTH] Computing PBKDF2 hash using user salt...`, "crypto");
                const { authHash, kek } = await this.crypto.deriveMasterKeys(passphrase, salt);

                // Authenticate
                statusText.textContent = "3/3 Validating session & decrypting RSA private key...";
                const loginRes = await fetch("/api/login", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ username, auth_hash: authHash })
                });

                if (!loginRes.ok) {
                    throw new Error("Invalid username or passphrase.");
                }

                const data = await loginRes.json();
                
                // Decrypt stored private key with KEK
                let encryptedPrivBlob = data.encrypted_private_key;
                while (typeof encryptedPrivBlob === 'string') {
                    try { encryptedPrivBlob = JSON.parse(encryptedPrivBlob); } catch (e) { break; }
                }
                this.unlockedPrivateKey = await this.crypto.decryptPrivateKey(encryptedPrivBlob, kek);
                this.log(`[AUTH] RSA Private key unlocked in browser memory.`, "success");

                let parsedPubJwk = data.public_key_jwk;
                while (typeof parsedPubJwk === 'string') {
                    try { parsedPubJwk = JSON.parse(parsedPubJwk); } catch (e) { break; }
                }

                this.currentUser = {
                    userId: data.user_id,
                    username: data.username,
                    publicKeyJwk: parsedPubJwk,
                    token: data.access_token
                };
                sessionStorage.setItem("zero_token", data.access_token);
                sessionStorage.setItem("zero_user", JSON.stringify(this.currentUser));

                this.closeAuthModal();
                this.updateUserSessionUI();
                this.refreshVault();
            }
        } catch (err) {
            const errDetail = err && err.message ? err.message : String(err);
            this.log(`[AUTH ERROR] ${errDetail}`, "warn");
            alert(errDetail);
        } finally {
            statusBox.classList.add("hidden");
        }
    }

    async checkExistingSession() {
        const token = sessionStorage.getItem("zero_token");
        const userStr = sessionStorage.getItem("zero_user");

        if (token && userStr) {
            try {
                this.currentUser = JSON.parse(userStr);
                this.currentUser.token = token;

                // Validate token with backend /api/me
                const meRes = await fetch("/api/me", {
                    headers: { "Authorization": `Bearer ${token}` }
                });

                if (!meRes.ok) {
                    this.log("[SESSION] Previous session token expired or invalid on server. Resetting session.", "warn");
                    this.logout();
                    return;
                }

                const meData = await meRes.json();
                let parsedPubJwk = meData.public_key_jwk;
                while (typeof parsedPubJwk === 'string') {
                    try { parsedPubJwk = JSON.parse(parsedPubJwk); } catch (e) { break; }
                }
                this.currentUser.publicKeyJwk = parsedPubJwk;

                this.updateUserSessionUI();
                this.refreshVault();
                this.log(`[SESSION] Active session verified for '${this.currentUser.username}'.`, "info");
            } catch (e) {
                this.logout();
            }
        } else {
            this.updateUserSessionUI();
        }
    }

    logout() {
        this.currentUser = null;
        this.unlockedPrivateKey = null;
        sessionStorage.removeItem("zero_token");
        sessionStorage.removeItem("zero_user");
        this.updateUserSessionUI();
        this.log(`[AUTH] Session terminated. Private key erased from RAM.`, "info");
        this.refreshVault();
    }

    updateUserSessionUI() {
        const userPill = document.getElementById("user-pill");
        const authNavButtons = document.getElementById("auth-nav-buttons");
        const navUsername = document.getElementById("nav-username");

        const heroSection = document.getElementById("hero-section");
        const dashboard = document.getElementById("view-dashboard");

        if (this.currentUser) {
            userPill?.classList.remove("hidden");
            userPill?.style && (userPill.style.display = 'flex');
            authNavButtons?.classList.add("hidden");
            if (navUsername) navUsername.textContent = this.currentUser.username;
            heroSection?.classList.add("hidden");
            dashboard?.classList.remove("hidden");
        } else {
            userPill?.classList.add("hidden");
            userPill?.style && (userPill.style.display = 'none');
            authNavButtons?.classList.remove("hidden");
            authNavButtons?.style && (authNavButtons.style.display = 'flex');
            heroSection?.classList.remove("hidden");
            dashboard?.classList.add("hidden");
        }
    }

    // ========================================================================
    // File Selection & Encryption / Upload
    // ========================================================================

    handleFileSelected(file) {
        this.selectedFile = file;
        const badge = document.getElementById("selected-file-badge");
        const nameEl = document.getElementById("selected-file-name");
        const sizeEl = document.getElementById("selected-file-size");
        const btn = document.getElementById("btn-start-encrypt");

        if (badge && nameEl && sizeEl) {
            nameEl.textContent = file.name;
            sizeEl.textContent = `(${this.formatBytes(file.size)})`;
            badge.classList.remove("hidden");
        }

        if (btn) {
            btn.disabled = false;
            btn.style.opacity = '1';
            btn.style.cursor = 'pointer';
            btn.innerHTML = `
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/></svg>
                <span>Encrypt & upload "${file.name}"</span>
            `;
        }
    }

    async handleEncryptAndUpload() {
        if (!this.selectedFile) return;

        if (!this.currentUser) {
            this.showAuthModal("login");
            return;
        }

        const shareMode = document.querySelector('input[name="share-mode"]:checked')?.value || "link";
        const inputRecipient = document.getElementById("target-recipient-input")?.value.trim();
        const selectRecipient = document.getElementById("user-dropdown-picker")?.value.trim();
        const targetRecipient = inputRecipient || selectRecipient || "";
        const filePassword = document.getElementById("upload-file-password")?.value.trim() || null;

        if (shareMode === "user" && !targetRecipient) {
            alert("Please specify or select a target recipient username.");
            return;
        }

        const btn = document.getElementById("btn-start-encrypt");
        if (btn) {
            btn.disabled = true;
            btn.innerHTML = `<svg class="w-5 h-5 animate-spin mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24"><circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle><path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v8H4z"></path></svg> Encrypting locally with AES-256-GCM...`;
        }

        try {
            this.log(`[ENCRYPT] Reading plaintext bytes for '${this.selectedFile.name}'...`, "info");
            const fileBuffer = await this.selectedFile.arrayBuffer();

            // 1. Local AES-256-GCM Encryption with optional extra file password layer
            this.log(`[ENCRYPT] Generating 256-bit DEK and 12-byte IV...`, "crypto");
            if (filePassword) {
                this.log(`[ENCRYPT] Applying secondary PBKDF2 file password protection layer...`, "crypto");
            }

            const { ciphertextBlob, ivBase64, rawDekBuffer, rawDekBase64Url, encryptedMetadata } = await this.crypto.encryptFile(
                fileBuffer,
                this.selectedFile.name,
                this.selectedFile.type || "application/octet-stream",
                filePassword
            );
            this.log(`[ENCRYPT] AES-256-GCM file encryption complete. Auth tag appended.`, "success");

            // 2. Prepare Wrapped DEKs
            const wrappedKeyItems = [];

            // Always wrap with current user's public key so owner can unlock in their vault
            if (!this.currentUser.publicKeyJwk) {
                // Fetch public key if missing
                const myPkRes = await fetch(`/api/users/${encodeURIComponent(this.currentUser.username)}/public-key`);
                if (myPkRes.ok) {
                    const myPkData = await myPkRes.json();
                    let pk = myPkData.public_key_jwk;
                    while (typeof pk === 'string') {
                        try { pk = JSON.parse(pk); } catch (e) { break; }
                    }
                    this.currentUser.publicKeyJwk = pk;
                }
            }

            const ownerWrappedKey = await this.crypto.wrapKeyForRecipient(rawDekBuffer, this.currentUser.publicKeyJwk);
            wrappedKeyItems.push({
                recipient_username: this.currentUser.username,
                wrapped_key: ownerWrappedKey
            });
            this.log(`[ENCRYPT] DEK wrapped with owner's RSA-OAEP public key.`, "crypto");

            // If targeted user share, fetch recipient's public key and wrap for them
            if (shareMode === "user") {
                this.log(`[ENCRYPT] Fetching public key for recipient '${targetRecipient}'...`, "info");
                const pubKeyRes = await fetch(`/api/users/${encodeURIComponent(targetRecipient)}/public-key`);
                if (!pubKeyRes.ok) {
                    throw new Error(`Recipient user '${targetRecipient}' not found on server.`);
                }
                const { public_key_jwk: recPubKeyStr } = await pubKeyRes.json();
                let recPubKeyJwk = recPubKeyStr;
                while (typeof recPubKeyJwk === 'string') {
                    try { recPubKeyJwk = JSON.parse(recPubKeyJwk); } catch (e) { break; }
                }

                const recWrappedKey = await this.crypto.wrapKeyForRecipient(rawDekBuffer, recPubKeyJwk);
                wrappedKeyItems.push({
                    recipient_username: targetRecipient,
                    wrapped_key: recWrappedKey
                });
                this.log(`[ENCRYPT] DEK wrapped with recipient '${targetRecipient}' RSA-OAEP public key.`, "crypto");
            }

            // 3. Upload Encrypted Payload to Blind Server Vault
            this.log(`[UPLOAD] Transmitting blind ciphertext blob (${this.formatBytes(ciphertextBlob.size)}) to server...`, "info");
            const formData = new FormData();
            formData.append("file", ciphertextBlob, "encrypted.bin");
            formData.append("iv", ivBase64);
            formData.append("encrypted_metadata", JSON.stringify(encryptedMetadata));
            formData.append("wrapped_keys", JSON.stringify(wrappedKeyItems));

            const uploadRes = await fetch("/api/upload", {
                method: "POST",
                headers: {
                    "Authorization": `Bearer ${this.currentUser.token}`
                },
                body: formData
            });

            if (!uploadRes.ok) {
                let detail = "Upload failed";
                try {
                    const errObj = await uploadRes.json();
                    if (errObj && errObj.detail) {
                        detail = typeof errObj.detail === 'object' ? JSON.stringify(errObj.detail) : errObj.detail;
                    }
                } catch (e) {
                    detail = `HTTP ${uploadRes.status}: ${uploadRes.statusText}`;
                }
                if (uploadRes.status === 401) {
                    this.logout();
                    this.showAuthModal("login");
                    throw new Error("Your session token is expired or invalid. Please sign in again.");
                }
                throw new Error(detail);
            }

            const result = await uploadRes.json();
            this.log(`[VAULT] File successfully stored with ID: ${result.file_id}`, "success");

            // Always display the share link option so user has both capabilities!
            const shareUrl = `${window.location.origin}/#/download/${result.file_id}?key=${rawDekBase64Url}`;
            document.getElementById("share-link-input").value = shareUrl;
            
            if (shareMode === "user") {
                document.getElementById("share-modal-title").textContent = `Shared with ${targetRecipient} & Link Ready`;
                document.getElementById("share-modal-desc").textContent = `File is encrypted for ${targetRecipient}. You can also copy this anonymous direct link:`;
            } else {
                document.getElementById("share-modal-title").textContent = `Encrypted Share Link Ready`;
                document.getElementById("share-modal-desc").textContent = `Anyone with this link can decrypt the file. The key is in the URL hash and never seen by the server.`;
            }
            document.getElementById("link-modal")?.classList.remove("hidden");

            // Reset upload UI and refresh vault
            this.selectedFile = null;
            const pwInput = document.getElementById("upload-file-password");
            if (pwInput) pwInput.value = "";
            document.getElementById("selected-file-badge")?.classList.add("hidden");
            this.switchTab("vault");

        } catch (err) {
            let errDetail;
            if (err instanceof DOMException) {
                errDetail = err.message || err.name || "WebCrypto DOMException (no details)";
            } else if (err && err.message) {
                errDetail = err.message;
            } else {
                errDetail = String(err);
            }
            this.log(`[ENCRYPT ERROR] ${errDetail}`, "warn");
            console.error("[ENCRYPT ERROR] Full error object:", err);
            alert(`Encryption/Sharing failed: ${errDetail}`);
        } finally {
            if (btn) {
                btn.disabled = false;
                btn.innerHTML = `<span>Encrypt and Upload</span>`;
            }
        }
    }

    handleFileSelectedReset() {
        const fileInput = document.getElementById("file-input");
        if (fileInput) fileInput.value = "";
        const btn = document.getElementById("btn-start-encrypt");
        if (btn) {
            btn.disabled = true;
            btn.style.opacity = '0.4';
            btn.style.cursor = 'not-allowed';
            btn.innerHTML = `
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/></svg>
                <span>Select a file first</span>
            `;
        }
    }

    // ========================================================================
    // Vault Rendering & Decrypt Actions
    // ========================================================================

    async refreshVault() {
        const vaultBody = document.getElementById("vault-table-body");
        const sharedBody = document.getElementById("shared-table-body");
        const sharedBadge = document.getElementById("shared-count-badge");

        if (!this.currentUser) {
            if (vaultBody) vaultBody.innerHTML = `<tr><td colspan="6" class="px-6 py-8 text-center text-slate-500">Sign in to view your encrypted vault.</td></tr>`;
            if (sharedBody) sharedBody.innerHTML = `<tr><td colspan="6" class="px-6 py-8 text-center text-slate-500">Sign in to view shared files.</td></tr>`;
            return;
        }

        try {
            const res = await fetch("/api/vault", {
                headers: { "Authorization": `Bearer ${this.currentUser.token}` }
            });
            if (!res.ok) throw new Error("Could not fetch vault data");
            const data = await res.json();

            // Render Owned Vault Files
            if (vaultBody) {
                if (data.owned_files.length === 0) {
                    vaultBody.innerHTML = `<tr><td colspan="6" class="px-6 py-8 text-center text-slate-500">Your vault is empty. Upload your first encrypted file!</td></tr>`;
                } else {
                    vaultBody.innerHTML = "";
                    for (const file of data.owned_files) {
                        vaultBody.appendChild(await this.createFileRow(file, false));
                    }
                }
            }

            // Render Shared With Me Files
            if (sharedBody) {
                if (data.shared_files.length === 0) {
                    sharedBody.innerHTML = `<tr><td colspan="6" class="px-6 py-8 text-center text-slate-500">No files currently shared with you.</td></tr>`;
                    if (sharedBadge) sharedBadge.classList.add("hidden");
                } else {
                    sharedBody.innerHTML = "";
                    if (sharedBadge) {
                        sharedBadge.textContent = data.shared_files.length;
                        sharedBadge.classList.remove("hidden");
                    }
                    for (const file of data.shared_files) {
                        sharedBody.appendChild(await this.createFileRow(file, true));
                    }
                }
            }
        } catch (err) {
            this.log(`[VAULT ERROR] ${err.message}`, "warn");
        }
    }

    async createFileRow(file, isShared = false) {
        const tr = document.createElement("tr");

        // Attempt local metadata decryption if we have private key in RAM
        let displayName = file.file_id.substring(0, 12) + "...";
        let displayMime = "Unknown";
        let isPwProtected = false;

        if (this.unlockedPrivateKey && file.wrapped_key) {
            try {
                const rawDek = await this.crypto.unwrapKeyWithPrivateKey(file.wrapped_key, this.unlockedPrivateKey);
                let metaObj = file.encrypted_metadata;
                while (typeof metaObj === 'string') {
                    try { metaObj = JSON.parse(metaObj); } catch (e) { break; }
                }
                const meta = await this.crypto.decryptMetadata(metaObj, rawDek);
                displayName = meta.fileName || displayName;
                displayMime = meta.mimeType || displayMime;
                isPwProtected = meta.passwordProtected || false;
            } catch (e) {}
        }

        const dateFormatted = new Date(file.created_at).toLocaleDateString(undefined, {
            month: "short", day: "numeric", hour: "2-digit", minute: "2-digit"
        });

        const pwBadge = isPwProtected 
            ? `<span class="badge badge-amber">🔐 Password</span>`
            : `<span class="badge badge-zinc">Standard</span>`;

        if (!isShared) {
            const sharesList = file.shared_with && file.shared_with.length > 0 
                ? file.shared_with.map(u => `<span class="badge badge-purple">${u}</span>`).join(" ")
                : `<span style="font-size: 12px; color: var(--text-muted);">Only you</span>`;

            tr.innerHTML = `
                <td style="display: flex; align-items: center; gap: 12px;">
                    <div style="width: 32px; height: 32px; border-radius: 8px; background: var(--accent-muted); display: flex; align-items: center; justify-content: center; flex-shrink: 0;">
                        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#8B5CF6" stroke-width="2"><path d="M13 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V9z"/><polyline points="13 2 13 9 20 9"/></svg>
                    </div>
                    <div style="min-width: 0;">
                        <div style="font-weight: 600; font-size: 14px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">${displayName}</div>
                        <div class="font-mono" style="font-size: 11px; color: var(--text-muted); overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">${file.file_id}</div>
                    </div>
                </td>
                <td class="font-mono" style="font-size: 13px; color: var(--text-secondary);">${this.formatBytes(file.file_size)}</td>
                <td style="font-size: 13px; color: var(--text-muted);">${dateFormatted}</td>
                <td>${pwBadge}</td>
                <td>${sharesList}</td>
                <td style="text-align: right; white-space: nowrap;">
                    <button class="btn-share-modal btn btn-ghost btn-sm" style="font-size: 12px;">Share</button>
                    <button class="btn-dl-file btn btn-sm" style="font-size: 12px; background: var(--accent-muted); color: #C4B5FD;">Download</button>
                    <button class="btn-del-file btn btn-ghost btn-sm btn-danger" style="font-size: 12px; padding: 6px 8px;" title="Delete">
                        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M3 6h18M19 6v14a2 2 0 01-2 2H7a2 2 0 01-2-2V6m3 0V4a2 2 0 012-2h4a2 2 0 012 2v2"/></svg>
                    </button>
                </td>
            `;

            tr.querySelector(".btn-share-modal")?.addEventListener("click", () => this.openVaultShareModal(file, displayName));
            tr.querySelector(".btn-dl-file")?.addEventListener("click", () => this.downloadAndDecryptVaultFile(file));
            tr.querySelector(".btn-del-file")?.addEventListener("click", () => this.deleteVaultFile(file.file_id));
        } else {
            tr.innerHTML = `
                <td style="display: flex; align-items: center; gap: 12px;">
                    <div style="width: 32px; height: 32px; border-radius: 8px; background: rgba(34,197,94,0.12); display: flex; align-items: center; justify-content: center; flex-shrink: 0;">
                        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#22C55E" stroke-width="2"><path d="M13 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V9z"/><polyline points="13 2 13 9 20 9"/></svg>
                    </div>
                    <div style="min-width: 0;">
                        <div style="font-weight: 600; font-size: 14px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">${displayName}</div>
                        <div class="font-mono" style="font-size: 11px; color: var(--text-muted);">${file.file_id}</div>
                    </div>
                </td>
                <td style="font-size: 13px; font-weight: 500; color: var(--accent);">${file.owner_username}</td>
                <td class="font-mono" style="font-size: 13px; color: var(--text-secondary);">${this.formatBytes(file.file_size)}</td>
                <td>${pwBadge}</td>
                <td style="font-size: 13px; color: var(--text-muted);">${dateFormatted}</td>
                <td style="text-align: right;">
                    <button class="btn-dl-file btn btn-sm" style="font-size: 12px; background: var(--accent-muted); color: #C4B5FD;">Download</button>
                </td>
            `;

            tr.querySelector(".btn-dl-file")?.addEventListener("click", () => this.downloadAndDecryptVaultFile(file));
        }

        return tr;
    }

    async openVaultShareModal(file, displayName) {
        this.activeShareFile = file;
        const modal = document.getElementById("vault-share-modal");
        const filenameEl = document.getElementById("vault-share-filename");
        const linkResult = document.getElementById("vault-link-result-box");
        const userDropdown = document.getElementById("vault-share-user-dropdown");

        if (filenameEl) filenameEl.textContent = `${displayName} (${file.file_id})`;
        if (linkResult) linkResult.classList.add("hidden");

        // Load users for dropdown
        if (userDropdown && this.currentUser) {
            try {
                const res = await fetch("/api/users", {
                    headers: { "Authorization": `Bearer ${this.currentUser.token}` }
                });
                if (res.ok) {
                    const users = await res.json();
                    userDropdown.innerHTML = `<option value="">Select user...</option>` + 
                        users.map(u => `<option value="${u}">${u}</option>`).join("");
                }
            } catch (e) {}
        }

        modal?.classList.remove("hidden");
    }

    async generateVaultFileShareLink() {
        if (!this.activeShareFile || !this.unlockedPrivateKey) {
            alert("Please unlock your private key by signing in.");
            return;
        }

        try {
            this.log(`[SHARE] Unwrapping DEK for link generation...`, "crypto");
            const rawDek = await this.crypto.unwrapKeyWithPrivateKey(this.activeShareFile.wrapped_key, this.unlockedPrivateKey);
            const rawDekBase64Url = CryptoEngine.bufferToBase64Url(rawDek);

            const shareUrl = `${window.location.origin}/#/download/${this.activeShareFile.file_id}?key=${rawDekBase64Url}`;
            
            const linkInput = document.getElementById("vault-share-link-input");
            const resultBox = document.getElementById("vault-link-result-box");
            if (linkInput && resultBox) {
                linkInput.value = shareUrl;
                resultBox.classList.remove("hidden");
            }
            this.log(`[SHARE] Anonymous link generated with DEK inside fragment.`, "success");
        } catch (err) {
            alert(`Failed to generate link: ${err.message}`);
        }
    }

    copyVaultShareLink() {
        const input = document.getElementById("vault-share-link-input");
        if (input) {
            input.select();
            navigator.clipboard.writeText(input.value);
            alert("Share link copied to clipboard!");
        }
    }

    async shareVaultFileWithUser() {
        const targetRecipient = document.getElementById("vault-share-recipient-input")?.value.trim();
        if (!targetRecipient) {
            alert("Please enter or select a recipient username.");
            return;
        }

        if (!this.activeShareFile || !this.unlockedPrivateKey) {
            alert("Please unlock your private key first.");
            return;
        }

        try {
            this.log(`[SHARE] Fetching public key for '${targetRecipient}'...`, "info");
            const pubKeyRes = await fetch(`/api/users/${encodeURIComponent(targetRecipient)}/public-key`);
            if (!pubKeyRes.ok) throw new Error(`User '${targetRecipient}' not found.`);
            const { public_key_jwk: recPubKeyStr } = await pubKeyRes.json();
            let recPubKeyJwk = recPubKeyStr;
            while (typeof recPubKeyJwk === 'string') {
                try { recPubKeyJwk = JSON.parse(recPubKeyJwk); } catch (e) { break; }
            }

            // 1. Unwrap DEK using owner private key
            const rawDek = await this.crypto.unwrapKeyWithPrivateKey(this.activeShareFile.wrapped_key, this.unlockedPrivateKey);

            // 2. Wrap DEK with recipient's RSA public key
            const wrappedKey = await this.crypto.wrapKeyForRecipient(rawDek, recPubKeyJwk);

            // 3. Post share entry to backend
            const shareRes = await fetch(`/api/files/${this.activeShareFile.file_id}/share`, {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                    "Authorization": `Bearer ${this.currentUser.token}`
                },
                body: JSON.stringify({
                    recipient_username: targetRecipient,
                    wrapped_key: wrappedKey
                })
            });

            if (!shareRes.ok) {
                const err = await shareRes.json();
                throw new Error(err.detail || "Sharing failed");
            }

            this.log(`[SHARE] File successfully shared with '${targetRecipient}'.`, "success");
            alert(`File successfully shared with '${targetRecipient}'.`);
            document.getElementById("vault-share-modal")?.classList.add("hidden");
            this.refreshVault();

        } catch (err) {
            alert(`Sharing error: ${err.message}`);
        }
    }

    async downloadAndDecryptVaultFile(file) {
        if (!this.unlockedPrivateKey) {
            alert("Private key not unlocked in memory. Please sign in again.");
            return;
        }

        try {
            this.log(`[DECRYPT] Unwrapping DEK using local RSA-OAEP private key...`, "crypto");
            let rawDek = await this.crypto.unwrapKeyWithPrivateKey(file.wrapped_key, this.unlockedPrivateKey);

            // Decrypt Metadata
            let metaObj = file.encrypted_metadata;
            while (typeof metaObj === 'string') {
                try { metaObj = JSON.parse(metaObj); } catch (e) { break; }
            }
            const meta = await this.crypto.decryptMetadata(metaObj, rawDek);
            const fileName = meta.fileName || "decrypted_file.bin";
            const mimeType = meta.mimeType || "application/octet-stream";

            // If file was additionally password-protected, prompt the recipient for the file password
            if (meta.passwordProtected && meta.passwordWrappedDek) {
                const userPassword = prompt(`🔒 This file "${fileName}" is password-protected by the sender. Please enter the file access password to decrypt:`);
                if (!userPassword) {
                    alert("Password required to access this file.");
                    return;
                }
                this.log(`[DECRYPT] Unwrapping secondary password layer via PBKDF2...`, "crypto");
                try {
                    rawDek = await this.crypto.unwrapDekWithFilePassword(
                        meta.passwordWrappedDek,
                        meta.passwordSalt,
                        meta.passwordIv,
                        userPassword
                    );
                } catch (pwErr) {
                    throw new Error("Incorrect file access password! Decryption aborted.");
                }
            }

            this.log(`[FETCH] Downloading ciphertext blob (${file.file_id})...`, "info");
            const blobRes = await fetch(`/api/files/${file.file_id}/download`);
            if (!blobRes.ok) throw new Error("Could not download encrypted file blob.");

            const ciphertextBuffer = await blobRes.arrayBuffer();

            this.log(`[DECRYPT] Decrypting ${this.formatBytes(ciphertextBuffer.byteLength)} with AES-256-GCM...`, "crypto");
            await this.crypto.decryptAndDownloadFile(ciphertextBuffer, rawDek, file.iv, fileName, mimeType);
            this.log(`[SUCCESS] Decrypted '${fileName}' directly in browser memory.`, "success");

        } catch (err) {
            this.log(`[DECRYPT ERROR] ${err.message}`, "warn");
            alert(`Decryption failed: ${err.message}`);
        }
    }

    async deleteVaultFile(fileId) {
        if (!confirm("Are you sure you want to permanently delete this encrypted file?")) return;

        try {
            const res = await fetch(`/api/files/${fileId}`, {
                method: "DELETE",
                headers: { "Authorization": `Bearer ${this.currentUser.token}` }
            });
            if (!res.ok) throw new Error("Delete failed");
            this.log(`[VAULT] File ${fileId} deleted.`, "info");
            this.refreshVault();
        } catch (err) {
            alert(err.message);
        }
    }

    // ========================================================================
    // URL Fragment Anonymous Link Sharing Router (#/download/:id#key=...)
    // ========================================================================

    async checkUrlFragmentRoute() {
        const hash = window.location.hash;
        if (!hash.startsWith("#/download/")) return;

        // Parse format: #/download/<file_id>?key=<rawDekBase64Url>
        const parts = hash.split("?key=");
        const fileId = parts[0].replace("#/download/", "").trim();
        const rawDekBase64Url = parts[1] ? parts[1].trim() : null;

        if (!fileId || !rawDekBase64Url) return;

        // Show Download View
        document.getElementById("view-dashboard")?.classList.add("hidden");
        const dlView = document.getElementById("view-download");
        dlView?.classList.remove("hidden");

        this.log(`[ANONYMOUS LINK] Detected link for file ${fileId}. Key parsed from URL fragment.`, "crypto");

        // Populate Metadata preview
        try {
            const infoRes = await fetch(`/api/files/${fileId}/info`);
            if (!infoRes.ok) throw new Error("File not found on blind vault.");
            const fileInfo = await infoRes.json();

            document.getElementById("dl-file-id").textContent = fileInfo.file_id;
            document.getElementById("dl-owner").textContent = fileInfo.owner_username;
            document.getElementById("dl-size").textContent = this.formatBytes(fileInfo.file_size);

            // Check if metadata indicates password protection
            const rawDekBytes = CryptoEngine.base64UrlToBuffer(rawDekBase64Url);
            let meta = null;
            try {
                let metaObj = fileInfo.encrypted_metadata;
                while (typeof metaObj === 'string') {
                    try { metaObj = JSON.parse(metaObj); } catch (e) { break; }
                }
                meta = await this.crypto.decryptMetadata(metaObj, rawDekBytes);
                if (meta && meta.passwordProtected) {
                    document.getElementById("dl-password-box")?.classList.remove("hidden");
                    document.getElementById("dl-key-status").textContent = "Password Protected + Key in Fragment";
                }
            } catch (e) {}

            // Bind execute download button
            const dlBtn = document.getElementById("btn-execute-download");
            dlBtn.onclick = () => this.executeAnonymousDecrypt(fileInfo, rawDekBase64Url, meta);

        } catch (err) {
            this.log(`[LINK ERROR] ${err.message}`, "warn");
            alert(`Could not load shared file info: ${err.message}`);
        }
    }

    async executeAnonymousDecrypt(fileInfo, rawDekBase64Url, parsedMeta = null) {
        const dlBtn = document.getElementById("btn-execute-download");
        const dlLabel = document.getElementById("dl-button-label");

        if (dlBtn) dlBtn.disabled = true;
        if (dlLabel) dlLabel.textContent = "Decrypting with AES-256-GCM in memory...";

        try {
            this.log(`[ANONYMOUS] Importing raw DEK from URL fragment...`, "crypto");
            let rawDekBytes = CryptoEngine.base64UrlToBuffer(rawDekBase64Url);

            // Decrypt Metadata
            let fileName = "shared_file.bin";
            let mimeType = "application/octet-stream";
            let meta = parsedMeta;

            if (!meta) {
                try {
                    let metaObj = fileInfo.encrypted_metadata;
                    while (typeof metaObj === 'string') {
                        try { metaObj = JSON.parse(metaObj); } catch (e) { break; }
                    }
                    meta = await this.crypto.decryptMetadata(metaObj, rawDekBytes);
                } catch (e) {}
            }

            if (meta) {
                fileName = meta.fileName || fileName;
                mimeType = meta.mimeType || mimeType;

                // If password protected, require password
                if (meta.passwordProtected && meta.passwordWrappedDek) {
                    const inputPassword = document.getElementById("dl-file-password")?.value.trim();
                    if (!inputPassword) {
                        throw new Error("This file is password-protected. Please enter the password above.");
                    }
                    this.log(`[ANONYMOUS] Unwrapping DEK with user password...`, "crypto");
                    try {
                        rawDekBytes = await this.crypto.unwrapDekWithFilePassword(
                            meta.passwordWrappedDek,
                            meta.passwordSalt,
                            meta.passwordIv,
                            inputPassword
                        );
                    } catch (pwErr) {
                        throw new Error("Incorrect file access password! Decryption failed.");
                    }
                }
            }

            this.log(`[ANONYMOUS] Fetching ciphertext blob from server...`, "info");
            const blobRes = await fetch(`/api/files/${fileInfo.file_id}/download`);
            if (!blobRes.ok) throw new Error("Failed to fetch encrypted payload from server.");

            const ciphertextBuffer = await blobRes.arrayBuffer();

            this.log(`[ANONYMOUS] Decrypting file payload with authenticated AES-GCM...`, "crypto");
            await this.crypto.decryptAndDownloadFile(ciphertextBuffer, rawDekBytes, fileInfo.iv, fileName, mimeType);

            this.log(`[SUCCESS] File '${fileName}' decrypted and saved!`, "success");
            if (dlLabel) dlLabel.textContent = "Decryption Complete! File Saved.";

        } catch (err) {
            this.log(`[DECRYPT ERROR] ${err.message}`, "warn");
            alert(`Decryption failed: ${err.message}`);
            if (dlLabel) dlLabel.textContent = "Decryption Failed";
        } finally {
            if (dlBtn) dlBtn.disabled = false;
        }
    }

    // ========================================================================
    // Manual Decrypt Tool
    // ========================================================================

    async handleManualDecrypt() {
        const fileInput = document.getElementById("manual-file-input");
        const keyInput = document.getElementById("manual-key-input")?.value.trim();
        const ivInput = document.getElementById("manual-iv-input")?.value.trim();

        if (!fileInput.files || fileInput.files.length === 0) {
            alert("Please select an encrypted file to decrypt.");
            return;
        }
        if (!keyInput) {
            alert("Please enter the DEK key or file password.");
            return;
        }

        const file = fileInput.files[0];
        this.log(`[MANUAL] Reading encrypted file '${file.name}'...`, "info");

        try {
            const buffer = await file.arrayBuffer();
            let dekKey;
            let iv = ivInput;

            // Check if key is a 32-byte Base64 / Base64URL string or passphrase
            if (keyInput.length >= 40 && (keyInput.includes("-") || keyInput.includes("_") || keyInput.includes("+") || keyInput.includes("="))) {
                // Treat as Base64/Base64URL DEK
                dekKey = CryptoEngine.base64UrlToBuffer(keyInput);
            } else {
                // Treat as PBKDF2 file password
                const { key } = await this.crypto.deriveKeyFromFilePassword(keyInput);
                dekKey = key;
            }

            if (!iv) {
                alert("Please provide the 12-byte IV for manual AES-GCM decryption.");
                return;
            }

            this.log(`[MANUAL] Executing AES-256-GCM authenticated decryption...`, "crypto");
            const decryptedBuffer = await this.crypto.decryptFileBuffer(buffer, dekKey, iv);
            
            // Trigger download
            const blob = new Blob([decryptedBuffer], { type: "application/octet-stream" });
            const outName = file.name.replace(/\.enc$/i, "").replace(/\.bin$/i, "") + "_decrypted";
            const url = URL.createObjectURL(blob);
            const a = document.createElement("a");
            a.href = url;
            a.download = outName;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            setTimeout(() => URL.revokeObjectURL(url), 10000);

            this.log(`[MANUAL] Decryption successful! File saved as '${outName}'.`, "success");
            alert(`Decryption successful! Saved as ${outName}.`);

        } catch (err) {
            this.log(`[MANUAL ERROR] ${err.message}`, "warn");
            alert(`Manual decryption failed: ${err.message}`);
        }
    }

    // ========================================================================
    // Helpers & User Utilities
    // ========================================================================

    async loadAvailableUsers() {
        if (!this.currentUser) return;
        const picker = document.getElementById("user-dropdown-picker");
        if (!picker) return;

        try {
            const res = await fetch("/api/users", {
                headers: { "Authorization": `Bearer ${this.currentUser.token}` }
            });
            if (res.ok) {
                const users = await res.json();
                picker.innerHTML = `<option value="">Select registered user...</option>` + 
                    users.map(u => `<option value="${u}">${u}</option>`).join("");
            }
        } catch (e) {}
    }

    copyShareLink() {
        const input = document.getElementById("share-link-input");
        if (input) {
            input.select();
            navigator.clipboard.writeText(input.value);
            alert("Share link copied to clipboard!");
        }
    }

    formatBytes(bytes, decimals = 2) {
        if (!+bytes) return '0 Bytes';
        const k = 1024;
        const dm = decimals < 0 ? 0 : decimals;
        const sizes = ['Bytes', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return `${parseFloat((bytes / Math.pow(k, i)).toFixed(dm))} ${sizes[i]}`;
    }
}

// Instantiate global application
window.app = new ZeroVaultApp();
