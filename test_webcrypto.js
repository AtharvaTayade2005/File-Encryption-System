const { webcrypto } = require('crypto');
global.window = { crypto: webcrypto, btoa: (b) => Buffer.from(b, 'binary').toString('base64'), atob: (b) => Buffer.from(b, 'base64').toString('binary') };
global.TextEncoder = TextEncoder;
global.TextDecoder = TextDecoder;
global.Blob = Blob;

const CryptoEngine = require('./crypto/webcrypto.js');

async function runTest() {
    try {
        const engine = new CryptoEngine();
        console.log("1. Deriving master keys for Alice...");
        const aliceMaster = await engine.deriveMasterKeys("alice_password_123");
        console.log("2. Generating keypair for Alice...");
        const aliceKeys = await engine.generateAsymmetricKeyPair(aliceMaster.kek);
        
        console.log("3. Deriving master keys for Bob...");
        const bobMaster = await engine.deriveMasterKeys("bob_password_123");
        console.log("4. Generating keypair for Bob...");
        const bobKeys = await engine.generateAsymmetricKeyPair(bobMaster.kek);

        console.log("Alice Public Key JWK:", aliceKeys.publicKeyJwk);
        console.log("Bob Public Key JWK:", bobKeys.publicKeyJwk);

        console.log("5. Alice encrypts file with password 'fileSecret999'...");
        const plaintext = Buffer.from("Hello Zero-Knowledge World! Secret data here.");
        const encResult = await engine.encryptFile(plaintext, "secret.txt", "text/plain", "fileSecret999");
        console.log("   Ciphertext size:", encResult.ciphertextBlob.size);
        console.log("   Password protected:", encResult.passwordProtected);

        console.log("6. Alice wraps DEK for herself...");
        const aliceWrapped = await engine.wrapKeyForRecipient(encResult.rawDekBuffer, aliceKeys.publicKeyJwk);
        console.log("   Alice wrapped key (base64):", aliceWrapped.substring(0, 30) + "...");

        console.log("7. Alice wraps DEK for Bob...");
        const bobWrapped = await engine.wrapKeyForRecipient(encResult.rawDekBuffer, bobKeys.publicKeyJwk);
        console.log("   Bob wrapped key (base64):", bobWrapped.substring(0, 30) + "...");

        console.log("8. Bob decrypts private key with Bob KEK...");
        const bobPrivKey = await engine.decryptPrivateKey(bobKeys.encryptedPrivateKey, bobMaster.kek);
        console.log("   Bob private key decrypted in RAM.");

        console.log("9. Bob unwraps DEK using private key...");
        let bobUnwrappedDek = await engine.unwrapKeyWithPrivateKey(bobWrapped, bobPrivKey);
        console.log("   Bob unwrapped DEK byteLength:", bobUnwrappedDek.byteLength);

        console.log("10. Bob decrypts metadata using raw DEK...");
        const decryptedMeta = await engine.decryptMetadata({
            ciphertext: encResult.encryptedMetadata.ciphertext,
            iv: encResult.encryptedMetadata.iv
        }, bobUnwrappedDek);
        console.log("   Decrypted metadata:", decryptedMeta);

        console.log("11. Bob unwraps password layer with 'fileSecret999'...");
        const finalDek = await engine.unwrapDekWithFilePassword(
            decryptedMeta.passwordWrappedDek,
            decryptedMeta.passwordSalt,
            decryptedMeta.passwordIv,
            "fileSecret999"
        );
        console.log("   Final DEK byteLength:", finalDek.byteLength);

        console.log("12. Bob decrypts file payload...");
        const cipherBuffer = await encResult.ciphertextBlob.arrayBuffer();
        const decryptedFile = await engine.decryptFileBuffer(cipherBuffer, finalDek, encResult.ivBase64);
        const resultString = new TextDecoder().decode(decryptedFile);
        console.log("   Decrypted content:", resultString);

        if (resultString === "Hello Zero-Knowledge World! Secret data here.") {
            console.log("\n[SUCCESS] Entire Node WebCrypto flow completed with 100% accuracy!");
        } else {
            console.error("\n[FAIL] Content mismatch!");
        }

    } catch (err) {
        console.error("\n[ERROR CAUGHT]:", err);
    }
}

runTest();
