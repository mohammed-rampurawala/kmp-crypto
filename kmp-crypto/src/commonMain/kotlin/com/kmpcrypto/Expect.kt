package com.kmpcrypto

// ── AES-256-GCM ──

/** Encrypts plaintext. Returns Base64(IV[12] + ciphertext + tag[16]). */
internal expect fun aesGcmEncrypt(plainText: String, key: ByteArray): String

/** Decrypts ciphertext. Expects Base64(IV[12] + ciphertext + tag[16]). */
internal expect fun aesGcmDecrypt(cipherText: String, key: ByteArray): String

/** Encrypts raw bytes. Returns IV[12] + ciphertext + tag[16]. */
internal expect fun aesGcmEncryptBytes(plainBytes: ByteArray, key: ByteArray): ByteArray

/** Decrypts raw bytes. Expects IV[12] + ciphertext + tag[16]. */
internal expect fun aesGcmDecryptBytes(cipherBytes: ByteArray, key: ByteArray): ByteArray

// ── Hashing ──

/** SHA-256 hash. Returns hex string. */
internal expect fun sha256Impl(input: ByteArray): ByteArray

/** HMAC-SHA256. Returns raw bytes. */
internal expect fun hmacSha256Impl(data: ByteArray, key: ByteArray): ByteArray

// ── Key Derivation ──

/** PBKDF2-HMAC-SHA256. Returns derived key bytes. */
internal expect fun pbkdf2Impl(
    password: CharArray,
    salt: ByteArray,
    iterations: Int,
    keyLengthBits: Int,
): ByteArray

// ── Random ──

/** Cryptographically secure random bytes. */
internal expect fun secureRandomBytesImpl(size: Int): ByteArray
