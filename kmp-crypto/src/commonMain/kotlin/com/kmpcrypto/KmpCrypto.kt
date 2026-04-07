package com.kmpcrypto

import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi

/**
 * KMP Crypto — Cross-platform cryptographic utilities for Kotlin Multiplatform.
 *
 * Supports Android (javax.crypto) and iOS (CommonCrypto) with identical behavior.
 * Uses AES-256-GCM with PBKDF2 key derivation — the same standard used by banks and governments.
 *
 * ```kotlin
 * // Encrypt
 * val encrypted = KmpCrypto.encrypt("secret data", "my-password")
 *
 * // Decrypt
 * val decrypted = KmpCrypto.decrypt(encrypted, "my-password")
 *
 * // Hash
 * val hash = KmpCrypto.sha256("hello")
 * ```
 */
object KmpCrypto {

    private const val DEFAULT_PBKDF2_ITERATIONS = 100_000
    private const val AES_KEY_BITS = 256

    // ── AES-256-GCM ──

    /**
     * Encrypts plaintext using AES-256-GCM with a key derived from the password via PBKDF2.
     *
     * @param plainText The text to encrypt
     * @param password The password used for key derivation
     * @param salt Salt for PBKDF2 key derivation (should be unique per use case)
     * @param iterations PBKDF2 iterations (default: 100,000)
     * @return Base64-encoded string: IV[12] + ciphertext + GCM tag[16]
     */
    fun encrypt(
        plainText: String,
        password: String,
        salt: String = "kmp-crypto-default-salt",
        iterations: Int = DEFAULT_PBKDF2_ITERATIONS,
    ): String {
        val key = deriveKey(password, salt, iterations)
        return aesGcmEncrypt(plainText, key)
    }

    /**
     * Decrypts ciphertext using AES-256-GCM with a key derived from the password via PBKDF2.
     *
     * @param cipherText Base64-encoded ciphertext (from [encrypt])
     * @param password The password used for key derivation (must match encryption password)
     * @param salt Salt for PBKDF2 key derivation (must match encryption salt)
     * @param iterations PBKDF2 iterations (must match encryption iterations)
     * @return Decrypted plaintext
     * @throws CryptoException if decryption fails (wrong password, corrupted data)
     */
    fun decrypt(
        cipherText: String,
        password: String,
        salt: String = "kmp-crypto-default-salt",
        iterations: Int = DEFAULT_PBKDF2_ITERATIONS,
    ): String {
        val key = deriveKey(password, salt, iterations)
        return aesGcmDecrypt(cipherText, key)
    }

    /**
     * Encrypts raw bytes using AES-256-GCM.
     *
     * @return Raw bytes: IV[12] + ciphertext + GCM tag[16]
     */
    fun encryptBytes(
        plainBytes: ByteArray,
        password: String,
        salt: String = "kmp-crypto-default-salt",
        iterations: Int = DEFAULT_PBKDF2_ITERATIONS,
    ): ByteArray {
        val key = deriveKey(password, salt, iterations)
        return aesGcmEncryptBytes(plainBytes, key)
    }

    /**
     * Decrypts raw bytes using AES-256-GCM.
     *
     * @return Decrypted bytes
     * @throws CryptoException if decryption fails
     */
    fun decryptBytes(
        cipherBytes: ByteArray,
        password: String,
        salt: String = "kmp-crypto-default-salt",
        iterations: Int = DEFAULT_PBKDF2_ITERATIONS,
    ): ByteArray {
        val key = deriveKey(password, salt, iterations)
        return aesGcmDecryptBytes(cipherBytes, key)
    }

    /**
     * Encrypts with a raw AES key (no PBKDF2). Use when you manage key derivation yourself.
     */
    fun encryptWithKey(plainText: String, aesKey: ByteArray): String {
        require(aesKey.size == 32) { "AES key must be 32 bytes (256 bits)" }
        return aesGcmEncrypt(plainText, aesKey)
    }

    /**
     * Decrypts with a raw AES key (no PBKDF2). Use when you manage key derivation yourself.
     */
    fun decryptWithKey(cipherText: String, aesKey: ByteArray): String {
        require(aesKey.size == 32) { "AES key must be 32 bytes (256 bits)" }
        return aesGcmDecrypt(cipherText, aesKey)
    }

    // ── Hashing ──

    /** Computes SHA-256 hash. Returns lowercase hex string. */
    fun sha256(input: String): String {
        val hash = sha256Impl(input.encodeToByteArray())
        return hash.toHexString()
    }

    /** Computes SHA-256 hash of raw bytes. Returns raw hash bytes. */
    fun sha256Bytes(input: ByteArray): ByteArray {
        return sha256Impl(input)
    }

    /** Computes HMAC-SHA256. Returns lowercase hex string. */
    fun hmacSha256(data: String, key: String): String {
        val mac = hmacSha256Impl(data.encodeToByteArray(), key.encodeToByteArray())
        return mac.toHexString()
    }

    /** Computes HMAC-SHA256 with raw bytes. Returns raw MAC bytes. */
    fun hmacSha256Bytes(data: ByteArray, key: ByteArray): ByteArray {
        return hmacSha256Impl(data, key)
    }

    // ── Key Derivation ──

    /**
     * Derives a key using PBKDF2-HMAC-SHA256.
     *
     * @param password The password
     * @param salt The salt (should be unique per user/context)
     * @param iterations Number of PBKDF2 iterations (default: 100,000)
     * @param keyLengthBits Desired key length in bits (default: 256)
     * @return Derived key bytes
     */
    fun pbkdf2(
        password: String,
        salt: String,
        iterations: Int = DEFAULT_PBKDF2_ITERATIONS,
        keyLengthBits: Int = AES_KEY_BITS,
    ): ByteArray {
        return pbkdf2Impl(
            password = password.toCharArray(),
            salt = salt.encodeToByteArray(),
            iterations = iterations,
            keyLengthBits = keyLengthBits,
        )
    }

    // ── Random ──

    /** Generates cryptographically secure random bytes. */
    fun secureRandomBytes(size: Int): ByteArray {
        require(size > 0) { "Size must be positive" }
        return secureRandomBytesImpl(size)
    }

    /** Generates a cryptographically secure random Base64 string. */
    @OptIn(ExperimentalEncodingApi::class)
    fun secureRandomString(length: Int = 16): String {
        val bytes = secureRandomBytesImpl(length)
        return Base64.UrlSafe.encode(bytes).replace("=", "").take(length)
    }

    // ── Internal ──

    private fun deriveKey(password: String, salt: String, iterations: Int): ByteArray {
        return pbkdf2Impl(
            password = password.toCharArray(),
            salt = salt.encodeToByteArray(),
            iterations = iterations,
            keyLengthBits = AES_KEY_BITS,
        )
    }

    private fun ByteArray.toHexString(): String =
        joinToString("") { byte ->
            val i = byte.toInt() and 0xFF
            val hex = "0123456789abcdef"
            "${hex[i shr 4]}${hex[i and 0x0F]}"
        }
}
