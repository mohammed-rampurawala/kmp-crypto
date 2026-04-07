package com.kmpcrypto

import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec

private const val GCM_IV_LENGTH = 12
private const val GCM_TAG_BITS = 128
private val secureRandom = SecureRandom()

// ── AES-256-GCM ──

internal actual fun aesGcmEncrypt(plainText: String, key: ByteArray): String {
    try {
        val iv = ByteArray(GCM_IV_LENGTH).also { secureRandom.nextBytes(it) }
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(GCM_TAG_BITS, iv))
        val cipherText = cipher.doFinal(plainText.toByteArray(Charsets.UTF_8))
        @OptIn(kotlin.io.encoding.ExperimentalEncodingApi::class)
        return kotlin.io.encoding.Base64.encode(iv + cipherText)
    } catch (e: Exception) {
        throw CryptoException("Encryption failed", e)
    }
}

internal actual fun aesGcmDecrypt(cipherText: String, key: ByteArray): String {
    try {
        @OptIn(kotlin.io.encoding.ExperimentalEncodingApi::class)
        val combined = kotlin.io.encoding.Base64.decode(cipherText)
        val iv = combined.sliceArray(0 until GCM_IV_LENGTH)
        val encrypted = combined.sliceArray(GCM_IV_LENGTH until combined.size)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(GCM_TAG_BITS, iv))
        return String(cipher.doFinal(encrypted), Charsets.UTF_8)
    } catch (e: Exception) {
        throw CryptoException("Decryption failed — wrong key or corrupted data", e)
    }
}

internal actual fun aesGcmEncryptBytes(plainBytes: ByteArray, key: ByteArray): ByteArray {
    try {
        val iv = ByteArray(GCM_IV_LENGTH).also { secureRandom.nextBytes(it) }
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(GCM_TAG_BITS, iv))
        return iv + cipher.doFinal(plainBytes)
    } catch (e: Exception) {
        throw CryptoException("Byte encryption failed", e)
    }
}

internal actual fun aesGcmDecryptBytes(cipherBytes: ByteArray, key: ByteArray): ByteArray {
    try {
        val iv = cipherBytes.sliceArray(0 until GCM_IV_LENGTH)
        val encrypted = cipherBytes.sliceArray(GCM_IV_LENGTH until cipherBytes.size)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(GCM_TAG_BITS, iv))
        return cipher.doFinal(encrypted)
    } catch (e: Exception) {
        throw CryptoException("Byte decryption failed — wrong key or corrupted data", e)
    }
}

// ── Hashing ──

internal actual fun sha256Impl(input: ByteArray): ByteArray {
    return MessageDigest.getInstance("SHA-256").digest(input)
}

internal actual fun hmacSha256Impl(data: ByteArray, key: ByteArray): ByteArray {
    val mac = Mac.getInstance("HmacSHA256")
    mac.init(SecretKeySpec(key, "HmacSHA256"))
    return mac.doFinal(data)
}

// ── Key Derivation ──

internal actual fun pbkdf2Impl(
    password: CharArray,
    salt: ByteArray,
    iterations: Int,
    keyLengthBits: Int,
): ByteArray {
    val factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
    val spec = PBEKeySpec(password, salt, iterations, keyLengthBits)
    return factory.generateSecret(spec).encoded
}

// ── Random ──

internal actual fun secureRandomBytesImpl(size: Int): ByteArray {
    return ByteArray(size).also { secureRandom.nextBytes(it) }
}
