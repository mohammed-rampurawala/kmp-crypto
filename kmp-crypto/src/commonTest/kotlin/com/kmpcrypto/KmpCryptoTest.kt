package com.kmpcrypto

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals
import kotlin.test.assertFailsWith

class KmpCryptoTest {

    @Test
    fun encryptDecryptRoundTrip() {
        val original = "Hello, KMP Crypto!"
        val password = "test-password"
        val encrypted = KmpCrypto.encrypt(original, password)
        val decrypted = KmpCrypto.decrypt(encrypted, password)
        assertEquals(original, decrypted)
    }

    @Test
    fun encryptProducesDifferentOutputEachTime() {
        val text = "same input"
        val password = "same password"
        val encrypted1 = KmpCrypto.encrypt(text, password)
        val encrypted2 = KmpCrypto.encrypt(text, password)
        assertNotEquals(encrypted1, encrypted2, "Random IV should produce different ciphertext")
    }

    @Test
    fun decryptWithWrongPasswordFails() {
        val encrypted = KmpCrypto.encrypt("secret", "correct-password")
        assertFailsWith<CryptoException> {
            KmpCrypto.decrypt(encrypted, "wrong-password")
        }
    }

    @Test
    fun bytesEncryptDecryptRoundTrip() {
        val original = byteArrayOf(0, 1, 2, 127, -128, -1)
        val password = "byte-test"
        val encrypted = KmpCrypto.encryptBytes(original, password)
        val decrypted = KmpCrypto.decryptBytes(encrypted, password)
        assertEquals(original.toList(), decrypted.toList())
    }

    @Test
    fun sha256ProducesKnownHash() {
        // SHA-256("hello") = 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824
        val hash = KmpCrypto.sha256("hello")
        assertEquals("2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824", hash)
    }

    @Test
    fun sha256EmptyString() {
        // SHA-256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        val hash = KmpCrypto.sha256("")
        assertEquals("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", hash)
    }

    @Test
    fun hmacSha256ProducesKnownOutput() {
        // HMAC-SHA256("hello", "key") = 9307b3b915efb5171ff14d8cb55fbcc798c6c0ef1456d66ded1a6aa723a58b7b
        val mac = KmpCrypto.hmacSha256("hello", "key")
        assertEquals("9307b3b915efb5171ff14d8cb55fbcc798c6c0ef1456d66ded1a6aa723a58b7b", mac)
    }

    @Test
    fun pbkdf2ProducesDeterministicOutput() {
        val key1 = KmpCrypto.pbkdf2("password", "salt", iterations = 1000)
        val key2 = KmpCrypto.pbkdf2("password", "salt", iterations = 1000)
        assertEquals(key1.toList(), key2.toList())
        assertEquals(32, key1.size) // 256 bits = 32 bytes
    }

    @Test
    fun secureRandomBytesReturnsCorrectSize() {
        val bytes = KmpCrypto.secureRandomBytes(32)
        assertEquals(32, bytes.size)
    }

    @Test
    fun secureRandomStringReturnsCorrectLength() {
        val str = KmpCrypto.secureRandomString(16)
        assertEquals(16, str.length)
    }

    @Test
    fun encryptWithCustomSalt() {
        val text = "custom salt test"
        val password = "password"
        val encrypted = KmpCrypto.encrypt(text, password, salt = "my-app-salt")
        val decrypted = KmpCrypto.decrypt(encrypted, password, salt = "my-app-salt")
        assertEquals(text, decrypted)
    }

    @Test
    fun differentSaltsProduceDifferentKeys() {
        val text = "salt test"
        val password = "password"
        val encrypted1 = KmpCrypto.encrypt(text, password, salt = "salt-a")
        assertFailsWith<CryptoException> {
            KmpCrypto.decrypt(encrypted1, password, salt = "salt-b")
        }
    }
}
