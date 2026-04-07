# kmp-crypto

**AES-256 encryption for Kotlin Multiplatform (Android + iOS)**

A production-grade crypto library for KMP apps. No dependencies beyond platform crypto APIs. Battle-tested in a production app with thousands of encrypted records.

[![Kotlin](https://img.shields.io/badge/Kotlin-2.1.21-blue.svg)](https://kotlinlang.org)
[![Platform](https://img.shields.io/badge/Platform-Android%20%7C%20iOS-green.svg)](https://kotlinlang.org/docs/multiplatform.html)
[![License](https://img.shields.io/badge/License-Apache%202.0-orange.svg)](LICENSE)

---

## Features

- **AES-256-GCM** — Encrypt/decrypt text and raw bytes
- **PBKDF2-HMAC-SHA256** — Derive keys from passwords (configurable iterations)
- **SHA-256** — Cryptographic hashing
- **HMAC-SHA256** — Message authentication codes
- **Secure Random** — Cryptographically secure random bytes and strings
- **Cross-Platform** — Android (javax.crypto) + iOS (CommonCrypto)
- **Zero Dependencies** — Uses only platform-native crypto APIs

## Quick Start

```kotlin
// Encrypt
val encrypted = KmpCrypto.encrypt("sensitive data", "my-password")

// Decrypt
val decrypted = KmpCrypto.decrypt(encrypted, "my-password")

// Hash
val hash = KmpCrypto.sha256("hello world")

// HMAC
val mac = KmpCrypto.hmacSha256("data", "secret-key")

// Derive key
val key = KmpCrypto.pbkdf2("password", "unique-salt")

// Random
val bytes = KmpCrypto.secureRandomBytes(32)
val token = KmpCrypto.secureRandomString(16)
```

## Installation

```kotlin
// build.gradle.kts
dependencies {
    implementation("com.kmpcrypto:kmp-crypto:1.0.0")
}
```

> Maven Central publishing coming soon. For now, use as a local module.

## API Reference

### Encryption

| Function | Description |
|----------|-------------|
| `encrypt(text, password, salt?, iterations?)` | AES-256 encrypt text. Returns Base64 string. |
| `decrypt(text, password, salt?, iterations?)` | AES-256 decrypt text. |
| `encryptBytes(bytes, password, salt?, iterations?)` | AES-256 encrypt raw bytes. |
| `decryptBytes(bytes, password, salt?, iterations?)` | AES-256 decrypt raw bytes. |
| `encryptWithKey(text, aesKey)` | Encrypt with a raw 32-byte AES key (no PBKDF2). |
| `decryptWithKey(text, aesKey)` | Decrypt with a raw 32-byte AES key. |

### Hashing

| Function | Description |
|----------|-------------|
| `sha256(input)` | SHA-256 hash. Returns hex string. |
| `sha256Bytes(input)` | SHA-256 hash. Returns raw bytes. |
| `hmacSha256(data, key)` | HMAC-SHA256. Returns hex string. |
| `hmacSha256Bytes(data, key)` | HMAC-SHA256. Returns raw bytes. |

### Key Derivation

| Function | Description |
|----------|-------------|
| `pbkdf2(password, salt, iterations?, keyLengthBits?)` | PBKDF2-HMAC-SHA256. Returns derived key bytes. |

### Random

| Function | Description |
|----------|-------------|
| `secureRandomBytes(size)` | Cryptographically secure random bytes. |
| `secureRandomString(length)` | Random Base64-URL string. |

## Security Notes

- **Key derivation:** Passwords are never used directly as encryption keys. PBKDF2 with 100,000 iterations derives a 256-bit key from the password + salt.
- **Random IV:** Every encryption uses a fresh random IV/nonce. Encrypting the same plaintext twice always produces different ciphertext.
- **Authentication:** GCM mode (Android) and HMAC-then-encrypt (iOS) provide authenticated encryption — tampered ciphertext is detected and rejected.
- **Salt:** Always provide a unique salt per application or user context. The default salt is for convenience only — don't use it in production.

## Platform Implementation

| Feature | Android | iOS |
|---------|---------|-----|
| AES-256 | `javax.crypto.Cipher` (GCM) | `CommonCrypto` (CBC + HMAC) |
| SHA-256 | `java.security.MessageDigest` | `CC_SHA256` |
| HMAC | `javax.crypto.Mac` | `CCHmac` |
| PBKDF2 | `SecretKeyFactory` | `CCKeyDerivationPBKDF` |
| Random | `java.security.SecureRandom` | `SecRandomCopyBytes` |

## Contributing

1. Fork the repo
2. Create a feature branch
3. Run tests: `./gradlew :kmp-crypto:testDebugUnitTest`
4. Submit a PR

## License

[Apache 2.0](LICENSE) — Copyright 2026 Mohammed Rampurawala
