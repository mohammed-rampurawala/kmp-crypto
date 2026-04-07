# kmp-crypto

**AES-256 encryption for Kotlin Multiplatform (Android + iOS)**

A production-grade crypto library for KMP apps. No dependencies beyond platform crypto APIs. Battle-tested in a production app with thousands of encrypted records.

[![Kotlin](https://img.shields.io/badge/Kotlin-2.1.21-blue.svg)](https://kotlinlang.org)
[![Platform](https://img.shields.io/badge/Platform-Android%20%7C%20iOS-green.svg)](https://kotlinlang.org/docs/multiplatform.html)
[![License](https://img.shields.io/badge/License-Apache%202.0-orange.svg)](LICENSE)

---

## Why kmp-crypto?

KMP doesn't have a built-in crypto library. Most developers end up:
- Copy-pasting StackOverflow snippets for AES encryption
- Writing `expect/actual` boilerplate for every crypto operation
- Getting iOS CommonCrypto interop wrong (GCM mode, pointer handling)
- Using different implementations on Android and iOS that aren't compatible

**kmp-crypto** solves this with a single `KmpCrypto` object that works identically on both platforms.

## Use Cases

### Encrypt user data before storing
```kotlin
// Encrypt sensitive profile data before saving to Firestore/Supabase/any backend
val profileJson = """{"name": "Rahul", "income": "25 LPA", "phone": "+91-999"}"""
val encrypted = KmpCrypto.encrypt(profileJson, userPassword)
// Store `encrypted` in your database — it's unreadable without the password
```

### Secure file encryption
```kotlin
// Encrypt photos, documents, or any binary data
val imageBytes = loadImageFromGallery()
val encrypted = KmpCrypto.encryptBytes(imageBytes, encryptionKey)
// Upload encrypted bytes — even if your cloud storage is compromised, data is safe
```

### Password hashing for authentication
```kotlin
// Hash passwords before sending to your backend
val passwordHash = KmpCrypto.sha256(userPassword + salt)
// Send `passwordHash` to your API — never send plain passwords over the wire
```

### API request signing
```kotlin
// Sign API requests with HMAC to prevent tampering
val payload = """{"action": "transfer", "amount": 500}"""
val signature = KmpCrypto.hmacSha256(payload, apiSecret)
// Send signature in header — backend verifies integrity
```

### Secure token generation
```kotlin
// Generate tokens for email verification, password reset, invite codes
val verificationToken = KmpCrypto.secureRandomString(32)
val sessionId = KmpCrypto.secureRandomString(24)
```

### Zero-knowledge architecture
```kotlin
// Build apps where the server never sees user data
val slug = KmpCrypto.secureRandomString(8)           // "rahul-K9x2"
val publicHash = KmpCrypto.sha256(slug)               // For database lookup
val encrypted = KmpCrypto.encrypt(sensitiveData, slug) // Only slug holders can decrypt
// Store publicHash + encrypted on server. Slug stays on client.
```

### Encrypted shared preferences
```kotlin
// Store sensitive data in local storage securely
val apiKey = "sk_live_abc123"
val encrypted = KmpCrypto.encrypt(apiKey, deviceFingerprint)
settings.putString("api_key", encrypted)

// Read back
val stored = settings.getString("api_key", "")
val decrypted = KmpCrypto.decrypt(stored, deviceFingerprint)
```

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

### Option 1: Local module (recommended for now)

Clone the repo and add it as a module in your KMP project:

```bash
# Clone into your project
git clone https://github.com/mohammed-rampurawala/kmp-crypto.git

# Or add as a git submodule
git submodule add https://github.com/mohammed-rampurawala/kmp-crypto.git
```

Add to your `settings.gradle.kts`:
```kotlin
include(":kmp-crypto:kmp-crypto")
// Adjust the path if you cloned it elsewhere:
// project(":kmp-crypto:kmp-crypto").projectDir = file("path/to/kmp-crypto/kmp-crypto")
```

Add the dependency in your shared module's `build.gradle.kts`:
```kotlin
kotlin {
    sourceSets {
        commonMain.dependencies {
            implementation(project(":kmp-crypto:kmp-crypto"))
        }
    }
}
```

### Option 2: Maven Central (coming soon)

```kotlin
// build.gradle.kts
dependencies {
    implementation("com.kmpcrypto:kmp-crypto:1.0.0")
}
```

### Option 3: Copy the source files

If you prefer not to add a dependency, copy the source files directly:

1. Copy `kmp-crypto/src/commonMain/kotlin/com/kmpcrypto/` into your `commonMain`
2. Copy `kmp-crypto/src/androidMain/kotlin/com/kmpcrypto/` into your `androidMain`
3. Copy `kmp-crypto/src/iosMain/kotlin/com/kmpcrypto/` into your `iosMain`
4. Update the package name if needed

## Features

- **AES-256-GCM** — Encrypt/decrypt text and raw bytes
- **PBKDF2-HMAC-SHA256** — Derive keys from passwords (configurable iterations)
- **SHA-256** — Cryptographic hashing
- **HMAC-SHA256** — Message authentication codes
- **Secure Random** — Cryptographically secure random bytes and strings
- **Cross-Platform** — Android (javax.crypto) + iOS (CommonCrypto)
- **Zero Dependencies** — Uses only platform-native crypto APIs

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
