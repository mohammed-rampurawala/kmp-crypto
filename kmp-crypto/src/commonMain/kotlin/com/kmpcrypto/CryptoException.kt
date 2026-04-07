package com.kmpcrypto

/** Exception thrown when a cryptographic operation fails. */
class CryptoException(message: String, cause: Throwable? = null) : Exception(message, cause)
