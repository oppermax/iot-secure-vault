"""
Utility functions for the IoT Secure Vault protocol.
"""
import secrets

CHALLENGE_SIZE = 4 # number of key IDs in challenge
NONCE_SIZE = 4  # bytes
KEY_LENGTH = 16  # bytes
SERVER_IP = '127.0.0.1'
SERVER_PORT = 7000

def random_nonce() -> bytes:
    """Generate a cryptographically secure random nonce."""
    return secrets.token_bytes(NONCE_SIZE)


def xor_bytes(a: bytes, b: bytes) -> bytes:
    """XOR two byte strings together."""
    result = bytearray()
    for i in range(min(len(a), len(b))):
        result.append(a[i] ^ b[i])
    return bytes(result)


def encrypt(message: bytes, key: bytes) -> bytes:
    """Encrypt message using XOR with key.
    
    Note: XOR encryption is simple but not secure for production.
    Consider using AES-GCM for real applications.
    """

    # TODO: Actually encrypt this
    result = bytearray(message)
    for i in range(len(result)):
        result[i] ^= key[i % len(key)]
    return bytes(result)


def decrypt(ciphertext: bytes, key: bytes) -> bytes:
    """Decrypt ciphertext using XOR with key."""
    return encrypt(ciphertext, key)


def concatenate(*args: bytes) -> bytes:
    """Concatenate multiple byte strings."""
    return b''.join(args)


def bytes_to_hex(data: bytes) -> str:
    """Convert bytes to hex string for display."""
    return data.hex()


def hex_to_bytes(hex_str: str) -> bytes:
    """Convert hex string back to bytes."""
    return bytes.fromhex(hex_str)
