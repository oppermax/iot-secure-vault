"""
Utility functions for the IoT Secure Vault protocol.
"""
import secrets
from Crypto.Cipher import AES

CHALLENGE_SIZE = 4 # number of key IDs in challenge
NONCE_SIZE = 16  # bytes
KEY_LENGTH = 16  # bytes
SERVER_IP = '127.0.0.1'
SERVER_PORT = 7000

def nonce_from_counter(counter: int) -> bytes:
    """Generate a nonce from a counter value."""
    return counter.to_bytes(NONCE_SIZE, 'big')

def random_nonce() -> bytes:
    """Generate a cryptographically secure random nonce."""
    return secrets.token_bytes(NONCE_SIZE)


def xor_bytes(a: bytes, b: bytes) -> bytes:
    """XOR two byte strings together."""
    result = bytearray()
    for i in range(min(len(a), len(b))):
        result.append(a[i] ^ b[i])
    return bytes(result)


def encrypt(message: bytes, key: bytes, nonce: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_GCM, nonce)

    return cipher.encrypt(message)


def decrypt(ciphertext: bytes, key: bytes, nonce: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_GCM, nonce)

    return cipher.decrypt(ciphertext)


def concatenate(*args: bytes) -> bytes:
    """Concatenate multiple byte strings."""
    return b''.join(args)


def bytes_to_hex(data: bytes) -> str:
    """Convert bytes to hex string for display."""
    return data.hex()
