"""
Vault-specific functions for challenge-response and vault updates.
"""
import struct
import secrets
import hmac
import hashlib
from typing import List
from .utils import KEY_LENGTH, concatenate


class Vault:
    """Vault class to manage vault keys."""

    def __init__(self, keys: List[bytes]):
        """Initialize Vault with a list of keys.

        Args:
            keys: List of vault keys (each KEY_LENGTH bytes)
        """
        self.keys = keys

def new_from_file(filepath: str) -> 'Vault':
    """Load vault keys from a binary file.

    Each key is stored as KEY_LENGTH bytes.
    """
    with open(filepath, 'rb') as f:
        data = f.read()

    if len(data) % KEY_LENGTH != 0:
        raise ValueError("Vault file size must be a multiple of KEY_LENGTH")

    num_keys = len(data) // KEY_LENGTH
    keys = []
    for i in range(num_keys):
        start = i * KEY_LENGTH
        end = start + KEY_LENGTH
        keys.append(data[start:end])

    vault = Vault(keys=keys)
    return vault

def random_key_id() -> int:
    """Generate a random vault key index (0-999)."""
    return secrets.randbelow(1000)


def create_challenge(num_keys: int) -> bytes:
    """Create a challenge with random key IDs.
    
    Each key ID is stored as 2 bytes (big-endian).
    """
    challenge = bytearray()
    for _ in range(num_keys):
        key_id = random_key_id()
        challenge.extend(key_id.to_bytes(2, 'big'))
    return bytes(challenge)


def split_key_ids(chunk: bytes) -> List[int]:
    """Extract key IDs from challenge bytes.
    
    Each key ID is 2 bytes (big-endian).
    """
    out = []
    for i in range(0, len(chunk), 2):
        key_id = int.from_bytes(chunk[i:i+2], 'big')
        out.append(key_id)
    return out


def xor_vault_keys(vault_keys: List[bytes]) -> bytes:
    """XOR all vault keys together to create encryption key."""
    if not vault_keys:
        return b''
    
    result = bytearray(vault_keys[0])
    for key in vault_keys[1:]:
        for i in range(min(len(result), len(key))):
            result[i] ^= key[i]
    return bytes(result)


def update_vault(current_vault: Vault, session_key: bytes, vault_file_path: str) -> Vault:
    """Update vault keys using HMAC with session key.
    
    This provides forward secrecy - even if the session key is compromised,
    previous vault states cannot be recovered.
    
    Algorithm:
    1. Concatenate all current vault keys
    2. Compute HMAC-SHA256 using session_key as key, vault data as message
    3. Split the HMAC output into chunks of KEY_LENGTH
    4. Use these chunks as the new vault keys
    
    Args:
        current_vault: List of current vault keys
        session_key: Session key from completed handshake
        
    Returns:
        New vault with updated keys
    """
    vault_size = len(current_vault.keys)
    
    # Concatenate all vault keys
    vault_data = concatenate(*current_vault.keys)
    
    # We need vault_size * KEY_LENGTH bytes for the new vault
    # HMAC-SHA256 produces 32 bytes, so we may need multiple rounds
    required_bytes = vault_size * KEY_LENGTH
    new_vault_data = bytearray()
    
    counter = 0
    while len(new_vault_data) < required_bytes:
        # Create HMAC with counter to generate different outputs
        h = hmac.new(
            session_key,
            vault_data + counter.to_bytes(4, 'big'),
            hashlib.sha256
        )
        new_vault_data.extend(h.digest())
        counter += 1
    
    # Split into vault keys
    new_keys = []
    for i in range(vault_size):
        start = i * KEY_LENGTH
        end = start + KEY_LENGTH
        new_keys.append(bytes(new_vault_data[start:end]))
    
    return save_vault(Vault(keys=new_keys), vault_file_path)


# Write vault file
def save_vault(vault: Vault, filename: str) -> Vault:
    print("Saving updated vault to", filename)
    with open(filename, 'wb') as f:
        for key in vault.keys:
            f.write(key)
    return vault