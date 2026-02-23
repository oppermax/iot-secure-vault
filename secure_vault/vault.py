"""
Vault-specific functions for challenge-response and vault updates.
"""

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
        self.size = len(keys)

    def fetch_keys(self, key_ids: List[int]) -> List[bytes]:
        return [self.keys[key_id] for key_id in key_ids]


def new_from_file(filepath: str) -> "Vault":
    """Load vault keys from a binary file.

    Each key is stored as KEY_LENGTH bytes.
    """
    with open(filepath, "rb") as f:
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


def random_key_id(vault_size: int) -> int:
    """Generate a random vault key index (0-999)."""
    return secrets.randbelow(vault_size)


# create_challenge takes an amount of vault keys and the total size of the vault to return the requested a
def create_challenge(num_keys: int, vault_size: int) -> bytes:
    challenge = bytearray()
    for _ in range(num_keys):
        key_id = random_key_id(vault_size)
        challenge.extend(key_id.to_bytes(2, "big"))
    return bytes(challenge)


def split_key_ids(chunk: bytes) -> List[int]:
    """Extract key IDs from challenge bytes.

    Each key ID is 2 bytes (big-endian).
    """
    out = []
    for i in range(0, len(chunk), 2):
        key_id = int.from_bytes(chunk[i : i + 2], "big")
        out.append(key_id)
    return out


def xor_vault_keys(vault_keys: List[bytes]) -> bytes:
    """XOR all vault keys together to create encryption key."""
    if not vault_keys:
        return b""

    result = bytearray(vault_keys[0])
    for key in vault_keys[1:]:
        for i in range(min(len(result), len(key))):
            result[i] ^= key[i]
    return bytes(result)


def update_vault(
    current_vault: Vault, session_data: bytes, vault_file_path: str
) -> Vault:
    """Update vault keys using HMAC with session data as the key.

    This provides forward secrecy - even if the session data is compromised,
    previous vault states cannot be recovered.

    Args:
        current_vault: Current vault with keys
        session_data: All data exchanged during the session (used as HMAC key)
        vault_file_path: Path to save updated vault

    Returns:
        New vault with updated keys
    """
    vault_size = len(current_vault.keys)

    # concatenate all vault keys
    vault_data = concatenate(*current_vault.keys)

    # we need vault_size * KEY_LENGTH bytes for the new vault
    # hmac-sha256 produces 32 bytes, so likely several rounds are needed to create enough data
    required_bytes = vault_size * KEY_LENGTH
    new_vault_data = bytearray()

    counter = 0
    while len(new_vault_data) < required_bytes:
        # create hmac with counter to generate different outputs
        h = hmac.new(
            session_data, vault_data + counter.to_bytes(4, "big"), hashlib.sha256
        )
        new_vault_data.extend(h.digest())
        counter += 1

    # split into vault keys
    new_keys = []
    for i in range(vault_size):
        start = i * KEY_LENGTH
        end = start + KEY_LENGTH
        new_keys.append(bytes(new_vault_data[start:end]))

    return save_vault(Vault(keys=new_keys), vault_file_path)


def save_vault(vault: Vault, filename: str) -> Vault:
    """Save vault keys to a binary file."""
    print("Saving updated vault to", filename)
    with open(filename, "wb") as f:
        for key in vault.keys:
            f.write(key)
    return vault
