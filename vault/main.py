import secrets
import random
from typing import List


NONCE_SIZE = 4  # bytes
VAULT_SIZE = 16
KEY_LENGTH = 16  # bytes

def random_nonce() -> bytes:
    """Generate a cryptographically secure random nonce."""
    return secrets.token_bytes(NONCE_SIZE)

def random_key_id() -> int:
    """Generate a random vault key index (0-999)."""
    return secrets.randbelow(1000)

def create_challenge(num_keys: int) -> bytes:
    """Create a challenge with random key IDs.
    
    Each key ID is stored as 2 bytes (big-endian), supporting 0-65535 range.
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
    """XOR all vault keys together to create encryption key.
    
    All keys must be the same length (KEY_LENGTH).
    """
    if not vault_keys:
        return b''
    
    result = bytearray(vault_keys[0])
    for key in vault_keys[1:]:
        for i in range(min(len(result), len(key))):
            result[i] ^= key[i]
    return bytes(result)

def xor_bytes(a: bytes, b: bytes) -> bytes:
    """XOR two byte strings together.
    
    Args:
        a: First byte string
        b: Second byte string
        
    Returns:
        XOR result (length is minimum of the two inputs)
    """
    result = bytearray()
    for i in range(min(len(a), len(b))):
        result.append(a[i] ^ b[i])
    return bytes(result)

def encrypt(message: bytes, key: bytes) -> bytes:
    """Encrypt message using XOR with key.
    
    Note: XOR encryption is simple but not secure for production.
    Consider using AES-GCM for real applications.
    """
    result = bytearray(message)
    for i in range(len(result)):
        result[i] ^= key[i % len(key)]
    return bytes(result)

def decrypt(ciphertext: bytes, key: bytes) -> bytes:
    """Decrypt ciphertext using XOR with key.
    
    XOR decryption is the same as encryption.
    """
    return encrypt(ciphertext, key)

def concatenate(*args: bytes) -> bytes:
    """Concatenate multiple byte strings."""
    return b''.join(args)

def init_handshake() -> bytes:
    """Client initiates handshake.
    
    Returns: session_id (4 bytes) + device_id (2 bytes)
    """
    session_id = random_nonce()
    device_id = (161).to_bytes(2, 'big')
    return concatenate(session_id, device_id)

def server_challenge(num_keys: int = 16) -> bytes:
    """Server sends challenge.
    
    Returns: r1 (4 bytes nonce) + c1 (challenge with key IDs)
    """
    r1 = random_nonce()
    c1 = create_challenge(num_keys)
    return concatenate(r1, c1)



def client_step3(vault: List[bytes], m2: bytes) -> tuple[bytes, bytes, bytes, bytes]:
    """Client Step 3: Respond to server challenge with encrypted message.
    
    Args:
        vault: Client's vault of keys
        m2: Server's challenge message (r1 + C1)
        
    Returns:
        Tuple of (m3, k_1, t_1, r_2, C_2) for verification later
    """
    # Extract r1 and C1 from server's message
    r1 = m2[:NONCE_SIZE]
    c1 = m2[NONCE_SIZE:]
    
    # Derive k_1 from challenge C1
    key_ids = split_key_ids(c1)
    vault_keys = [vault[key_id % len(vault)] for key_id in key_ids]
    k_1 = xor_vault_keys(vault_keys)
    
    # Generate random numbers
    t_1 = random_nonce()  # Client's contribution to session key
    r_2 = random_nonce()  # Client's challenge to server
    
    # Create client's challenge C_2
    c_2 = create_challenge(num_keys=len(key_ids))
    
    # Create payload: r1 || t1 || C2 || r2
    payload = concatenate(r1, t_1, c_2, r_2)
    
    # Encrypt with k_1
    m3 = encrypt(payload, k_1)
    
    return m3, k_1, t_1, r_2, c_2

def server_step4(vault: List[bytes], m3: bytes, c1: bytes, r1: bytes) -> tuple[bytes, bytes]:
    """Server Step 4: Verify client and send encrypted response.
    
    Args:
        vault: Server's vault of keys
        m3: Client's encrypted message
        c1: Challenge the server sent in Step 2
        r1: Nonce the server sent in Step 2
        
    Returns:
        Tuple of (m4, session_key) - encrypted response and derived session key
    """
    # Derive k_1 from the challenge we sent
    key_ids = split_key_ids(c1)
    vault_keys = [vault[key_id % len(vault)] for key_id in key_ids]
    k_1 = xor_vault_keys(vault_keys)
    
    # Decrypt M_3
    decrypted = decrypt(m3, k_1)
    
    # Parse the decrypted payload: r1 || t1 || C2 || r2
    r1_received = decrypted[:NONCE_SIZE]
    t_1 = decrypted[NONCE_SIZE:NONCE_SIZE*2]
    
    # C2 is the rest except the last NONCE_SIZE bytes (which is r2)
    c_2 = decrypted[NONCE_SIZE*2:-NONCE_SIZE]
    r_2 = decrypted[-NONCE_SIZE:]
    
    # Verify r1 matches what we sent
    if r1_received != r1:
        raise ValueError("Authentication failed: r1 mismatch")
    
    # Derive k_2 from client's challenge C_2
    key_ids_2 = split_key_ids(c_2)
    vault_keys_2 = [vault[key_id % len(vault)] for key_id in key_ids_2]
    k_2 = xor_vault_keys(vault_keys_2)
    
    # Generate server's contribution to session key
    t_2 = random_nonce()
    
    # Create encryption key: k_2 ⊕ t_1
    encryption_key = xor_bytes(k_2, t_1)
    
    # Create payload: r2 || t2
    payload = concatenate(r_2, t_2)
    
    # Encrypt with k_2 ⊕ t_1
    m4 = encrypt(payload, encryption_key)
    
    # Calculate session key: t_1 ⊕ t_2
    session_key = xor_bytes(t_1, t_2)
    
    return m4, session_key

def client_verify_step4(m4: bytes, k_2: bytes, t_1: bytes, r_2: bytes) -> bytes:
    """Client verifies server's response and derives session key.
    
    Args:
        m4: Server's encrypted response
        k_2: Key derived from C_2 challenge
        t_1: Client's random number from Step 3
        r_2: Client's challenge nonce from Step 3
        
    Returns:
        session_key: The final session key for encrypted communication
    """
    # Create decryption key: k_2 ⊕ t_1
    decryption_key = xor_bytes(k_2, t_1)
    
    # Decrypt M_4
    decrypted = decrypt(m4, decryption_key)
    
    # Parse: r2 || t2
    r2_received = decrypted[:NONCE_SIZE]
    t_2 = decrypted[NONCE_SIZE:NONCE_SIZE*2]
    
    # Verify r2 matches what we sent
    if r2_received != r_2:
        raise ValueError("Authentication failed: r2 mismatch")
    
    # Calculate session key: t_1 ⊕ t_2
    session_key = xor_bytes(t_1, t_2)
    
    return session_key


# Utility functions for debugging/display
def bytes_to_hex(data: bytes) -> str:
    """Convert bytes to hex string for display."""
    return data.hex()

def hex_to_bytes(hex_str: str) -> bytes:
    """Convert hex string back to bytes."""
    return bytes.fromhex(hex_str)

def main():
    """Complete handshake protocol demonstration."""
    # Initialize shared vault (both client and server have the same vault)
    vault: List[bytes] = []
    for _ in range(VAULT_SIZE):
        key = secrets.token_bytes(KEY_LENGTH)
        vault.append(key)
    
    print("=== IoT Secure Vault - Complete Handshake Protocol ===\n")
    
    # STEP 1: Client initiates handshake
    print("STEP 1: Client → Server (Handshake Initiation)")
    m1 = init_handshake()
    print(f"  M_1 (session_id + device_id): {bytes_to_hex(m1)}")
    print()
    
    # STEP 2: Server sends challenge
    print("STEP 2: Server → Client (Challenge)")
    m2 = server_challenge(num_keys=4)
    r1 = m2[:NONCE_SIZE]
    c1 = m2[NONCE_SIZE:]
    print(f"  M_2 (r1 + C1): {bytes_to_hex(m2)}")
    print(f"  r1: {bytes_to_hex(r1)}")
    print(f"  C1: {bytes_to_hex(c1)}")
    print()
    
    # STEP 3: Client responds with encrypted message
    print("STEP 3: Client → Server (Encrypted Response)")
    m3, k_1, t_1, r_2, c_2 = client_step3(vault, m2)
    print(f"  M_3 (encrypted): {bytes_to_hex(m3)}")
    print(f"  Client derived k_1: {bytes_to_hex(k_1)}")
    print(f"  Client generated t_1: {bytes_to_hex(t_1)}")
    print(f"  Client generated r_2: {bytes_to_hex(r_2)}")
    print(f"  Client challenge C_2: {bytes_to_hex(c_2)}")
    print()
    
    # STEP 4: Server verifies and responds
    print("STEP 4: Server → Client (Verification & Response)")
    try:
        m4, server_session_key = server_step4(vault, m3, c1, r1)
        print(f"  ✓ Server verified r1 successfully")
        print(f"  M_4 (encrypted): {bytes_to_hex(m4)}")
        print(f"  Server session key: {bytes_to_hex(server_session_key)}")
    except ValueError as e:
        print(f"  ✗ Server authentication failed: {e}")
        return
    print()
    
    # Client verifies server and derives session key
    print("STEP 4 (Client Verification):")
    # Client needs to derive k_2 from its own challenge C_2
    key_ids_2 = split_key_ids(c_2)
    vault_keys_2 = [vault[key_id % len(vault)] for key_id in key_ids_2]
    k_2 = xor_vault_keys(vault_keys_2)
    
    try:
        client_session_key = client_verify_step4(m4, k_2, t_1, r_2)
        print(f"  ✓ Client verified r2 successfully")
        print(f"  Client session key: {bytes_to_hex(client_session_key)}")
    except ValueError as e:
        print(f"  ✗ Client authentication failed: {e}")
        return
    print()
    
    # Verify both parties have the same session key
    print("=== HANDSHAKE COMPLETE ===")
    if server_session_key == client_session_key:
        print(f"✓ SUCCESS: Both parties derived the same session key!")
        print(f"  Session Key (t = t_1 ⊕ t_2): {bytes_to_hex(client_session_key)}")
    else:
        print(f"✗ FAILURE: Session keys don't match!")
        print(f"  Server: {bytes_to_hex(server_session_key)}")
        print(f"  Client: {bytes_to_hex(client_session_key)}")
        return
    print()
    
    # Demonstrate encrypted communication with session key
    print("=== Encrypted Communication ===")
    message = b"Hello, IoT Device! This is encrypted with the session key."
    encrypted = encrypt(message, client_session_key)
    decrypted = decrypt(encrypted, server_session_key)
    
    print(f"Original message: {message.decode()}")
    print(f"Encrypted: {bytes_to_hex(encrypted)}")
    print(f"Decrypted: {decrypted.decode()}")

    

if __name__ == "__main__":
    main()