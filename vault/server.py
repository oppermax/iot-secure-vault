"""
Server implementation for the IoT Secure Vault protocol.
"""
from typing import List, Optional, Dict, Tuple
from .utils import (
    NONCE_SIZE, random_nonce, xor_bytes, encrypt, decrypt,
    concatenate, bytes_to_hex
)
from .vault import (
    create_challenge, split_key_ids, xor_vault_keys, update_vault, Vault
)



class VaultServer:
    """Server that authenticates IoT devices and manages secure sessions."""
    
    def __init__(self, vault: Vault):
        """Initialize Vault Server.
        
        Args:
            vault: List of pre-shared vault keys (each KEY_LENGTH bytes)
        """
        self.vault = vault
        
        # Active sessions: session_id -> session data
        self.sessions: Dict[bytes, dict] = {}
    
    def handle_handshake(self, m1: bytes, num_keys: int = 4) -> Tuple[bytes, bytes]:
        """Step 2: Handle client's handshake initiation and send challenge.
        
        Args:
            m1: Client's handshake message (session_id + device_id)
            num_keys: Number of keys to include in challenge
            
        Returns:
            Tuple of (session_id, M_2) where M_2 is the challenge message
        """
        # Parse M_1
        session_id = m1[:NONCE_SIZE]
        device_id_bytes = m1[NONCE_SIZE:NONCE_SIZE+2]
        device_id = int.from_bytes(device_id_bytes, 'big')
        
        # Generate challenge
        r1 = random_nonce()
        c1 = create_challenge(num_keys)
        m2 = concatenate(r1, c1)
        
        # Store session state
        self.sessions[session_id] = {
            'device_id': device_id,
            'r1': r1,
            'c1': c1,
            'session_key': None
        }

        print(f"[Server] Step 2: Sending challenge to device {device_id}")
        print(f"  Session ID: {bytes_to_hex(session_id)}")
        print(f"  r1: {bytes_to_hex(r1)}")
        
        return session_id, m2
    
    def verify_and_respond(self, session_id: bytes, m3: bytes) -> Tuple[bool, Optional[bytes]]:
        """Step 4: Verify client and send encrypted response.
        
        Args:
            session_id: Session identifier
            m3: Client's encrypted message
            
        Returns:
            Tuple of (success, M_4) where M_4 is the encrypted response (None if failed)
        """
        if session_id not in self.sessions:
            print(f"[Server] ✗ Unknown session: {bytes_to_hex(session_id)}")
            return False, None
        
        session = self.sessions[session_id]
        r1 = session['r1']
        c1 = session['c1']
        
        # Derive k_1 from the challenge we sent
        key_ids = split_key_ids(c1)
        vault_keys = [self.vault.keys[key_id % len(self.vault.keys)] for key_id in key_ids]
        k_1 = xor_vault_keys(vault_keys)
        
        # Decrypt M_3
        try:
            decrypted = decrypt(m3, k_1)
        except Exception as e:
            print(f"[Server] ✗ Decryption failed: {e}")
            return False, None
        
        # Parse the decrypted payload: r1 || t1 || C2 || r2
        r1_received = decrypted[:NONCE_SIZE]
        t_1 = decrypted[NONCE_SIZE:NONCE_SIZE*2]
        
        # C2 is the rest except the last NONCE_SIZE bytes (which is r2)
        c_2 = decrypted[NONCE_SIZE*2:-NONCE_SIZE]
        r_2 = decrypted[-NONCE_SIZE:]
        
        # Verify r1 matches what we sent
        if r1_received != r1:
            print(f"[Server] ✗ Client authentication failed: r1 mismatch")
            print(f"  Expected: {bytes_to_hex(r1)}")
            print(f"  Received: {bytes_to_hex(r1_received)}")
            return False, None
        
        # Derive k_2 from client's challenge C_2
        key_ids_2 = split_key_ids(c_2)
        vault_keys_2 = [self.vault.keys[key_id % len(self.vault.keys
                                                )] for key_id in key_ids_2]
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
        session['session_key'] = session_key
        
        print(f"[Server] Step 4: Client verified successfully")
        print(f"  ✓ r1 verified")
        print(f"  Session key: {bytes_to_hex(session_key)}")
        
        return True, m4
    
    def send_encrypted(self, session_id: bytes, message: bytes) -> bytes:
        """Encrypt a message with the session key.
        
        Args:
            session_id: Session identifier
            message: Plaintext message
            
        Returns:
            Encrypted message
        """
        if session_id not in self.sessions:
            raise RuntimeError(f"Unknown session: {bytes_to_hex(session_id)}")
        
        session_key = self.sessions[session_id]['session_key']
        if not session_key:
            raise RuntimeError("No session key established. Complete handshake first.")
        
        return encrypt(message, session_key)
    
    def receive_encrypted(self, session_id: bytes, ciphertext: bytes) -> bytes:
        """Decrypt a message with the session key.
        
        Args:
            session_id: Session identifier
            ciphertext: Encrypted message
            
        Returns:
            Decrypted message
        """
        if session_id not in self.sessions:
            raise RuntimeError(f"Unknown session: {bytes_to_hex(session_id)}")
        
        session_key = self.sessions[session_id]['session_key']
        if not session_key:
            raise RuntimeError("No session key established. Complete handshake first.")
        
        return decrypt(ciphertext, session_key)
    
    def end_session(self, session_id: bytes):
        """End session and update vault for forward secrecy.
        
        This MUST be called after each successful session to update the vault.
        Both client and server must call this with the same session key to stay in sync.
        
        Args:
            session_id: Session identifier
        """
        if session_id not in self.sessions:
            raise RuntimeError(f"Unknown session: {bytes_to_hex(session_id)}")
        
        session_key = self.sessions[session_id]['session_key']
        if not session_key:
            raise RuntimeError("No session key established. Cannot update vault.")
        
        print(f"[Server] Ending session {bytes_to_hex(session_id)} and updating vault")
        
        # Update vault using HMAC with session key
        self.vault = update_vault(self.vault, session_key)
        
        print(f"  ✓ Vault updated with {len(self.vault.keys)} new keys")
        
        # Remove session
        del self.sessions[session_id]
    
    def close_session(self, session_id: bytes):
        """Close and remove a session WITHOUT updating vault.
        
        WARNING: This does NOT update the vault. Use end_session() instead
        to properly end a session with vault update.
        
        Args:
            session_id: Session identifier
        """
        if session_id in self.sessions:
            del self.sessions[session_id]
            print(f"[Server] Session closed: {bytes_to_hex(session_id)}")
    
    def get_active_sessions(self) -> List[bytes]:
        """Get list of active session IDs.
        
        Returns:
            List of session IDs
        """
        return list(self.sessions.keys())

