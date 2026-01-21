"""
IoT Device (Client) implementation for the Secure Vault protocol.
"""
import logging
from typing import List, Optional
from .utils import (
    NONCE_SIZE, random_nonce, xor_bytes, encrypt, decrypt, 
    concatenate, bytes_to_hex
)
from .vault import (
    create_challenge, split_key_ids, xor_vault_keys, update_vault, Vault
)



class IoTDevice:
    """IoT Device client that performs mutual authentication with a server."""
    
    def __init__(self, device_id: int, vault: Vault, vault_file_path: str):
        """Initialize IoT Device.
        
        Args:
            device_id: Unique device identifier (0-65535)
            vault: List of pre-shared vault keys (each KEY_LENGTH bytes)
        """
        self.device_id = device_id
        self.vault = vault
        self.vault_file_path = vault_file_path
        
        # Session state
        self.session_id: Optional[bytes] = None
        self.session_key: Optional[bytes] = None
        
        # Handshake state (for verification)
        self._k_1: Optional[bytes] = None
        self._k_2: Optional[bytes] = None
        self._t_1: Optional[bytes] = None
        self._r_2: Optional[bytes] = None
        self._c_2: Optional[bytes] = None
    
    def initiate_handshake(self) -> bytes:
        """Step 1: Initiate handshake with server.
        
        Returns:
            M_1: session_id (4 bytes) + device_id (2 bytes)
        """
        self.session_id = random_nonce()
        device_id_bytes = self.device_id.to_bytes(2, 'big')
        m1 = concatenate(self.session_id, device_id_bytes)

        
        print(f"[Device] Step 1: Initiating handshake")
        print(f"  Session ID: {bytes_to_hex(self.session_id)}")
        print(f"  Device ID: {self.device_id}")
        
        return m1
    
    def respond_to_challenge(self, m2: bytes) -> bytes:
        """Step 3: Respond to server's challenge with encrypted message.
        
        Args:
            m2: Server's challenge (r1 + C1)
            
        Returns:
            M_3: Encrypted response
        """
        # Extract r1 and C1 from server's message
        r1 = m2[:NONCE_SIZE]
        c1 = m2[NONCE_SIZE:]
        
        # Derive k_1 from challenge C1
        key_ids = split_key_ids(c1)
        vault_keys = [self.vault.keys[key_id % len(self.vault.keys)] for key_id in key_ids]
        self._k_1 = xor_vault_keys(vault_keys)
        
        # Generate random numbers
        self._t_1 = random_nonce()  # Client's contribution to session key
        self._r_2 = random_nonce()  # Client's challenge to server
        
        # Create client's challenge C_2
        self._c_2 = create_challenge(num_keys=len(key_ids))
        
        # Create payload: r1 || t1 || C2 || r2
        payload = concatenate(r1, self._t_1, self._c_2, self._r_2)
        
        # Encrypt with k_1 and r1 as nonce
        m3 = encrypt(payload, self._k_1, r1)
        
        print(f"[Device] Step 3: Responding to challenge")
        print(f"  Derived k_1: {bytes_to_hex(self._k_1)}")
        print(f"  Generated t_1: {bytes_to_hex(self._t_1)}")
        print(f"  Generated r_2: {bytes_to_hex(self._r_2)}")
        
        return m3
    
    def verify_server(self, m4: bytes) -> bool:
        """Step 4 (Client): Verify server's response and derive session key.
        
        Args:
            m4: Server's encrypted response
            
        Returns:
            True if verification successful, False otherwise
        """
        if not all([self._k_1, self._t_1, self._r_2, self._c_2]):
            raise RuntimeError("Must call respond_to_challenge() first")
        
        # Derive k_2 from our challenge C_2
        key_ids_2 = split_key_ids(self._c_2)
        vault_keys_2 = [self.vault.keys[key_id % len(self.vault.keys)] for key_id in key_ids_2]
        self._k_2 = xor_vault_keys(vault_keys_2)
        
        # Create decryption key: k_2 ⊕ t_1
        decryption_key = xor_bytes(self._k_2, self._t_1)
        
        # Decrypt M_4
        decrypted = decrypt(m4, decryption_key, self._r_2)
        
        # Parse: r2 || t2
        r2_received = decrypted[:NONCE_SIZE]
        t_2 = decrypted[NONCE_SIZE:NONCE_SIZE*2]
        
        # Verify r2 matches what we sent
        if r2_received != self._r_2:
            print(f"[Device] ✗ Server authentication failed: r2 mismatch")
            return False
        
        # Calculate session key: t_1 ⊕ t_2
        self.session_key = xor_bytes(self._t_1, t_2)
        
        print(f"[Device] Step 4: Server verified successfully")
        print(f"  ✓ r2 verified")
        # print(f"  Session key: {bytes_to_hex(self.session_key)}")
        
        return True
    
    def send_encrypted(self, message: bytes) -> bytes:
        """Encrypt a message with the session key.
        
        Args:
            message: Plaintext message
            
        Returns:
            Encrypted message
        """
        if not self.session_key:
            raise RuntimeError("No session key established. Complete handshake first.")
        
        return encrypt(message, self.session_key)
    
    def receive_encrypted(self, ciphertext: bytes) -> bytes:
        """Decrypt a message with the session key.
        
        Args:
            ciphertext: Encrypted message
            
        Returns:
            Decrypted message
        """
        if not self.session_key:
            raise RuntimeError("No session key established. Complete handshake first.")
        
        return decrypt(ciphertext, self.session_key)
    
    def end_session(self):
        """End session and update vault for forward secrecy.
        
        This MUST be called after each successful session to update the vault.
        Both client and server must call this with the same session key to stay in sync.
        """
        if not self.session_key:
            raise RuntimeError("No session key established. Cannot update vault.")
        
        print(f"[Device] Ending session and updating vault")
        
        # Update vault using HMAC with session key
        # TODO this should actually be the session data whatever that even means
        self.vault = update_vault(self.vault, self.session_key, self.vault_file_path)
        
        print(f"  ✓ Vault updated with {len(self.vault.keys)} new keys")
        
        # Clear session state
        self.reset_session()
    
    def reset_session(self):
        """Reset session state for a new handshake.
        
        WARNING: This does NOT update the vault. Use end_session() instead
        to properly end a session with vault update.
        """
        self.session_id = None
        self.session_key = None
        self._k_1 = None
        self._k_2 = None
        self._t_1 = None
        self._r_2 = None
        self._c_2 = None

