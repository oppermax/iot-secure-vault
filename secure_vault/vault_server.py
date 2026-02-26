"""
Server implementation for the IoT Secure Vault protocol.
"""

from typing import Optional, Dict, Tuple
from .session import ServerSession
from .utils import (
    NONCE_SIZE,
    random_nonce,
    xor_bytes,
    encrypt,
    decrypt,
    concatenate,
    bytes_to_hex,
)
from .vault import (
    create_challenge,
    split_key_ids,
    xor_vault_keys,
    update_vault,
    new_from_file,
)


class VaultServer:
    """Server that authenticates IoT devices and manages secure sessions."""

    def __init__(self, vault_file_path: str, challenge_size):
        """Initialize Vault Server.

        Args:
            vault: List of pre-shared vault keys (each KEY_LENGTH bytes)
        """
        self.vault = new_from_file(vault_file_path)
        self.vault_file_path = vault_file_path

        self.challenge_size = challenge_size # number of keys in challenge

        # active sessions: session_id -> ServerSession
        self.sessions: Dict[bytes, ServerSession] = {}

    # handle_handshake is the server's first step in the handshake process. It accepts m1 and a returns session_id and m2
    def handle_handshake(self, m1: bytes) -> Tuple[bytes, bytes]:
        """Step 2: Handle handshake initiation from device and respond with challenge."""
        session_id = m1[:NONCE_SIZE]
        device_id_bytes = m1[NONCE_SIZE : NONCE_SIZE + 2]
        device_id = int.from_bytes(device_id_bytes, "big")

        # generate challenge
        r1 = random_nonce()
        c1 = create_challenge(num_keys=self.challenge_size, vault_size=self.vault.size)
        m2 = concatenate(r1, c1)

        # store session state
        self.sessions[session_id] = ServerSession(
            device_id=device_id,
            r1=r1,
            c1=c1,
        )

        print(f"[Server] Step 2: Sending challenge to device {device_id}")
        print(f"  Session ID: {bytes_to_hex(session_id)}")
        print(f"  r1: {bytes_to_hex(r1)}")

        # we need to return the session_id so that we know what session this m2 belongs to
        return session_id, m2

    def verify_and_respond(
        self, session_id: bytes, m3: bytes
    ) -> Tuple[bool, Optional[bytes]]:
        """Step 3: Verify client's response to challenge and respond with server's contribution to session key."""
        if session_id not in self.sessions:
            print(
                f"[Server] ✗ Unknown session: {bytes_to_hex(session_id)}. Initiate handshake first."
            )
            return False, None

        # load session info
        session = self.sessions[session_id]
        r1 = session.r1  # nonce we sent to client
        c1 = session.c1  # challenge we sent to client

        # derive k_1 from the challenge we sent
        key_ids = split_key_ids(c1)  # break the challenge into key IDs
        vault_keys = self.vault.fetch_keys(key_ids)  # fetch the keys from the vault
        k_1 = xor_vault_keys(vault_keys)  # xor them to also compute k_1

        # decrypt m3 with k_1 and r1 (the nonce we sent to client)
        try:
            decrypted = decrypt(m3, k_1, r1)
        except Exception as e:
            print(f"[Server] ✗ Decryption failed: {e}")
            return False, None

        # parse the decrypted payload: r1 || t1 || C2 || r2
        r1_received = decrypted[:NONCE_SIZE]
        t_1 = decrypted[NONCE_SIZE : NONCE_SIZE * 2]

        # c2 is the rest except the last NONCE_SIZE bytes (which is r2)
        c_2 = decrypted[NONCE_SIZE * 2 : -NONCE_SIZE]
        r_2 = decrypted[-NONCE_SIZE:]

        # verify r1 matches what we sent
        if r1_received != r1:
            print("[Server] ✗ Client authentication failed: r1 mismatch")
            print(f"  Expected: {bytes_to_hex(r1)}")
            print(f"  Received: {bytes_to_hex(r1_received)}")
            return False, None

        # derive k_2 from client's challenge C_2
        key_ids_2 = split_key_ids(c_2)
        vault_keys_2 = [
            self.vault.keys[key_id % len(self.vault.keys)] for key_id in key_ids_2
        ]
        k_2 = xor_vault_keys(vault_keys_2)

        # generate server's contribution to session key
        t_2 = random_nonce()

        # create encryption key: k_2 ⊕ t_1
        encryption_key = xor_bytes(k_2, t_1)

        # create payload: r2 || t2
        payload = concatenate(r_2, t_2)

        # encrypt with k_2 ⊕ t_1
        m4 = encrypt(payload, encryption_key, r_2)

        # calculate session key: t_1 ⊕ t_2
        session_key = xor_bytes(t_1, t_2)
        session.session_key = session_key

        print("[Server] Step 4: Client verified successfully")
        print("  ✓ r1 verified")
        print(f"  Session key: {bytes_to_hex(session_key)}")

        return True, m4


    def end_session(self, session_id: bytes):
        """End session and update vault with session data."""
        if session_id not in self.sessions:
            raise RuntimeError(f"Unknown session: {bytes_to_hex(session_id)}")

        session = self.sessions[session_id]
        session_key = session.session_key
        session_data = bytes(session.session_data)

        if not session_key:
            raise RuntimeError("No session key established. Cannot update vault.")

        print(f"[Server] Ending session {bytes_to_hex(session_id)} and updating vault")
        print(f"  Using {len(session_data)} bytes of session data for vault update")

        # update vault using HMAC with session data as key
        self.vault = update_vault(self.vault, session_data, self.vault_file_path)

        print(f"  ✓ Vault updated with {len(self.vault.keys)} new keys")

        # remove session
        del self.sessions[session_id]
