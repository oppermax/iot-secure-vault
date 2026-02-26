
from typing import Optional

from .session import ClientSession
from .utils import (
    NONCE_SIZE,
    random_nonce,
    xor_bytes,
    encrypt,
    decrypt,
    concatenate,
    bytes_to_hex,
)
from .vault import create_challenge, split_key_ids, xor_vault_keys, update_vault, Vault


class IoTDevice:
    def __init__(self, device_id: int, vault: Vault, vault_file_path: str):
        """Initialize IoT Device.

        Args:
            device_id: Unique device identifier (0-65535)
            vault: List of pre-shared vault keys (each KEY_LENGTH bytes)
            vault_file_path: Path to vault file that is being used
        """
        self.device_id = device_id
        self.vault = vault
        self.vault_file_path = vault_file_path

        # session state (will be initialized during handshake)
        self.session: Optional[ClientSession] = None

    def initiate_handshake(self) -> bytes:
        """Step 1: Initiate handshake with server by sending a random session ID and the device ID.

        Returns:
            M_1: session_id + device_id
        """
        session_id = random_nonce()
        device_id_bytes = self.device_id.to_bytes(2, "big")
        m1 = concatenate(session_id, device_id_bytes)

        # initialize new session
        self.session = ClientSession(session_id=session_id)

        print("[Device] Step 1: Initiating handshake")
        print(f"  Session ID: {bytes_to_hex(session_id)}")
        print(f"  Device ID: {self.device_id}")

        return m1

    def respond_to_challenge(self, m2: bytes) -> bytes:
        """Step 3: Respond to server's challenge with encrypted message.

        Args:
            m2: Server's challenge (r1 + C1)

        Returns:
            M_3: Encrypted response
        """
        if not self.session:
            raise RuntimeError("Must call initiate_handshake() first")

        # extract r1 and C1 from server's message
        r1 = m2[:NONCE_SIZE]
        c1 = m2[NONCE_SIZE:]

        # look up the vault keys at the indices requested by the server challenge
        key_ids = split_key_ids(c1)
        vault_keys = [
            self.vault.keys[key_id % len(self.vault.keys)] for key_id in key_ids
        ]
        # create k_1 by XORing the fetched vault keys
        self.session.k_1 = xor_vault_keys(vault_keys)

        # generate random numbers
        self.session.t_1 = random_nonce()  # client's contribution to session key
        self.session.r_2 = random_nonce()  # client's challenge to server

        # create client's challenge C_2
        self.session.c_2 = create_challenge(
            num_keys=len(key_ids), vault_size=len(self.vault.keys)
        )

        # create payload: t1 || C2 || r2
        payload = concatenate(self.session.t_1, self.session.c_2, self.session.r_2)

        # encrypt with k_1 and r1 as nonce
        m3 = encrypt(payload, self.session.k_1, r1)

        print("[Device] Step 3: Responding to challenge")
        print(f"  Derived k_1: {bytes_to_hex(self.session.k_1)}")
        print(f"  Generated t_1: {bytes_to_hex(self.session.t_1)}")
        print(f"  Generated r_2: {bytes_to_hex(self.session.r_2)}")

        return m3

    def verify_server(self, m4: bytes) -> bool:
        """Step 5: Verify server's response and derive session key.

        Args:
            m4: Server's encrypted response

        Returns:
            True if verification successful, False otherwise
        """
        if not self.session or not all([self.session.k_1, self.session.t_1, self.session.r_2, self.session.c_2]):
            raise RuntimeError("Must call respond_to_challenge() first")

        # derive k_2 from our challenge C_2
        key_ids_2 = split_key_ids(self.session.c_2)
        vault_keys_2 = [
            self.vault.keys[key_id % len(self.vault.keys)] for key_id in key_ids_2
        ]
        self.session.k_2 = xor_vault_keys(vault_keys_2)

        # create decryption key: k_2 ⊕ t_1
        decryption_key = xor_bytes(self.session.k_2, self.session.t_1)

        # decrypt M_4
        decrypted = decrypt(m4, decryption_key, self.session.r_2)

        # parse: t2
        t_2 = decrypted[:NONCE_SIZE]

        # calculate session key: t_1 ⊕ t_2
        self.session.session_key = xor_bytes(self.session.t_1, t_2)

        print("[Device] Step 5: Server verified successfully")
        print(f"  Session key: {bytes_to_hex(self.session.session_key)}")

        return True

    def append_data(self, data: bytes):
        """Append data exchanged during session for vault update.

        Args:
            data: Data to append to session data
        """
        if not self.session:
            raise RuntimeError("No active session")
        self.session.append_data(data)

    def end_session(self):
        """End session and update vault for forward secrecy.

        This MUST be called after each successful session to update the vault.
        Both client and server must call this with the same session data to stay in sync.
        """
        if not self.session or not self.session.session_key:
            raise RuntimeError("No session key established. Cannot update vault.")

        print("[Device] Ending session and updating vault")
        print(f"  Using {len(self.session.session_data)} bytes of session data for vault update")

        # update vault using HMAC with session data as key
        self.vault = update_vault(self.vault, bytes(self.session.session_data), self.vault_file_path)

        print(f"  ✓ Vault updated with {len(self.vault.keys)} new keys")

        # clear session state
        self.session = None