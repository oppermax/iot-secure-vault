from dataclasses import dataclass, field
from typing import Optional

@dataclass
class ServerSession:
    """Server-side session state for device authentication."""
    device_id: int
    r1: bytes
    c1: bytes
    session_key: Optional[bytes] = None
    session_data: bytearray = field(default_factory=bytearray)
    data_counter: int = 0

    def append_data(self, data: bytes):
        """Append data exchanged during session for vault update.

        Args:
            data: Data to append to session data
        """
        self.session_data.extend(data)


@dataclass
class ClientSession:
    """Client-side session state for device authentication."""
    session_id: bytes
    session_key: Optional[bytes] = None
    session_data: bytearray = field(default_factory=bytearray)
    data_counter: int = 0

    # intermediate handshake values
    k_1: Optional[bytes] = None
    k_2: Optional[bytes] = None
    t_1: Optional[bytes] = None
    r_2: Optional[bytes] = None
    c_2: Optional[bytes] = None

    def append_data(self, data: bytes):
        """Append data exchanged during session for vault update.

        Args:
            data: Data to append to session data
        """
        self.session_data.extend(data)

