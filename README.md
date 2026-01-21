# IoT Secure Vault

Mutual authentication protocol using synchronized secure vaults for key management.

## Quick Start

```bash
python -m server.main
```

```bash
python -m client.main
```

## Key Concept

**Client and server have SEPARATE vaults that stay in sync.**

## How It Works

1. **Handshake**: Client and server authenticate each other
2. **Communication**: Exchange encrypted messages
3. **Vault Update**: Both update their vaults using `HMAC(session_key, vault)`
4. **Sync**: Both compute the same new vault (deterministic)


## Mutation

The assumption of the paper is that the channel over which client and server communicate is reliable and never loses data.
Obviously, this is not the case in real-world applications. The current implementation follows the approach to only mutate
on successful completion of a session. If the client or server crashes during communication, the vaults remain unchanged.

Theoretically, the connection could be interrupted after the client sends the request end the session and before the server 
receives it. In this case, the vaults would be out of sync.