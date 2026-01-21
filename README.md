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
