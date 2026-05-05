# Tresor — E2EE Messaging App

A secure, end-to-end encrypted messaging application built with Next.js and the Web Crypto API. The server stores only ciphertext — plaintext messages never leave your device.

## Getting Started

```bash
npm install
npm run dev
```

Open [http://localhost:3000](http://localhost:3000).

---

## Architecture

```text
┌─────────────────────────────────────────────────────┐
│                    CLIENT (Browser)                  │
│                                                      │
│  ┌──────────────┐     ┌───────────────────────────┐ │
│  │  React UI    │────▶│     Web Crypto API        │ │
│  │  (Next.js)   │     │  RSA-OAEP  AES-GCM  PBKDF2│ │
│  └──────────────┘     └───────────────────────────┘ │
│         │                        │                  │
│         │  encrypted blobs only  │ keys in memory   │
│         ▼                        ▼                  │
│  ┌──────────────────────────────────┐               │
│  │  WebSocket (real-time) / REST    │               │
│  └──────────────────────────────────┘               │
└─────────────────────────────┬───────────────────────┘
                              │ HTTPS / WSS
                              ▼
┌─────────────────────────────────────────────────────┐
│                  SERVER (Koyeb)                      │
│                                                      │
│  Stores: ciphertext, iv, encryptedKey (RSA blobs)   │
│  Stores: public_key, wrapped_private_key, salt      │
│  Never sees: plaintext or raw private keys          │
│                                                      │
│  Auth  ──  Users  ──  Conversations  ──  Messages   │
└─────────────────────────────────────────────────────┘
```

---

## Encryption Flow

### Registration

```text
1. Browser generates RSA-OAEP 2048-bit keypair (Web Crypto)
2. Browser generates random 128-bit PBKDF2 salt
3. Browser derives AES-GCM wrapping key:
     PBKDF2(password, salt, 100_000 iterations, SHA-256) → AES-GCM 256-bit
4. Browser wraps RSA private key with AES-GCM → wrapped_private_key (opaque blob)
5. POST /auth/register:
     { username, display_name, password, public_key, wrapped_private_key, pbkdf2_salt }
6. Server stores all fields. wrapped_private_key is opaque — server cannot use it.
7. Server returns access_token + refresh_token
8. Private key lives in memory only for the current session
```

### Login (restoring session)

```text
1. POST /auth/login → server returns user profile including wrapped_private_key + pbkdf2_salt
2. Browser re-derives AES-GCM key: PBKDF2(password, pbkdf2_salt)
3. Browser unwraps private key using AES-GCM → CryptoKey in memory
4. Private key never stored in plaintext anywhere
```

### Sending a Message

```text
1. GET /users/{recipientId}/public-key → fetch recipient's RSA public key
2. Generate ephemeral AES-GCM 256-bit key + 96-bit random IV
3. Encrypt plaintext:   AES-GCM(aesKey, iv, plaintext)              → ciphertext
4. Encrypt AES key for recipient: RSA-OAEP(recipientPubKey, aesKey) → encryptedKey
5. Encrypt AES key for self:      RSA-OAEP(myPubKey, aesKey)        → encryptedKeyForSelf
6. Send via WebSocket (fallback: POST /messages):
     { to: recipientId, payload: { ciphertext, iv, encryptedKey, encryptedKeyForSelf } }
```

### Receiving a Message

```text
1. WebSocket delivers message.receive event (or poll GET /conversations/{userId}/messages)
2. Select the correct encrypted AES key:
     - If I sent it  → decrypt encryptedKeyForSelf with my RSA private key
     - If I received → decrypt encryptedKey with my RSA private key
3. RSA-OAEP decrypt → raw AES-GCM key bytes
4. AES-GCM decrypt(aesKey, iv, ciphertext) → plaintext
5. Plaintext rendered in UI, never persisted to disk
```

---

## Key Management

| Key | Generated | Stored | Protected by |
| --- | --- | --- | --- |
| RSA public key | Client, on register | Server (plaintext — intended) | N/A |
| RSA private key | Client, on register | Server as `wrapped_private_key` | AES-GCM (PBKDF2 from password) |
| AES-GCM message key | Client, per message | Never stored | Ephemeral — one per message |
| PBKDF2 salt | Client, on register | Server | N/A (public value) |

**The private key never exists on the server in usable form.** The server holds a wrapped blob that is only unwrappable with the user's password — which the server never receives after the initial registration.

---

## Security Trade-offs

**What we get:**

- Server is fully zero-knowledge for message content
- Private key is protected at rest by the user's password (100k PBKDF2 iterations)
- Each message uses a fresh ephemeral AES key (no key reuse across messages)
- Sender can read their own sent messages via `encryptedKeyForSelf`
- Access tokens expire every 15 minutes; refresh tokens are revocable

**Accepted trade-offs:**

- **Server-side wrapped key**: The AES-GCM-encrypted private key lives on the server. If the server is compromised AND an attacker obtains the password, they could unwrap the key. Mitigation: strong password enforcement.
- **No forward secrecy**: RSA-OAEP means old messages are at risk if the private key is ever compromised. ECDH with ephemeral keys (Signal protocol) would solve this but is out of scope.
- **In-memory keys only**: Refreshing or closing the tab ends the session and requires re-login.
- **No replay protection**: A captured encrypted payload could theoretically be resubmitted. Server-side message IDs provide partial mitigation.

---

## Known Limitations

- No multi-device sync beyond server-stored wrapped key
- No message deletion or editing
- No read receipts surfaced in UI (delivered flag exists on backend)
- Session ends on page refresh — no persistence
- WebSocket reconnect on drop is not yet implemented (falls back to REST polling)

---

## Tech Stack

- **Frontend**: Next.js 15 (App Router), React 19, TypeScript
- **Crypto**: Web Crypto API — browser-native, zero external crypto libraries
- **Transport**: WebSocket for real-time delivery, REST as offline fallback
- **Backend**: Provided — `https://whisperbox.koyeb.app`
