# 🔐 MHHS — Multi-layer Hybrid Hash Shield

> **Custom encryption library** — layered AES-256 + ChaCha20 + custom SPN cipher.  
> Simple API, military-grade protection.

---

## ⚡ Quick Install

```bash
# 1. Clone the repo
git clone https://github.com/YOUR_USERNAME/mhhs.git
cd mhhs

# 2. Install dependency (only one)
pip install cryptography

# 3. Done — import and use
python3 -c "import mhhs; print('MHHS ready ✓')"
```

---

## 📦 Requirements

| Package | Version | Install |
|---------|---------|---------|
| Python | 3.9+ | [python.org](https://python.org) |
| cryptography | latest | `pip install cryptography` |

---

## 🚀 Usage

### 1. Generate a key

```python
import mhhs

key = mhhs.generate_key()
print("key:", key)
# key: 9a8fe4cff2d56a18738cf5f7d95c6b49aff49dc254aa39d...
```

### 2. Encrypt a message

```python
msg = "hello"
encrypted = mhhs.encrypt(msg, key)
print("mhhs:", encrypted)
# mhhs: O-M00x_L-{Ec(V}O^}5NL$(c-o6l6-dxN5!d#<G*pq...
```

### 3. Decrypt

```python
original = mhhs.decrypt(encrypted, key)
print("original:", original)
# original: hello
```

---

## 💰 Encrypt Transactions / Numbers

```python
key = mhhs.generate_key()

amount = 9_500.75
enc = mhhs.encrypt(amount, key)
print("mhhs:", enc)

dec = mhhs.decrypt(enc, key)
print("amount:", dec)
# amount: 9500.75   ← comes back as float automatically
```

---

## 🗝 Key Types

```python
# Full 512-bit key (default — strongest)
key = mhhs.generate_key()
print("key:", key)

# Short readable key (128-bit — easy to share)
key = mhhs.generate_key("short")
print("key:", key.short)
# key: fd3a-f526-bf83-3928-db54-982f-64d0-3016

# Key pair — public + private
pub, priv = mhhs.generate_key("pair")
print("public:", pub.short)
print("private:", priv.short)
```

---

## 💬 MHHSMessage — Fluent Style

```python
key = mhhs.generate_key()

m = mhhs.message("Lacagta waxay tahay $5,000")

m.encrypt(key)
print("mhhs:", m)       # → encrypted token

m.decrypt(key)
print("msg:", m)        # → Lacagta waxay tahay $5,000
```

---

## 🛡 Security Layers

```
plaintext
  └─ [L1] Key derivation   PBKDF2-SHA512 (400,000 iters) + HKDF-SHA3-512
  └─ [L2] SPN cipher       16-round custom Substitution-Permutation Network
  └─ [L3] ChaCha20         ChaCha20-Poly1305  (256-bit, AEAD)
  └─ [L4] AES-256          AES-256-GCM        (256-bit, AEAD)
  └─ [L5] MAC              HMAC-SHA3-512      (tamper detection)
  └─ [L6] Envelope         Base85 + version header
```

| Property | Value |
|----------|-------|
| Key space | 2^512 effective |
| Salt | 256-bit random (fresh per encryption) |
| Nonces | 96-bit × 2 (never reused) |
| Quantum resistance | 128-bit post-quantum (AES + ChaCha20) |
| Timing attacks | `hmac.compare_digest` everywhere |
| Padding oracle | None — AEAD only |

---

## ❌ Wrong Key → Clear Error

```python
wrong_key = mhhs.generate_key()
mhhs.decrypt(token, wrong_key)
# ValueError: Decryption failed — wrong key or data was tampered.
```

---

## 📁 File Structure

```
mhhs/
├── mhhs.py          ← the library (import this)
├── README.md        ← you are here
└── requirements.txt ← pip install -r requirements.txt
```

---

## 🔧 Full Example Script

```python
import mhhs

# --- Setup ---
key = mhhs.generate_key()
print("key:", key)

# --- Message ---
msg = "Hello, World!"
enc = mhhs.encrypt(msg, key)
print("mhhs:", enc)

dec = mhhs.decrypt(enc, key)
print("original:", dec)

# --- Transaction ---
tx = 1_250.00
enc_tx = mhhs.encrypt(tx, key)
print("mhhs:", enc_tx)
print("amount:", mhhs.decrypt(enc_tx, key))
```

---

## 📜 License

MIT — free to use, modify, and share.

---

> Built with ❤️ — MHHS v1.0
