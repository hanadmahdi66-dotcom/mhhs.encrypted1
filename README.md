![Version](https://img.shields.io/badge/MHHS-v1.0-7F77DD?style=for-the-badge&logo=shield&logoColor=white)
![Python](https://img.shields.io/badge/Python-3.9+-3776AB?style=for-the-badge&logo=python&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-D4537E?style=for-the-badge)
![Status](https://img.shields.io/badge/Status-Active-1D9E75?style=for-the-badge)
![Platform](https://img.shields.io/badge/Platform-Linux%20|%20Mac%20|%20Windows-888780?style=for-the-badge)

---





# 🔐 MHHS — Multi-layer Hybrid Hash Shield

> **Custom encryption library** — layered AES-256 + ChaCha20 + custom SPN cipher.MHHS GAME LYER
> Simple API, military-grade protection.

---

## ⚡ Quick Install

```bash
# 1. Clone the repo
git clone https://github.com/hanadmahdi66-dotcom/mhhs.encrypted1.git
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

### 🛡 Encryption Layers

![AES-256](https://img.shields.io/badge/AES--256--GCM-Military_Grade-E24B4A?style=for-the-badge&logoColor=white)
![ChaCha20](https://img.shields.io/badge/ChaCha20--Poly1305-Google_Standard-0F6E56?style=for-the-badge&logoColor=white)
![SPN](https://img.shields.io/badge/SPN_Cipher-16_Rounds-534AB7?style=for-the-badge&logoColor=white)
![Layers](https://img.shields.io/badge/Encryption_Layers-6_Deep-BA7517?style=for-the-badge&logoColor=white)
![Quantum](https://img.shields.io/badge/Quantum_Resistant-128bit_PostQ-185FA5?style=for-the-badge&logoColor=white)
![HMAC](https://img.shields.io/badge/HMAC--SHA3--512-Tamper_Proof-993C1D?style=for-the-badge&logoColor=white)
![PBKDF2](https://img.shields.io/badge/PBKDF2--SHA512-400K_iters-639922?style=for-the-badge&logoColor=white)
![KeySize](https://img.shields.io/badge/Key_Size-512_bit-7F77DD?style=for-the-badge&logoColor=white)
![Install](https://img.shields.io/badge/pip_install-cryptography-3776AB?style=for-the-badge&logo=python&logoColor=white)

---

## ❌ Wrong Key → Clear Error

```python
wrong_key = mhhs.generate_key()
mhhs.decrypt(token, wrong_key)
# ValueError: Decryption failed — wrong key or data was tampered.
```

---


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

> Built with  — MHHS v1.0
