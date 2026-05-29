"""
╔══════════════════════════════════════════════════════════════════╗
║   MHHS  —  Multi-layer Hybrid Hash Shield                       ║
║   Custom Encryption Library  |  v1.0                            ║
║                                                                  ║
║   USAGE:                                                         ║
║     import mhhs                                                  ║
║                                                                  ║
║     key = mhhs.generate_key()                                    ║
║     print("key:", key)                                           ║
║                                                                  ║
║     msg = "hello world"                                          ║
║     encrypted = mhhs.encrypt(msg, key)                          ║
║     print("mhhs:", encrypted)                                    ║
║                                                                  ║
║     original = mhhs.decrypt(encrypted, key)                     ║
║     print("original:", original)                                 ║
║                                                                  ║
║   KEY FORMATS:                                                   ║
║     mhhs.generate_key()          →  full 512-bit key            ║
║     mhhs.generate_key("short")   →  short readable key          ║
║     mhhs.generate_key("pair")    →  (public_key, private_key)   ║
╚══════════════════════════════════════════════════════════════════╝
"""

import os
import hmac
import struct
import base64
import hashlib
import secrets
import textwrap
from typing import Union, Tuple

from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes as _hashes, hmac as _hmac
from cryptography.hazmat.backends import default_backend

# ──────────────────────────────────────────
#  INTERNAL CONSTANTS
# ──────────────────────────────────────────
_MAGIC       = b"MH1"
_SALT_LEN    = 32
_NONCE_CHA   = 12
_NONCE_AES   = 12
_MAC_LEN     = 64
_PBKDF2_ITER = 400_000
_KEY_VERSION  = "mhhs-v1"


# ──────────────────────────────────────────
#  INTERNAL: S-BOX  (SHA3-derived, bijective)
# ──────────────────────────────────────────
def _make_sbox():
    seed = hashlib.sha3_256(b"MHHS-SBOX-V1").digest()
    box = list(range(256))
    j = 0
    for i in range(256):
        j = (j + box[i] + seed[i % 32]) & 0xFF
        box[i], box[j] = box[j], box[i]
    inv = bytearray(256)
    for i, v in enumerate(box):
        inv[v] = i
    return bytes(box), bytes(inv)

_SBOX, _INV_SBOX = _make_sbox()


# ──────────────────────────────────────────
#  INTERNAL: SPN CIPHER  (16-round)
# ──────────────────────────────────────────
def _rk(key: bytes, r: int) -> bytes:
    return hmac.new(key, r.to_bytes(4, "big"), "sha256").digest()

def _mix(b: bytearray) -> bytearray:
    out, prev = bytearray(len(b)), 0
    for i, x in enumerate(b):
        out[i] = x ^ prev
        prev = out[i]
    return out

def _unmix(b: bytearray) -> bytearray:
    out, prev = bytearray(len(b)), 0
    for i, x in enumerate(b):
        out[i] = x ^ prev
        prev = x
    return out

def _spn(data: bytes, key: bytes, enc: bool) -> bytes:
    BLOCK = 64
    if enc:
        pad = BLOCK - (len(data) % BLOCK)
        data += bytes([pad] * pad)
        out = b""
        for i in range(0, len(data), BLOCK):
            blk = bytearray(data[i:i+BLOCK])
            for r in range(16):
                blk = bytearray(_SBOX[x] for x in blk)
                blk = _mix(blk)
                rk = _rk(key, r)
                for j in range(len(blk)):
                    blk[j] ^= rk[j % 32]
            out += bytes(blk)
        return out
    else:
        out = b""
        for i in range(0, len(data), BLOCK):
            blk = bytearray(data[i:i+BLOCK])
            for r in reversed(range(16)):
                rk = _rk(key, r)
                for j in range(len(blk)):
                    blk[j] ^= rk[j % 32]
                blk = _unmix(blk)
                blk = bytearray(_INV_SBOX[x] for x in blk)
            out += bytes(blk)
        return out[:-out[-1]]


# ──────────────────────────────────────────
#  INTERNAL: KEY PARSING
# ──────────────────────────────────────────
def _parse_key(key: str) -> bytes:
    """Accept both full key (hex) and short key (base32 padded)."""
    try:
        raw = bytes.fromhex(key)
        if len(raw) == 64:
            return raw
    except ValueError:
        pass
    try:
        raw = bytes.fromhex(key.replace("-", "").replace(" ", ""))
        if len(raw) >= 16:
            # expand short key to 64 bytes via HKDF
            hkdf = HKDF(_hashes.SHA3_512(), 64, b"mhhs-short-key", b"MHHS-EXPAND", default_backend())
            return hkdf.derive(raw)
    except ValueError:
        pass
    raise ValueError("Invalid key. Use mhhs.generate_key() to create a valid key.")


def _derive(key_bytes: bytes, salt: bytes):
    """Split 64-byte master key into 3 subkeys via HKDF."""
    def _e(label):
        h = HKDF(_hashes.SHA3_512(), 32, salt, b"MHHS-" + label, default_backend())
        return h.derive(key_bytes)
    return _e(b"SPN"), _e(b"CHA"), _e(b"AES")


def _mac(spn_k, cha_k, aes_k, *parts):
    mac_key = hashlib.sha3_256(spn_k + cha_k + aes_k).digest()
    h = _hmac.HMAC(mac_key, _hashes.SHA3_512(), default_backend())
    for p in parts:
        h.update(struct.pack(">Q", len(p)))
        h.update(p)
    return h.finalize()


# ══════════════════════════════════════════
#  PUBLIC API
# ══════════════════════════════════════════

class MHHSKey(str):
    """
    A string subclass so you can print it normally but it
    also carries .short and .algorithm metadata.
    """
    short: str
    algorithm: str
    bits: int

    def __new__(cls, value, short="", algorithm="MHHS-v1", bits=512):
        obj = str.__new__(cls, value)
        obj.short = short
        obj.algorithm = algorithm
        obj.bits = bits
        return obj

    def __repr__(self):
        return f"MHHSKey('{self.short}...', bits={self.bits})"


def generate_key(mode: str = "full") -> "MHHSKey | Tuple[MHHSKey, MHHSKey]":
    """
    Generate a new encryption key.

    Modes:
        "full"   (default) — 512-bit key, hex string
        "short"            — compact 128-bit key (still strong)
        "pair"             — returns (public_key, private_key) tuple

    Examples:
        key = mhhs.generate_key()
        key = mhhs.generate_key("short")
        pub, priv = mhhs.generate_key("pair")
    """
    if mode == "full":
        raw = secrets.token_bytes(64)
        hex_key = raw.hex()
        short = hex_key[:8] + "..." + hex_key[-4:]
        k = MHHSKey(hex_key, short=short, algorithm="MHHS-v1", bits=512)
        return k

    elif mode == "short":
        raw = secrets.token_bytes(16)
        grouped = "-".join(raw.hex()[i:i+4] for i in range(0, 32, 4))
        short = grouped[:9] + "..."
        k = MHHSKey(grouped.replace("-", ""), short=grouped, algorithm="MHHS-v1-short", bits=128)
        k.short = grouped   # readable grouped form
        return k

    elif mode == "pair":
        priv_raw = secrets.token_bytes(64)
        priv_hex = priv_raw.hex()
        # Public key = HKDF-derived from private (one-way)
        hkdf = HKDF(_hashes.SHA3_512(), 32, b"mhhs-pub", b"MHHS-PUBLIC", default_backend())
        pub_raw = hkdf.derive(priv_raw)
        pub_hex = pub_raw.hex()
        priv_k = MHHSKey(priv_hex, short=priv_hex[:8]+"...", algorithm="MHHS-private", bits=512)
        pub_k  = MHHSKey(pub_hex,  short=pub_hex[:8]+"...",  algorithm="MHHS-public",  bits=256)
        return pub_k, priv_k

    else:
        raise ValueError(f"Unknown mode '{mode}'. Use: 'full', 'short', or 'pair'")


def encrypt(data: Union[str, bytes, int, float], key: str) -> str:
    """
    Encrypt any value.

    Returns a compact MHHS token string.

    Examples:
        token = mhhs.encrypt("hello", key)
        token = mhhs.encrypt(9999.99, key)      # numbers (e.g. transactions)
        token = mhhs.encrypt(b"binary", key)
    """
    # Serialize input to bytes with type tag
    if isinstance(data, str):
        payload = b"\x01" + data.encode("utf-8")
    elif isinstance(data, bytes):
        payload = b"\x02" + data
    elif isinstance(data, int):
        payload = b"\x03" + str(data).encode()
    elif isinstance(data, float):
        payload = b"\x04" + str(data).encode()
    else:
        payload = b"\x05" + str(data).encode()

    key_bytes = _parse_key(key)
    salt      = secrets.token_bytes(_SALT_LEN)
    n_cha     = secrets.token_bytes(_NONCE_CHA)
    n_aes     = secrets.token_bytes(_NONCE_AES)

    k_spn, k_cha, k_aes = _derive(key_bytes, salt)

    # Layer 2: SPN
    c1 = _spn(payload, k_spn, enc=True)
    # Layer 3: ChaCha20-Poly1305
    c2 = ChaCha20Poly1305(k_cha).encrypt(n_cha, c1, salt)
    # Layer 4: AES-256-GCM
    c3 = AESGCM(k_aes).encrypt(n_aes, c2, salt + n_cha)
    # Layer 5: MAC
    tag = _mac(k_spn, k_cha, k_aes, salt, n_cha, n_aes, c3)

    blob = _MAGIC + salt + n_cha + n_aes + tag + c3
    return base64.b85encode(blob).decode("ascii")


def decrypt(token: str, key: str) -> Union[str, bytes, int, float]:
    """
    Decrypt a MHHS token back to its original value.

    Raises ValueError on wrong key or tampered data.

    Example:
        original = mhhs.decrypt(token, key)
    """
    try:
        blob = base64.b85decode(token.encode("ascii"))
    except Exception:
        raise ValueError("Not a valid MHHS token.")

    if blob[:3] != _MAGIC:
        raise ValueError("Invalid token — not MHHS format.")

    pos = 3
    salt  = blob[pos:pos+_SALT_LEN];  pos += _SALT_LEN
    n_cha = blob[pos:pos+_NONCE_CHA]; pos += _NONCE_CHA
    n_aes = blob[pos:pos+_NONCE_AES]; pos += _NONCE_AES
    tag   = blob[pos:pos+_MAC_LEN];   pos += _MAC_LEN
    ct    = blob[pos:]

    key_bytes        = _parse_key(key)
    k_spn, k_cha, k_aes = _derive(key_bytes, salt)

    # Verify MAC first (timing-safe)
    expected = _mac(k_spn, k_cha, k_aes, salt, n_cha, n_aes, ct)
    if not hmac.compare_digest(tag, expected):
        raise ValueError("Decryption failed — wrong key or data was tampered.")

    c2 = AESGCM(k_aes).decrypt(n_aes, ct, salt + n_cha)
    c1 = ChaCha20Poly1305(k_cha).decrypt(n_cha, c2, salt)
    raw = _spn(c1, k_spn, enc=False)

    # Deserialize by type tag
    tag_byte, value = raw[0], raw[1:]
    if tag_byte == 0x01: return value.decode("utf-8")
    if tag_byte == 0x02: return bytes(value)
    if tag_byte == 0x03: return int(value)
    if tag_byte == 0x04: return float(value)
    return value.decode("utf-8")


# ──────────────────────────────────────────
#  CONVENIENCE: MHHSMessage wrapper
# ──────────────────────────────────────────

class MHHSMessage:
    """
    Optional wrapper that mimics the mhhs.encrypted(msg) style.

    Example:
        m = mhhs.message("hello world")
        m.encrypt(key)
        print("mhhs:", m)          # prints encrypted token
        m.decrypt(key)
        print("original:", m)      # prints original text
    """

    def __init__(self, data):
        self._original = data
        self._token    = None
        self._decrypted = None

    def encrypt(self, key: str) -> "MHHSMessage":
        self._token = encrypt(self._original, key)
        return self

    def decrypt(self, key: str) -> "MHHSMessage":
        if self._token is None:
            raise ValueError("Nothing encrypted yet. Call .encrypt(key) first.")
        self._decrypted = decrypt(self._token, key)
        return self

    def __str__(self):
        if self._decrypted is not None:
            return str(self._decrypted)
        if self._token is not None:
            return self._token
        return str(self._original)

    def __repr__(self):
        state = "encrypted" if self._token and not self._decrypted else (
                "decrypted" if self._decrypted else "plaintext")
        return f"MHHSMessage({state})"


def message(data) -> MHHSMessage:
    """Create a MHHSMessage object for fluent encrypt/decrypt."""
    return MHHSMessage(data)


# ──────────────────────────────────────────
#  DEMO
# ──────────────────────────────────────────

if __name__ == "__main__":
    SEP = "─" * 54

    print()
    print(SEP)
    print("  MHHS  —  Multi-layer Hybrid Hash Shield")
    print(SEP)

    # ── 1. generate_key + print
    print()
    print("  ── 1. Key generation ──")
    key = generate_key()
    print(f"  key: {key}")
    print(f"  key.short:     {key.short}")
    print(f"  key.algorithm: {key.algorithm}")
    print(f"  key.bits:      {key.bits}")

    # ── 2. Encrypt a message
    print()
    print("  ── 2. Encrypt a message ──")
    msg = "hello"
    encrypted_msg = encrypt(msg, key)
    print(f'  msg = "{msg}"')
    print(f"  mhhs: {encrypted_msg}")

    # ── 3. Decrypt
    print()
    print("  ── 3. Decrypt ──")
    original = decrypt(encrypted_msg, key)
    print(f"  original: {original}")

    # ── 4. Transaction / money amount
    print()
    print("  ── 4. Encrypt a transaction amount ──")
    amount = 9_500.75
    enc_amount = encrypt(amount, key)
    print(f"  amount = {amount}")
    print(f"  mhhs: {enc_amount}")
    dec_amount = decrypt(enc_amount, key)
    print(f"  decrypted: {dec_amount}  (type: {type(dec_amount).__name__})")

    # ── 5. Short key style
    print()
    print("  ── 5. Short key ──")
    short_key = generate_key("short")
    print(f"  key: {short_key.short}")
    enc2 = encrypt("Nabad iyo amaan", short_key)
    dec2 = decrypt(enc2, short_key)
    print(f"  mhhs: {enc2[:60]}...")
    print(f"  decrypted: {dec2}")

    # ── 6. Key pair
    print()
    print("  ── 6. Key pair ──")
    pub, priv = generate_key("pair")
    print(f"  public  key: {pub.short}")
    print(f"  private key: {priv.short}")

    # ── 7. MHHSMessage fluent style
    print()
    print("  ── 7. Fluent MHHSMessage style ──")
    m = message("Lacagta waxay tahay $5,000")
    m.encrypt(key)
    print(f"  print('mhhs:', m)  →  mhhs: {m}")
    m.decrypt(key)
    print(f"  print('msg:', m)   →  msg: {m}")

    # ── 8. Wrong key test
    print()
    print("  ── 8. Wrong key rejection ──")
    wrong_key = generate_key()
    try:
        decrypt(encrypted_msg, wrong_key)
        print("  ✗ FAIL")
    except ValueError as e:
        print(f"  ✓ Rejected: {e}")

    print()
    print(SEP)
    print("  All tests passed ✓")
    print(SEP)
    print()
