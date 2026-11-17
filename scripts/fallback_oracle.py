#!/usr/bin/env python3
"""Independent Noise fallback oracle.

This file is not the MoonBit implementation. It recomputes handshake and
transport transcripts for patterns the Noise rev 34 rules allow.

Dependencies, recorded when the expected file was generated:
  Python standard library hashlib and hmac
  cryptography==41.0.7 (PyCA; Apache-2.0 OR BSD-3-Clause)
    X25519PrivateKey, ChaCha20Poly1305, AESGCM

Run from the repository root:

  python3 scripts/fallback_oracle.py --write
  python3 scripts/fallback_oracle.py --check

`--check` recomputes and exits non-zero if scripts/fallback_oracle.json differs.
The MoonBit tests compare against that JSON.
"""

import argparse
import hashlib
import hmac
import json
import pathlib
import sys

import cryptography
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305

ROOT = pathlib.Path(__file__).resolve().parents[1]
OUT = ROOT / "scripts" / "fallback_oracle.json"
PROLOGUE = bytes.fromhex("4a6f686e2047616c74")
INIT_E = bytes.fromhex(
    "893e28b9dc6ca8d611ab664754b8ceb7bac5117349a4439a6b0569da977c464a"
)
RESP_E = bytes.fromhex(
    "bbdb4cdbd309f1a1f2e1456967fe288cadd6f712d65dc7b7793d5e63da6b375b"
)
INIT_S = bytes.fromhex(
    "e61ef9919cde45dd5f82166404bd08e38bceb5dfdfded0a34c8df7ed542214d1"
)
RESP_S = bytes.fromhex(
    "4a3acbfdb163dec651dfa3194dece676d437029c62a408b4c5ea9114246e4893"
)
P0 = bytes.fromhex("4d757272617920526f746862617264")
P1 = bytes.fromhex("462e20412e20486179656b")
P2 = bytes.fromhex("4361726c204d656e676572")
P3 = bytes.fromhex("4a65616e2d426170746973746520536179")
PSK0 = hashlib.sha256(b"noise.mbt fallback psk0").digest()


def pub(scalar: bytes) -> bytes:
    return (
        X25519PrivateKey.from_private_bytes(scalar)
        .public_key()
        .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    )


def dh(scalar: bytes, peer: bytes) -> bytes:
    return X25519PrivateKey.from_private_bytes(scalar).exchange(
        X25519PublicKey.from_public_bytes(peer)
    )


def hkdf(ck: bytes, ikm: bytes, outputs: int):
    temp = hmac.new(ck, ikm, hashlib.sha256).digest()
    out1 = hmac.new(temp, b"\x01", hashlib.sha256).digest()
    out2 = hmac.new(temp, out1 + b"\x02", hashlib.sha256).digest()
    out3 = b""
    if outputs >= 3:
        out3 = hmac.new(temp, out2 + b"\x03", hashlib.sha256).digest()
    return out1, out2, out3


class Sym:
    def __init__(self, cipher: str, protocol: str):
        self.cipher = cipher
        name = protocol.encode()
        self.h = name if len(name) <= 32 else hashlib.sha256(name).digest()
        self.ck = self.h
        self.k = b""
        self.n = 0

    def mix_hash(self, data: bytes) -> None:
        self.h = hashlib.sha256(self.h + data).digest()

    def mix_key(self, ikm: bytes) -> None:
        self.ck, self.k, _ = hkdf(self.ck, ikm, 2)
        self.n = 0

    def mix_key_and_hash(self, ikm: bytes) -> None:
        self.ck, temp_h, self.k = hkdf(self.ck, ikm, 3)
        self.mix_hash(temp_h)
        self.n = 0

    def encrypt(self, plaintext: bytes) -> bytes:
        if self.k == b"":
            self.mix_hash(plaintext)
            return plaintext
        nonce_n = self.n.to_bytes(8, "little" if self.cipher == "ChaChaPoly" else "big")
        nonce = b"\x00\x00\x00\x00" + nonce_n
        aead = (
            ChaCha20Poly1305(self.k)
            if self.cipher == "ChaChaPoly"
            else AESGCM(self.k)
        )
        ciphertext = aead.encrypt(nonce, plaintext, self.h)
        self.mix_hash(ciphertext)
        self.n += 1
        return ciphertext

    def split(self):
        k1, k2, _ = hkdf(self.ck, b"", 2)
        return k1, k2


def transport_encrypt(cipher: str, key: bytes, n: int, plaintext: bytes) -> bytes:
    nonce_n = n.to_bytes(8, "little" if cipher == "ChaChaPoly" else "big")
    nonce = b"\x00\x00\x00\x00" + nonce_n
    aead = ChaCha20Poly1305(key) if cipher == "ChaChaPoly" else AESGCM(key)
    return aead.encrypt(nonce, plaintext, b"")


def decrypt_with(sym: Sym, ciphertext: bytes) -> bytes:
    if sym.k == b"":
        sym.mix_hash(ciphertext)
        return ciphertext
    nonce_n = sym.n.to_bytes(8, "little" if sym.cipher == "ChaChaPoly" else "big")
    nonce = b"\x00\x00\x00\x00" + nonce_n
    aead = (
        ChaCha20Poly1305(sym.k) if sym.cipher == "ChaChaPoly" else AESGCM(sym.k)
    )
    plaintext = aead.decrypt(nonce, ciphertext, sym.h)
    sym.mix_hash(ciphertext)
    sym.n += 1
    return plaintext


def xxfallback_case(cipher: str, psk):
    protocol = (
        "Noise_XXfallback+psk0_25519_%s_SHA256" % cipher
        if psk is not None
        else "Noise_XXfallback_25519_%s_SHA256" % cipher
    )
    alice_e = pub(INIT_E)
    bob_e = pub(RESP_E)
    alice = Sym(cipher, protocol)
    bob = Sym(cipher, protocol)
    for sym in (alice, bob):
        sym.mix_hash(PROLOGUE)
        sym.mix_hash(alice_e)
        # Noise rev 34 section 9: in a PSK handshake every MixHash(e) is
        # followed by MixKey(e), including a pre-message ephemeral.
        if psk is not None:
            sym.mix_key(alice_e)
    m1 = b""
    if psk is not None:
        bob.mix_key_and_hash(psk)
        alice.mix_key_and_hash(psk)
    m1 += bob_e
    bob.mix_hash(bob_e)
    alice.mix_hash(bob_e)
    if psk is not None:
        bob.mix_key(bob_e)
        alice.mix_key(bob_e)
    bob.mix_key(dh(RESP_E, alice_e))
    alice.mix_key(dh(INIT_E, bob_e))
    enc_s = bob.encrypt(pub(RESP_S))
    m1 += enc_s
    if decrypt_with(alice, enc_s) != pub(RESP_S):
        raise RuntimeError("responder static mismatch")
    bob.mix_key(dh(RESP_S, alice_e))
    alice.mix_key(dh(INIT_E, pub(RESP_S)))
    enc_p = bob.encrypt(P0)
    m1 += enc_p
    if decrypt_with(alice, enc_p) != P0:
        raise RuntimeError("m1 payload mismatch")
    m2 = b""
    enc_is = alice.encrypt(pub(INIT_S))
    m2 += enc_is
    if decrypt_with(bob, enc_is) != pub(INIT_S):
        raise RuntimeError("initiator static mismatch")
    alice.mix_key(dh(INIT_S, bob_e))
    bob.mix_key(dh(RESP_E, pub(INIT_S)))
    enc_p2 = alice.encrypt(P1)
    m2 += enc_p2
    if decrypt_with(bob, enc_p2) != P1:
        raise RuntimeError("m2 payload mismatch")
    ak1, ak2 = alice.split()
    bk1, bk2 = bob.split()
    if ak1 != bk1 or ak2 != bk2:
        raise RuntimeError("split mismatch")
    # c1 is initiator -> responder. Bob writes the next transport message,
    # which is c2, then Alice writes c1.
    m3 = transport_encrypt(cipher, bk2, 0, P2)
    m4 = transport_encrypt(cipher, ak1, 0, P3)
    return {
        "protocol": protocol,
        "handshake_hash": alice.h.hex(),
        "m1": m1.hex(),
        "m2": m2.hex(),
        "m3": m3.hex(),
        "m4": m4.hex(),
        "responder_sends_first": True,
        "psk0": None if psk is None else psk.hex(),
    }


def nnfallback_case():
    cipher = "ChaChaPoly"
    protocol = "Noise_NNfallback_25519_ChaChaPoly_SHA256"
    alice_e = pub(INIT_E)
    bob_e = pub(RESP_E)
    alice = Sym(cipher, protocol)
    bob = Sym(cipher, protocol)
    for sym in (alice, bob):
        sym.mix_hash(PROLOGUE)
        sym.mix_hash(alice_e)
    m1 = bob_e
    bob.mix_hash(bob_e)
    alice.mix_hash(bob_e)
    bob.mix_key(dh(RESP_E, alice_e))
    alice.mix_key(dh(INIT_E, bob_e))
    enc = bob.encrypt(P0)
    m1 += enc
    if decrypt_with(alice, enc) != P0:
        raise RuntimeError("nn payload mismatch")
    ak1, ak2 = alice.split()
    bk1, bk2 = bob.split()
    m2 = transport_encrypt(cipher, ak1, 0, P1)
    return {
        "protocol": protocol,
        "handshake_hash": alice.h.hex(),
        "m1": m1.hex(),
        "m2": m2.hex(),
        "responder_sends_first": True,
        "note": "one remaining handshake message from the responder; next transport message is from the initiator",
    }


def build():
    return {
        "oracle": "scripts/fallback_oracle.py",
        "python_cryptography": cryptography.__version__,
        "sources": [
            "Noise Protocol Framework revision 34, sections 5, 9 and 10.2",
            "https://noiseprotocol.org/noise.html",
            "cryptography " + cryptography.__version__ + " X25519, ChaCha20Poly1305, AESGCM",
            "Python hashlib SHA-256 and hmac",
        ],
        "xxfallback_chacha": xxfallback_case("ChaChaPoly", None),
        "xxfallback_aes": xxfallback_case("AESGCM", None),
        "xxfallback_psk0_chacha": xxfallback_case("ChaChaPoly", PSK0),
        "nnfallback_chacha": nnfallback_case(),
    }


def main():
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--write", action="store_true")
    group.add_argument("--check", action="store_true")
    args = parser.parse_args()
    payload = json.dumps(build(), indent=2, sort_keys=True) + "\n"
    if args.write:
        OUT.write_text(payload)
        print("wrote %s" % OUT)
        print("cryptography %s" % cryptography.__version__)
        return
    current = OUT.read_text() if OUT.exists() else ""
    if current != payload:
        print("fallback oracle JSON does not match a fresh run", file=sys.stderr)
        print("cryptography %s" % cryptography.__version__, file=sys.stderr)
        sys.exit(1)
    print("fallback oracle JSON matches")


if __name__ == "__main__":
    main()
