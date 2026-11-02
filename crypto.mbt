///|
/// Diffie-Hellman function. Only Curve25519 (`25519`) is implemented.
pub enum DhKind {
  Curve25519
}

///|
/// AEAD cipher. `ChaChaPoly` is RFC 8439; `AesGcm` is AES-256-GCM.
pub enum CipherKind {
  ChaChaPoly
  AesGcm
}

///|
/// Hash function used for HMAC and HKDF inside Noise.
pub enum HashKind {
  Sha256
  Blake2s
}

///|
pub fn DhKind::name(self : DhKind) -> String {
  match self {
    Curve25519 => "25519"
  }
}

///|
pub fn CipherKind::name(self : CipherKind) -> String {
  match self {
    ChaChaPoly => "ChaChaPoly"
    AesGcm => "AESGCM"
  }
}

///|
pub fn HashKind::name(self : HashKind) -> String {
  match self {
    Sha256 => "SHA256"
    Blake2s => "BLAKE2s"
  }
}

///|
pub fn HashKind::hash_len(self : HashKind) -> Int32 {
  match self {
    Sha256 | Blake2s => 32
  }
}

///|
pub fn HashKind::block_len(self : HashKind) -> Int32 {
  match self {
    Sha256 | Blake2s => 64
  }
}

///|
/// Unkeyed HASH(data).
pub fn HashKind::digest(self : HashKind, data : Bytes) -> Bytes {
  match self {
    Sha256 => @lib.sha256(data)
    Blake2s => @lib.blake2s(data, 32)
  }
}

///|
/// HMAC-HASH(key, message) as required by the Noise spec (RFC 2104).
///
/// SHA-256 uses mooncry's `hmac_sha256`. BLAKE2s HMAC is implemented here
/// because mooncry's keyed BLAKE2s is the BLAKE2 keyed mode, not HMAC.
pub fn HashKind::hmac(self : HashKind, key : Bytes, message : Bytes) -> Bytes {
  match self {
    Sha256 => @lib.hmac_sha256(key, message)
    Blake2s => hmac_blake2s(key, message)
  }
}

///|
fn hmac_blake2s(key : Bytes, message : Bytes) -> Bytes {
  let block = 64
  let k_prime = if key.length() > block {
    pad_right(@lib.blake2s(key, 32), block)
  } else {
    pad_right(key, block)
  }
  let ipad = xor_bytes(k_prime, repeat_byte(b'\x36', block))
  let opad = xor_bytes(k_prime, repeat_byte(b'\x5c', block))
  let inner = @lib.blake2s(concat2(ipad, message), 32)
  @lib.blake2s(concat2(opad, inner), 32)
}

///|
/// Noise HKDF: HMAC(ck, ikm), then the numbered expansion outputs.
fn hkdf(
  hash : HashKind,
  chaining_key : Bytes,
  ikm : Bytes,
  outputs : Int32,
) -> (Bytes, Bytes, Bytes) {
  let temp = hash.hmac(chaining_key, ikm)
  let out1 = hash.hmac(temp, one_byte(b'\x01'))
  let out2 = if outputs >= 2 {
    hash.hmac(temp, concat2(out1, one_byte(b'\x02')))
  } else {
    b""
  }
  let out3 = if outputs >= 3 {
    hash.hmac(temp, concat2(out2, one_byte(b'\x03')))
  } else {
    b""
  }
  (out1, out2, out3)
}

///|
fn cipher_key(material : Bytes) -> Bytes {
  if material.length() == 32 {
    material
  } else {
    bytes_slice(material, 0, 32)
  }
}

///|
/// 96-bit AEAD nonce: 4 zero bytes followed by `n`.
/// ChaChaPoly uses little-endian `n`; AESGCM uses big-endian `n`.
fn aead_nonce(kind : CipherKind, n : UInt64) -> Bytes {
  let buf = @buffer.Buffer()
  buf.write_byte(b'\x00')
  buf.write_byte(b'\x00')
  buf.write_byte(b'\x00')
  buf.write_byte(b'\x00')
  match kind {
    ChaChaPoly => buf.write_uint64_le(n)
    AesGcm => buf.write_uint64_be(n)
  }
  buf.to_bytes()
}

///|
fn aead_encrypt(
  kind : CipherKind,
  key : Bytes,
  n : UInt64,
  ad : Bytes,
  plaintext : Bytes,
) -> Bytes {
  let nonce = aead_nonce(kind, n)
  match kind {
    ChaChaPoly => @lib.chacha20_poly1305_encrypt(key, nonce, ad, plaintext)
    AesGcm => {
      let boxed = @lib.aes_gcm_encrypt(plaintext, key, nonce, ad)
      concat2(boxed.ct, boxed.tag)
    }
  }
}

///|
fn aead_decrypt(
  kind : CipherKind,
  key : Bytes,
  n : UInt64,
  ad : Bytes,
  ciphertext : Bytes,
) -> Bytes raise NoiseError {
  let nonce = aead_nonce(kind, n)
  match kind {
    ChaChaPoly =>
      match @lib.chacha20_poly1305_decrypt_or(key, nonce, ad, ciphertext) {
        Ok(pt) => pt
        Err(_) => raise DecryptFail
      }
    AesGcm => {
      if ciphertext.length() < 16 {
        raise DecryptFail
      }
      let body_len = ciphertext.length() - 16
      let body = bytes_slice(ciphertext, 0, body_len)
      let tag = bytes_slice(ciphertext, body_len, 16)
      match @lib.aes_gcm_decrypt(body, key, nonce, ad, tag) {
        Ok(pt) => pt
        Err(_) => raise DecryptFail
      }
    }
  }
}

///|
/// X25519(scalar, peer public). The scalar is clamped inside mooncry.
pub fn dh_25519(scalar : Bytes, peer_public : Bytes) -> Bytes raise NoiseError {
  match @lib.x25519_or(scalar, peer_public) {
    Ok(shared) => shared
    Err(_) => raise InvalidInput("x25519 inputs must be 32 bytes")
  }
}

///|
/// X25519 public key from a 32-byte private scalar.
pub fn public_key_25519(scalar : Bytes) -> Bytes raise NoiseError {
  if scalar.length() != 32 {
    raise InvalidInput("x25519 private key must be 32 bytes")
  }
  @lib.x25519_public_key(scalar)
}

///|
let nonce_reserved : UInt64 = 18446744073709551615UL
