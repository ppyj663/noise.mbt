///|
/// Diffie-Hellman function. `25519` is 32 bytes and `448` is 56 bytes.
pub enum DhKind {
  Curve25519
  X448
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
  Sha512
  Blake2s
  Blake2b
}

///|
pub fn DhKind::name(self : DhKind) -> String {
  match self {
    Curve25519 => "25519"
    X448 => "448"
  }
}

///|
pub fn DhKind::dh_len(self : DhKind) -> Int32 {
  match self {
    Curve25519 => 32
    X448 => 56
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
    Sha512 => "SHA512"
    Blake2s => "BLAKE2s"
    Blake2b => "BLAKE2b"
  }
}

///|
pub fn HashKind::hash_len(self : HashKind) -> Int32 {
  match self {
    Sha256 | Blake2s => 32
    Sha512 | Blake2b => 64
  }
}

///|
pub fn HashKind::block_len(self : HashKind) -> Int32 {
  match self {
    Sha256 | Blake2s => 64
    Sha512 | Blake2b => 128
  }
}

///|
/// SHA-256 via mooncry. Useful for deriving demo keys.
pub fn sha256(data : Bytes) -> Bytes {
  @lib.sha256(data)
}

///|
/// Lower-case hex encoding via mooncry.
pub fn to_hex(data : Bytes) -> String {
  @lib.bytes_to_hex(data)
}

///|
/// Unkeyed HASH(data).
pub fn HashKind::digest(self : HashKind, data : Bytes) -> Bytes {
  match self {
    Sha256 => @lib.sha256(data)
    Sha512 => @lib.sha512(data)
    Blake2s => blake2s_256(data)
    Blake2b => blake2b_512(data)
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
    Sha512 => @lib.hmac_sha512(key, message)
    Blake2s => hmac_with(64, key, message, blake2s_256)
    Blake2b => hmac_with(128, key, message, blake2b_512)
  }
}

///|
fn hmac_with(
  block : Int32,
  key : Bytes,
  message : Bytes,
  digest : (Bytes) -> Bytes,
) -> Bytes {
  let k_prime = if key.length() > block {
    pad_right(digest(key), block)
  } else {
    pad_right(key, block)
  }
  let ipad = xor_bytes(k_prime, repeat_byte(b'\x36', block))
  let opad = xor_bytes(k_prime, repeat_byte(b'\x5c', block))
  digest(concat2(opad, digest(concat2(ipad, message))))
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
/// Public key for the selected Noise DH function.
pub fn dh_public(kind : DhKind, scalar : Bytes) -> Bytes raise NoiseError {
  match kind {
    Curve25519 => public_key_25519(scalar)
    X448 => public_key_x448(scalar)
  }
}

///|
/// DH(private, peer public) for the selected Noise DH function.
pub fn dh_exchange(
  kind : DhKind,
  scalar : Bytes,
  peer_public : Bytes,
) -> Bytes raise NoiseError {
  match kind {
    Curve25519 => dh_25519(scalar, peer_public)
    X448 => dh_x448(scalar, peer_public)
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
/// X448(scalar, peer public). The scalar is 56 bytes.
pub fn dh_x448(scalar : Bytes, peer_public : Bytes) -> Bytes raise NoiseError {
  match @lib.x448_or(scalar, peer_public) {
    Ok(shared) => shared
    Err(_) => raise InvalidInput("x448 inputs must be 56 bytes")
  }
}

///|
/// X448 public key from a 56-byte private scalar.
pub fn public_key_x448(scalar : Bytes) -> Bytes raise NoiseError {
  if scalar.length() != 56 {
    raise InvalidInput("x448 private key must be 56 bytes")
  }
  @lib.x448_public_key(scalar)
}

///|
let nonce_reserved : UInt64 = 18446744073709551615UL
