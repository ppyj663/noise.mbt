///|
/// CipherState from Noise spec section 5.1.
///
/// `k` empty means the cipher is not keyed yet: encrypt and decrypt return
/// the input unchanged and do not touch `n`. The nonce value 2^64-1 is
/// reserved for `Rekey` and cannot encrypt or decrypt a message.
pub struct CipherState {
  priv kind : CipherKind
  priv mut key : Bytes?
  priv mut nonce : UInt64
}

///|
pub fn CipherState::new(kind : CipherKind) -> CipherState {
  { kind, key: None, nonce: 0UL, }
}

///|
pub fn CipherState::kind(self : CipherState) -> CipherKind {
  self.kind
}

///|
pub fn CipherState::has_key(self : CipherState) -> Bool {
  match self.key {
    Some(_) => true
    None => false
  }
}

///|
pub fn CipherState::get_nonce(self : CipherState) -> UInt64 {
  self.nonce
}

///|
/// `InitializeKey`. `None` installs the empty key.
pub fn CipherState::initialize_key(
  self : CipherState,
  key : Bytes?,
) -> Unit raise NoiseError {
  match key {
    Some(k) =>
      if k.length() != 32 {
        raise InvalidInput("cipher key must be 32 bytes")
      }
    None => ()
  }
  self.key = key
  self.nonce = 0UL
}

///|
/// `SetNonce`. Used for out-of-order transport messages (spec 11.4).
pub fn CipherState::set_nonce(self : CipherState, nonce : UInt64) -> Unit {
  self.nonce = nonce
}

///|
/// `EncryptWithAd`.
pub fn CipherState::encrypt_with_ad(
  self : CipherState,
  ad : Bytes,
  plaintext : Bytes,
) -> Bytes raise NoiseError {
  match self.key {
    None => plaintext
    Some(key) => {
      if self.nonce == nonce_reserved {
        raise NonceExhausted
      }
      let n = self.nonce
      let out = aead_encrypt(self.kind, key, n, ad, plaintext)
      self.nonce = n + 1UL
      out
    }
  }
}

///|
/// `DecryptWithAd`. On authentication failure `n` is left unchanged.
pub fn CipherState::decrypt_with_ad(
  self : CipherState,
  ad : Bytes,
  ciphertext : Bytes,
) -> Bytes raise NoiseError {
  match self.key {
    None => ciphertext
    Some(key) => {
      if self.nonce == nonce_reserved {
        raise NonceExhausted
      }
      let n = self.nonce
      let out = aead_decrypt(self.kind, key, n, ad, ciphertext)
      self.nonce = n + 1UL
      out
    }
  }
}

///|
/// `Rekey`. No-op when `k` is empty. Does not change `n`.
/// The new key is the first 32 bytes of `ENCRYPT(k, 2^64-1, zerolen, zeros)`.
pub fn CipherState::rekey(self : CipherState) -> Unit {
  match self.key {
    None => ()
    Some(key) => {
      let full = aead_encrypt(self.kind, key, nonce_reserved, b"", zeros(32))
      self.key = Some(bytes_slice(full, 0, 32))
    }
  }
}
