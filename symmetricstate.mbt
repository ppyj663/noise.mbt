///|
/// SymmetricState from Noise spec section 5.2: chaining key, handshake hash,
/// and one CipherState.
pub struct SymmetricState {
  priv cipher : CipherState
  priv hash : HashKind
  priv mut ck : Bytes
  priv mut h : Bytes
}

///|
pub fn SymmetricState::new(
  cipher : CipherKind,
  hash : HashKind,
) -> SymmetricState {
  let n = hash.hash_len()
  { cipher: CipherState::new(cipher), hash, ck: zeros(n), h: zeros(n), }
}

///|
pub fn SymmetricState::has_key(self : SymmetricState) -> Bool {
  self.cipher.has_key()
}

///|
pub fn SymmetricState::get_hash(self : SymmetricState) -> Bytes {
  self.h
}

///|
/// `InitializeSymmetric`.
pub fn SymmetricState::initialize(
  self : SymmetricState,
  protocol_name : String,
) -> Unit raise NoiseError {
  let name = @utf8.encode(protocol_name)
  let hlen = self.hash.hash_len()
  if name.length() <= hlen {
    self.h = pad_right(name, hlen)
  } else {
    self.h = self.hash.digest(name)
  }
  self.ck = self.h
  self.cipher.initialize_key(None)
}

///|
/// `MixKey`.
pub fn SymmetricState::mix_key(
  self : SymmetricState,
  ikm : Bytes,
) -> Unit raise NoiseError {
  let (ck, temp_k, _) = hkdf(self.hash, self.ck, ikm, 2)
  self.ck = ck
  self.cipher.initialize_key(Some(cipher_key(temp_k)))
}

///|
/// `MixHash`.
pub fn SymmetricState::mix_hash(self : SymmetricState, data : Bytes) -> Unit {
  self.h = self.hash.digest(concat2(self.h, data))
}

///|
/// `MixKeyAndHash`, used by the `psk` token.
pub fn SymmetricState::mix_key_and_hash(
  self : SymmetricState,
  ikm : Bytes,
) -> Unit raise NoiseError {
  let (ck, temp_h, temp_k) = hkdf(self.hash, self.ck, ikm, 3)
  self.ck = ck
  self.mix_hash(temp_h)
  self.cipher.initialize_key(Some(cipher_key(temp_k)))
}

///|
/// `EncryptAndHash`.
pub fn SymmetricState::encrypt_and_hash(
  self : SymmetricState,
  plaintext : Bytes,
) -> Bytes raise NoiseError {
  let ciphertext = self.cipher.encrypt_with_ad(self.h, plaintext)
  self.mix_hash(ciphertext)
  ciphertext
}

///|
/// `DecryptAndHash`. The handshake hash absorbs the ciphertext only after
/// authentication succeeds.
pub fn SymmetricState::decrypt_and_hash(
  self : SymmetricState,
  ciphertext : Bytes,
) -> Bytes raise NoiseError {
  let plaintext = self.cipher.decrypt_with_ad(self.h, ciphertext)
  self.mix_hash(ciphertext)
  plaintext
}

///|
/// `Split`. Returns `(c1, c2)` for initiator-to-responder and the reverse.
pub fn SymmetricState::split(
  self : SymmetricState,
) -> (CipherState, CipherState) raise NoiseError {
  let (k1, k2, _) = hkdf(self.hash, self.ck, b"", 2)
  let c1 = CipherState::new(self.cipher.kind())
  let c2 = CipherState::new(self.cipher.kind())
  c1.initialize_key(Some(cipher_key(k1)))
  c2.initialize_key(Some(cipher_key(k2)))
  (c1, c2)
}
