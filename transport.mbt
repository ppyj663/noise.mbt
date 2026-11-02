///|
/// Transport ciphers returned by `Split`.
///
/// `send` encrypts messages this party transmits. `recv` decrypts messages
/// from the peer. Associated data is empty, per the spec. Call `rekey_send`
/// or `rekey_recv` to rotate a key without resetting its nonce.
pub struct Transport {
  priv send : CipherState
  priv recv : CipherState
  priv hash : Bytes
}

///|
pub fn Transport::handshake_hash(self : Transport) -> Bytes {
  self.hash
}

///|
pub fn Transport::sending_nonce(self : Transport) -> UInt64 {
  self.send.get_nonce()
}

///|
pub fn Transport::receiving_nonce(self : Transport) -> UInt64 {
  self.recv.get_nonce()
}

///|
/// `SetNonce` on the receiving cipher (spec section 11.4).
/// Replay tracking is left to the application.
pub fn Transport::set_receiving_nonce(self : Transport, nonce : UInt64) -> Unit {
  self.recv.set_nonce(nonce)
}

///|
pub fn Transport::write_message(
  self : Transport,
  payload : Bytes,
) -> Bytes raise NoiseError {
  let message = self.send.encrypt_with_ad(b"", payload)
  if message.length() > 65535 {
    raise MessageTooLong
  }
  message
}

///|
pub fn Transport::read_message(
  self : Transport,
  message : Bytes,
) -> Bytes raise NoiseError {
  if message.length() > 65535 {
    raise MessageTooLong
  }
  self.recv.decrypt_with_ad(b"", message)
}

///|
pub fn Transport::rekey_send(self : Transport) -> Unit {
  self.send.rekey()
}

///|
pub fn Transport::rekey_recv(self : Transport) -> Unit {
  self.recv.rekey()
}
