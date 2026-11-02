///|
/// Failures from the Noise state machine.
///
/// `DecryptFail` is authentication failure. `NonceExhausted` means `n` reached
/// the reserved value 2^64-1, so no further transport message can use that
/// cipher key.
pub suberror NoiseError {
  DecryptFail
  NonceExhausted
  MissingKey
  MissingRandom
  WrongTurn
  HandshakeFinished
  HandshakeFailed
  TruncatedMessage
  MessageTooLong
  InvalidInput(String)
  Unsupported(String)
}
