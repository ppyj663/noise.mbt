///|
/// Fixed labels below are test secrets only. Do not use them in production.
fn bhex(s : String) -> Bytes {
  @lib.hex_to_bytes(s)
}

///|
fn expect_noise(
  kind : String,
  action : () -> Unit raise NoiseError,
) -> Unit raise Error {
  try {
    action()
    fail("expected " + kind)
  } catch {
    DecryptFail => assert_eq(kind, "decrypt")
    NonceExhausted => assert_eq(kind, "nonce")
    MissingKey => assert_eq(kind, "missing")
    WrongTurn => assert_eq(kind, "turn")
    HandshakeFailed => assert_eq(kind, "failed")
    TruncatedMessage => assert_eq(kind, "truncated")
    MessageTooLong => assert_eq(kind, "long")
    InvalidInput(_) => assert_eq(kind, "input")
    _ => fail("unexpected error, wanted " + kind)
  }
}

///|
fn xx_transport() -> (Transport, Transport) raise NoiseError {
  let init = Builder::new("Noise_XX_25519_ChaChaPoly_SHA256")
    .local_private_key(@lib.sha256(b"boundary-init-static"))
    .local_ephemeral_private(@lib.sha256(b"boundary-init-e"))
    .build_initiator(None)
  let resp = Builder::new("Noise_XX_25519_ChaChaPoly_SHA256")
    .local_private_key(@lib.sha256(b"boundary-resp-static"))
    .local_ephemeral_private(@lib.sha256(b"boundary-resp-e"))
    .build_responder(None)
  let m1 = init.write_message(b"")
  let _ = resp.read_message(m1)
  let m2 = resp.write_message(b"")
  let _ = init.read_message(m2)
  let m3 = init.write_message(b"")
  let _ = resp.read_message(m3)
  (init.into_transport(), resp.into_transport())
}

///|
test "empty payload and flipped transport ciphertext" {
  let (a, b) = xx_transport()
  let ct = a.write_message(b"")
  assert_eq(ct.length(), 16)
  assert_eq(b.read_message(ct), b"")
  let good = a.write_message(b"payload")
  let flipped = flip_last(good)
  let nonce_before = b.receiving_nonce()
  expect_noise("decrypt", () => {
    let _ = b.read_message(flipped)
  })
  assert_eq(b.receiving_nonce(), nonce_before)
  assert_eq(b.read_message(good), b"payload")
}

///|
test "every truncated prefix of a transport message fails closed" {
  let (a, b) = xx_transport()
  let ct = a.write_message(b"truncate-me-please")
  let mut n = 0
  while n < ct.length() {
    let prefix = bytes_slice(ct, 0, n)
    let before = b.receiving_nonce()
    expect_noise("decrypt", () => {
      let _ = b.read_message(prefix)
    })
    assert_eq(b.receiving_nonce(), before)
    n = n + 1
  }
  assert_eq(b.read_message(ct), b"truncate-me-please")
}

///|
test "oversized transport write does not consume a nonce" {
  let (a, b) = xx_transport()
  let before = a.sending_nonce()
  let too_big = Bytes::make(65520, b'\x61')
  expect_noise("long", () => {
    let _ = a.write_message(too_big)
  })
  assert_eq(a.sending_nonce(), before)
  let limit = Bytes::make(65519, b'\x62')
  let ct = a.write_message(limit)
  assert_eq(ct.length(), 65535)
  assert_eq(b.read_message(ct), limit)
  expect_noise("long", () => {
    let _ = b.read_message(Bytes::make(65536, b'\x00'))
  })
}

///|
test "repeat read does not return the old plaintext" {
  let (a, b) = xx_transport()
  let ct = a.write_message(b"once")
  assert_eq(b.read_message(ct), b"once")
  expect_noise("decrypt", () => {
    let _ = b.read_message(ct)
  })
}

///|
test "rekey desynchronizes until the peer rekeys and nonce is kept" {
  let (a, b) = xx_transport()
  let n = a.sending_nonce()
  a.rekey_send()
  assert_eq(a.sending_nonce(), n)
  let ct = a.write_message(b"rotated")
  expect_noise("decrypt", () => {
    let _ = b.read_message(ct)
  })
  b.rekey_recv()
  assert_eq(b.read_message(ct), b"rotated")
}

///|
test "nonce exhaustion on transport" {
  let (a, _) = xx_transport()
  a.set_receiving_nonce(18446744073709551615UL)
  // set_receiving_nonce changes recv, not send. Exhaust the sender directly.
  let _ = a
  let send = CipherState::new(ChaChaPoly)
  send.initialize_key(Some(@lib.sha256(b"nonce-key")))
  send.set_nonce(18446744073709551614UL)
  let ct = send.encrypt_with_ad(b"", b"last")
  expect_noise("nonce", () => {
    let _ = send.encrypt_with_ad(b"", b"no")
  })
  let recv = CipherState::new(ChaChaPoly)
  recv.initialize_key(Some(@lib.sha256(b"nonce-key")))
  recv.set_nonce(18446744073709551614UL)
  assert_eq(recv.decrypt_with_ad(b"", ct), b"last")
  expect_noise("nonce", () => {
    let _ = recv.decrypt_with_ad(b"", ct)
  })
}

///|
test "invalid key lengths and wrong handshake turn" {
  expect_noise("input", () => {
    let _ = Builder::new("Noise_NN_25519_ChaChaPoly_SHA256").local_private_key(
      b"short",
    )
  })
  let init = Builder::new("Noise_NN_25519_ChaChaPoly_SHA256")
    .local_ephemeral_private(@lib.sha256(b"i-e"))
    .build_initiator(None)
  expect_noise("turn", () => {
    let _ = init.read_message(b"")
  })
}

///|
test "all-zero X25519 peer public is not rejected" {
  // Noise rev 34 section 12.1: invalid public keys produce an all-zero output.
  // This test does not claim that every invalid point is rejected.
  let scalar = bhex(
    "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
  )
  let shared = dh_25519(scalar, Bytes::make(32, b'\x00'))
  assert_eq(shared, Bytes::make(32, b'\x00'))
}

///|
test "deterministic sample of payload lengths round-trips" {
  // A fixed xorshift sample, not a claim about every random input.
  let init = Builder::new("Noise_NN_25519_AESGCM_SHA256")
    .local_ephemeral_private(@lib.sha256(b"fuzz-i"))
    .build_initiator(None)
  let resp = Builder::new("Noise_NN_25519_AESGCM_SHA256")
    .local_ephemeral_private(@lib.sha256(b"fuzz-r"))
    .build_responder(None)
  let m0 = init.write_message(b"hs")
  let _ = resp.read_message(m0)
  let m1 = resp.write_message(b"hs")
  let _ = init.read_message(m1)
  let a = init.into_transport()
  let b = resp.into_transport()
  let mut state = 0xC0FFEEU
  let mut n = 0
  while n < 24 {
    state = state ^ (state << 13)
    state = state ^ (state >> 17)
    state = state ^ (state << 5)
    let len = (state & 0xFFU).reinterpret_as_int()
    let payload = Bytes::make(len, (n + 1).to_byte())
    if n % 2 == 0 {
      let ct = a.write_message(payload)
      assert_eq(b.read_message(ct), payload)
    } else {
      let ct = b.write_message(payload)
      assert_eq(a.read_message(ct), payload)
    }
    n = n + 1
  }
}

///|
test "authentication failure during handshake deletes the attempt" {
  let init = Builder::new("Noise_NN_25519_ChaChaPoly_SHA256")
    .prologue(b"p")
    .local_ephemeral_private(@lib.sha256(b"a"))
    .build_initiator(None)
  let resp = Builder::new("Noise_NN_25519_ChaChaPoly_SHA256")
    .prologue(b"p")
    .local_ephemeral_private(@lib.sha256(b"b"))
    .build_responder(None)
  let m1 = init.write_message(b"one")
  let _ = resp.read_message(m1)
  let m2 = resp.write_message(b"two")
  expect_noise("decrypt", () => {
    let _ = init.read_message(flip_last(m2))
  })
  expect_noise("failed", () => {
    let _ = init.read_message(m2)
  })
}
