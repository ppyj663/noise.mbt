///|
fn demo_key(label : String) -> Bytes {
  @lib.sha256(@utf8.encode(label))
}

///|
test "wrong turn and tampered handshake" {
  let init = Builder::new("Noise_NN_25519_ChaChaPoly_SHA256")
    .prologue(b"prologue")
    .local_ephemeral_private(demo_key("i-e"))
    .build_initiator(None)
  let resp = Builder::new("Noise_NN_25519_ChaChaPoly_SHA256")
    .prologue(b"prologue")
    .local_ephemeral_private(demo_key("r-e"))
    .build_responder(None)
  let early = try {
    let _ = resp.write_message(b"no")
    true
  } catch {
    WrongTurn => false
    _ => true
  }
  assert_false(early)
  let m1 = init.write_message(b"hello")
  assert_eq(resp.read_message(m1), b"hello")
  let m2 = resp.write_message(b"world")
  let tampered = try {
    let _ = init.read_message(flip_last(m2))
    true
  } catch {
    DecryptFail => false
    _ => true
  }
  assert_false(tampered)
  let dead = try {
    let _ = init.read_message(m2)
    true
  } catch {
    HandshakeFailed => false
    _ => true
  }
  assert_false(dead)
}

///|
test "transport tamper rekey and nonce" {
  let init = Builder::new("Noise_XX_25519_AESGCM_SHA256")
    .local_private_key(demo_key("i-s"))
    .local_ephemeral_private(demo_key("i-e"))
    .build_initiator(None)
  let resp = Builder::new("Noise_XX_25519_AESGCM_SHA256")
    .local_private_key(demo_key("r-s"))
    .local_ephemeral_private(demo_key("r-e"))
    .build_responder(None)
  let m1 = init.write_message(b"one")
  assert_eq(resp.read_message(m1), b"one")
  let m2 = resp.write_message(b"two")
  assert_eq(init.read_message(m2), b"two")
  let m3 = init.write_message(b"three")
  assert_eq(resp.read_message(m3), b"three")
  let a = init.into_transport()
  let b = resp.into_transport()
  let ct = a.write_message(b"ping")
  assert_eq(b.read_message(ct), b"ping")
  let pong = a.write_message(b"pong")
  let before = b.receiving_nonce()
  let bad = try {
    let _ = b.read_message(flip_last(pong))
    true
  } catch {
    DecryptFail => false
    _ => true
  }
  assert_false(bad)
  assert_eq(b.receiving_nonce(), before)
  assert_eq(b.read_message(pong), b"pong")
  // Rewinding the nonce decrypts an old message again. The spec leaves
  // replay tracking to the application.
  b.set_receiving_nonce(0UL)
  assert_eq(b.read_message(ct), b"ping")
  b.set_receiving_nonce(2UL)
  a.rekey_send()
  b.rekey_recv()
  let rotated = a.write_message(b"after-rekey")
  let rejected = try {
    let _ = b.read_message(flip_last(rotated))
    true
  } catch {
    DecryptFail => false
    _ => true
  }
  assert_false(rejected)
  assert_eq(b.read_message(rotated), b"after-rekey")
}

///|
test "custom pattern string and psk round trip" {
  let nx = Pattern::parse("-> e\n<- e, ee, s, es")
  let init = Builder::from_pattern("Noise_NX_25519_ChaChaPoly_BLAKE2s", nx)
    .local_ephemeral_private(demo_key("nx-i"))
    .build_initiator(None)
  let resp = Builder::from_pattern("Noise_NX_25519_ChaChaPoly_BLAKE2s", nx)
    .local_private_key(demo_key("nx-s"))
    .local_ephemeral_private(demo_key("nx-r"))
    .build_responder(None)
  let m1 = init.write_message(b"nx")
  assert_eq(resp.read_message(m1), b"nx")
  let m2 = resp.write_message(b"back")
  assert_eq(init.read_message(m2), b"back")
  assert_true(init.is_finished())
  let left = init.into_transport()
  let right = resp.into_transport()
  assert_eq(right.read_message(left.write_message(b"go")), b"go")
  let psk_pattern = Pattern::parse("-> e\n<- e, ee, psk")
  let secret = demo_key("psk")
  let pi = Builder::from_pattern("Noise_NN_25519_AESGCM_BLAKE2s", psk_pattern)
    .psk(secret)
    .local_ephemeral_private(demo_key("psk-i"))
    .build_initiator(None)
  let pr = Builder::from_pattern("Noise_NN_25519_AESGCM_BLAKE2s", psk_pattern)
    .psk(secret)
    .local_ephemeral_private(demo_key("psk-r"))
    .build_responder(None)
  let p1 = pi.write_message(b"p")
  assert_eq(pr.read_message(p1), b"p")
  let p2 = pr.write_message(b"q")
  assert_eq(pi.read_message(p2), b"q")
  assert_eq(pi.handshake_hash(), pr.handshake_hash())
}

///|
test "message longer than 65535 is rejected" {
  let init = Builder::new("Noise_NN_25519_ChaChaPoly_SHA256")
    .local_ephemeral_private(demo_key("big-i"))
    .build_initiator(None)
  let huge = Bytes::make(65504, b'\x01')
  let rejected = try {
    let _ = init.write_message(huge)
    true
  } catch {
    MessageTooLong => false
    _ => true
  }
  assert_false(rejected)
}

///|
test "builder reports curve25519" {
  let builder = Builder::new("Noise_IK_25519_ChaChaPoly_SHA256")
  assert_eq(builder.dh_name(), "25519")
}
