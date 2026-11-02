///|
fn expect_err(
  f : () -> Unit raise NoiseError,
  kind : String,
) -> Unit raise Error {
  try {
    f()
    fail("expected " + kind)
  } catch {
    DecryptFail => assert_eq(kind, "decrypt")
    NonceExhausted => assert_eq(kind, "nonce")
    _ => fail("unexpected error, wanted " + kind)
  }
}

///|
test "cipherstate empty key is a copy" {
  let cs = CipherState::new(ChaChaPoly)
  let pt = b"plain"
  assert_eq(cs.encrypt_with_ad(b"ad", pt), pt)
  assert_eq(cs.get_nonce(), 0UL)
  assert_eq(cs.decrypt_with_ad(b"ad", pt), pt)
  cs.rekey()
  assert_false(cs.has_key())
}

///|
test "cipherstate round trip and tamper" {
  let send = CipherState::new(ChaChaPoly)
  let recv = CipherState::new(ChaChaPoly)
  let key = zeros(32)
  send.initialize_key(Some(key))
  recv.initialize_key(Some(key))
  let ad = b"assoc"
  let ct = send.encrypt_with_ad(ad, b"hello")
  assert_eq(ct.length(), 21)
  assert_eq(recv.decrypt_with_ad(ad, ct), b"hello")
  assert_eq(send.get_nonce(), 1UL)
  let bad = bytes_slice(ct, 0, ct.length())
  // flip the last tag byte
  let flipped = flip_last(ct)
  let before = recv.get_nonce()
  expect_err(
    () => {
      let _ = recv.decrypt_with_ad(ad, flipped)
      ()
    },
    "decrypt",
  )
  assert_eq(recv.get_nonce(), before)
  let _ = bad
}

///|
fn flip_last(data : Bytes) -> Bytes {
  let n = data.length()
  let out = Array::make(n, b'\x00')
  for i in 0..<n {
    out[i] = data[i]
  }
  let last = out[n - 1].to_int()
  out[n - 1] = (last ^ 1).to_byte()
  Bytes::from_array(out[:])
}

///|
test "cipherstate rekey matches known vectors and keeps nonce" {
  let cs = CipherState::new(ChaChaPoly)
  cs.initialize_key(Some(zeros(32)))
  let _ = cs.encrypt_with_ad(b"", b"m")
  assert_eq(cs.get_nonce(), 1UL)
  cs.rekey()
  assert_eq(cs.get_nonce(), 1UL)
  // REKEY(0x00..00) for ChaChaPoly, nonce 2^64-1, 32 zero bytes.
  let again = CipherState::new(ChaChaPoly)
  again.initialize_key(Some(zeros(32)))
  again.rekey()
  let probe = again.encrypt_with_ad(b"", b"")
  let expect = CipherState::new(ChaChaPoly)
  expect.initialize_key(
    Some(
      @lib.hex_to_bytes(
        "25ce5d37df19f3783185f2ffd5ab17fa3397c212f02d62fb1733e0b875b74c58",
      ),
    ),
  )
  assert_eq(probe, expect.encrypt_with_ad(b"", b""))
  let aes = CipherState::new(AesGcm)
  aes.initialize_key(Some(zeros(32)))
  aes.rekey()
  let aes_ct = aes.encrypt_with_ad(b"", b"")
  let aes_expect = CipherState::new(AesGcm)
  aes_expect.initialize_key(
    Some(
      @lib.hex_to_bytes(
        "f1573ed7ea59562387a25c24fabe25a3155fecd880e181089fe581c148cc6ba9",
      ),
    ),
  )
  assert_eq(aes_ct, aes_expect.encrypt_with_ad(b"", b""))
}

///|
test "cipherstate nonce exhaustion" {
  let cs = CipherState::new(AesGcm)
  cs.initialize_key(Some(zeros(32)))
  cs.set_nonce(18446744073709551614UL)
  let ct = cs.encrypt_with_ad(b"", b"last")
  assert_eq(cs.get_nonce(), 18446744073709551615UL)
  expect_err(
    () => {
      let _ = cs.encrypt_with_ad(b"", b"nope")
      ()
    },
    "nonce",
  )
  let recv = CipherState::new(AesGcm)
  recv.initialize_key(Some(zeros(32)))
  recv.set_nonce(18446744073709551614UL)
  assert_eq(recv.decrypt_with_ad(b"", ct), b"last")
  expect_err(
    () => {
      let _ = recv.decrypt_with_ad(b"", ct)
      ()
    },
    "nonce",
  )
}

///|
test "cipherstate lengths round trip" {
  let key = @lib.sha256(b"k")
  for kind in [ChaChaPoly, AesGcm] {
    let a = CipherState::new(kind)
    let b = CipherState::new(kind)
    a.initialize_key(Some(key))
    b.initialize_key(Some(key))
    let lengths = [0, 1, 15, 16, 31, 64]
    for n in lengths {
      let pt = Bytes::make(n, b'\x61')
      let ct = a.encrypt_with_ad(b"ad", pt)
      assert_eq(ct.length(), n + 16)
      assert_eq(b.decrypt_with_ad(b"ad", ct), pt)
    }
  }
}
