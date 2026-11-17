///|
fn dh_expect(kind : String, body : () -> Unit raise NoiseError) -> Unit raise {
  let ok = try {
    body()
    true
  } catch {
    InvalidInput(_) => kind != "input"
    _ => true
  }
  assert_false(ok)
}

///|
test "invalid dh lengths are rejected before the ladder" {
  dh_expect("input", () => {
    let _ = dh_25519(Bytes::make(31, b'\x01'), Bytes::make(32, b'\x02'))
  })
  dh_expect("input", () => {
    let _ = dh_25519(Bytes::make(32, b'\x01'), Bytes::make(33, b'\x02'))
  })
  dh_expect("input", () => {
    let _ = dh_x448(Bytes::make(55, b'\x01'), Bytes::make(56, b'\x02'))
  })
  dh_expect("input", () => {
    let _ = dh_x448(Bytes::make(56, b'\x01'), Bytes::make(57, b'\x02'))
  })
}

///|
test "x25519 low-order public keys return all zeros by default" {
  // Little-endian small-order u coordinates. Noise rev 34 section 12.1 says
  // invalid public keys produce an all-zero output. RFC 7748 section 6.1 is
  // only the curve operation underneath that rule.
  let scalar = bhex_dh(
    "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
  )
  let points = [
    "0000000000000000000000000000000000000000000000000000000000000000", "0100000000000000000000000000000000000000000000000000000000000000",
    "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800", "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157",
    "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
  ]
  for point in points {
    let shared = dh_25519(scalar, bhex_dh(point))
    assert_true(dh_output_is_all_zero(shared))
    assert_eq(shared.length(), 32)
  }
}

///|
test "x448 all-zero public key returns 56 zero bytes" {
  let scalar = Bytes::make(56, b'\x11')
  let shared = dh_x448(scalar, Bytes::make(56, b'\x00'))
  assert_eq(shared, Bytes::make(56, b'\x00'))
}

///|
test "default policy completes a known-zero dh and does not authenticate" {
  // NK mixes es = DH(initiator ephemeral, responder static). The remote
  // static here is the all-zero public key, so the DH output is all zeros.
  // write_message returning is not evidence that anyone knows a private key.
  let init = Builder::new("Noise_NK_25519_ChaChaPoly_SHA256")
    .remote_public_key(Bytes::make(32, b'\x00'))
    .local_ephemeral_private(@lib.sha256(b"dh-policy-e"))
    .build_initiator(None)
  let message = init.write_message(b"not-authenticated")
  assert_true(message.length() > 32)
}

///|
test "optional all-zero rejection is not an identity check" {
  let init = Builder::new("Noise_NK_25519_ChaChaPoly_SHA256")
    .reject_all_zero_dh()
    .remote_public_key(Bytes::make(32, b'\x00'))
    .local_ephemeral_private(@lib.sha256(b"dh-policy-e"))
    .build_initiator(None)
  dh_expect("input", () => {
    let _ = init.write_message(b"stop")
  })
  let x448 = Builder::new("Noise_NK_448_ChaChaPoly_SHA512")
    .reject_all_zero_dh()
    .remote_public_key(Bytes::make(56, b'\x00'))
    .local_ephemeral_private(Bytes::make(56, b'\x22'))
    .build_initiator(None)
  dh_expect("input", () => {
    let _ = x448.write_message(b"stop")
  })
}

///|
fn bhex_dh(s : String) -> Bytes {
  @lib.hex_to_bytes(s)
}
