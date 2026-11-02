///|
fn hex(s : String) -> Bytes {
  @lib.hex_to_bytes(s)
}

///|
fn expect_hex(got : Bytes, want : String) -> Unit raise Error {
  assert_eq(@lib.bytes_to_hex(got), want)
}

///|
test "sha256 empty and abc" {
  expect_hex(
    Sha256.digest(b""),
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  )
  expect_hex(
    Sha256.digest(b"abc"),
    "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
  )
}

///|
test "blake2s rfc 7693" {
  expect_hex(
    Blake2s.digest(b""),
    "69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9",
  )
  expect_hex(
    Blake2s.digest(b"abc"),
    "508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982",
  )
}

///|
test "hmac sha256 rfc 4231 case 1" {
  let key = hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
  expect_hex(
    Sha256.hmac(key, b"Hi There"),
    "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
  )
}

///|
test "hmac blake2s" {
  expect_hex(
    Blake2s.hmac(b"key", b"The quick brown fox jumps over the lazy dog"),
    "f93215bb90d4af4c3061cd932fb169fb8bb8a91d0b4022baea1271e1323cd9a0",
  )
}

///|
test "x25519 rfc 7748 6.1" {
  let alice = hex(
    "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
  )
  let bob = hex(
    "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb",
  )
  expect_hex(
    public_key_25519(alice),
    "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a",
  )
  expect_hex(
    public_key_25519(bob),
    "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f",
  )
  let shared = dh_25519(alice, public_key_25519(bob))
  expect_hex(
    shared, "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742",
  )
  assert_eq(shared, dh_25519(bob, public_key_25519(alice)))
}

///|
test "chacha20-poly1305 rfc 8439 section 2.8.2" {
  let key = hex(
    "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
  )
  let nonce = hex("070000004041424344454647")
  let ad = hex("50515253c0c1c2c3c4c5c6c7")
  let pt = hex(
    "4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e",
  )
  let ct = @lib.chacha20_poly1305_encrypt(key, nonce, ad, pt)
  expect_hex(
    ct, "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b61161ae10b594f09e26a7e902ecbd0600691",
  )
}

///|
test "aesgcm nist empty plaintext" {
  let key = zeros(32)
  let nonce = zeros(12)
  let boxed = @lib.aes_gcm_encrypt(b"", key, nonce, b"")
  expect_hex(boxed.tag, "530f8afbc74536b9a963b4f1c4cb738b")
  assert_eq(boxed.ct.length(), 0)
}
