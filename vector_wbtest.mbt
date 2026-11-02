///|
test "cacophony vectors for supported suites" {
  assert_eq(verify_cacophony_vectors(), "NN 4/4, NK 4/4, XX 4/4, IK 4/4")
}

///|
test "embedded vectors match the published checksum" {
  assert_eq(
    @lib.bytes_to_hex(@lib.sha256(@utf8.encode(cacophony_json()))),
    "abf46916f6dd7fb38e1d7476cb5c42c1f91afcdd3c3132f84542f8c1cb8de7f9",
  )
}
