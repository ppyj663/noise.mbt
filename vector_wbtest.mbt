///|
test "cacophony vectors for supported suites" {
  assert_eq(verify_cacophony_vectors(), "944/944")
}

///|
test "embedded vectors match the published checksum" {
  assert_eq(
    @lib.bytes_to_hex(@lib.sha256(@utf8.encode(cacophony_json()))),
    "e2f1ddfbf5297125bdd10558ba7701fbae5d5b2b423b65d022d013ad066aacd0",
  )
}
