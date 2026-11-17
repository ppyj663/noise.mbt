///|
test "cacophony vectors for supported suites" {
  let report = cacophony_report()
  assert_eq(report.vectors_loaded, 944)
  assert_eq(report.vectors_executed, 944)
  assert_eq(report.skipped, 0)
  assert_eq(report.messages_compared, 5664)
  assert_eq(
    report.vectors_executed.to_string() +
    "/" +
    report.vectors_loaded.to_string(),
    "944/944",
  )
}

///|
test "embedded vectors match the published checksum" {
  assert_eq(
    @lib.bytes_to_hex(@lib.sha256(@utf8.encode(cacophony_json()))),
    "e2f1ddfbf5297125bdd10558ba7701fbae5d5b2b423b65d022d013ad066aacd0",
  )
}
