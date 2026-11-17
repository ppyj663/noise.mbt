///|
async test "tcp loopback completes xx handshake and transport" {
  assert_eq(
    run_tcp_loopback(),
    "tcp 127.0.0.1 xx | bob:你好，我是响应方 | pong:传输：pong",
  )
}

///|
async test "tcp short frame does not yield plaintext" {
  assert_eq(run_tcp_short_frame(), "short-frame")
}

///|
test "frame length refuses a message above 65535" {
  let rejected = try {
    let _ = encode_noise_frame(Bytes::make(65536, b'\x01'))
    true
  } catch {
    TooLong => false
    _ => true
  }
  assert_false(rejected)
  let frame = encode_noise_frame(Bytes::make(65535, b'\x02'))
  assert_eq(frame.length(), 65537)
  assert_eq(frame[0], b'\xFF')
  assert_eq(frame[1], b'\xFF')
}
