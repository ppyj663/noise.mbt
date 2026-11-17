///|
pub suberror FrameError {
  TooLong
  BadPayload
}

///|
/// 16-bit big-endian length prefix, as Noise section 13 recommends when an
/// application needs a frame length. The length is the Noise message size and
/// must be <= 65535. This is not part of the Noise message itself.
pub fn encode_noise_frame(message : Bytes) -> Bytes raise FrameError {
  if message.length() > 65535 {
    raise TooLong
  }
  let buf = @buffer.Buffer()
  let n = message.length()
  buf.write_byte((n / 256).to_byte())
  buf.write_byte((n % 256).to_byte())
  buf.write_bytes(message)
  buf.to_bytes()
}

///|
pub async fn write_noise_frame(conn : @socket.Tcp, message : Bytes) -> Unit {
  conn.write(encode_noise_frame(message))
}

///|
pub async fn read_noise_frame(conn : @socket.Tcp) -> Bytes {
  let header = conn.read_exactly(2)
  let n = header[0].to_int() * 256 + header[1].to_int()
  if n > 65535 {
    raise TooLong
  }
  conn.read_exactly(n)
}
