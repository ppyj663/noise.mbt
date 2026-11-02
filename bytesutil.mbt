///|
fn concat2(a : Bytes, b : Bytes) -> Bytes {
  let buf = @buffer.Buffer()
  buf.write_bytes(a)
  buf.write_bytes(b)
  buf.to_bytes()
}

///|
fn bytes_slice(data : Bytes, start : Int32, len : Int32) -> Bytes {
  let out = Array::make(len, b'\x00')
  for i in 0..<len {
    out[i] = data[start + i]
  }
  Bytes::from_array(out[:])
}

///|
fn take_bytes(
  data : Bytes,
  start : Int32,
  len : Int32,
) -> Bytes raise NoiseError {
  if start < 0 || len < 0 || start + len > data.length() {
    raise TruncatedMessage
  }
  bytes_slice(data, start, len)
}

///|
fn xor_bytes(a : Bytes, b : Bytes) -> Bytes {
  let len = a.length()
  let result = Array::make(len, b'\x00')
  for i in 0..<len {
    result[i] = (a[i].to_int() ^ b[i].to_int()).to_byte()
  }
  Bytes::from_array(result[:])
}

///|
fn pad_right(data : Bytes, n : Int32) -> Bytes {
  let out = Array::make(n, b'\x00')
  let limit = if data.length() < n { data.length() } else { n }
  for i in 0..<limit {
    out[i] = data[i]
  }
  Bytes::from_array(out[:])
}

///|
fn repeat_byte(byte : Byte, count : Int32) -> Bytes {
  Bytes::make(count, byte)
}

///|
fn one_byte(byte : Byte) -> Bytes {
  let arr = [byte]
  Bytes::from_array(arr[:])
}

///|
fn zeros(n : Int32) -> Bytes {
  Bytes::make(n, b'\x00')
}
