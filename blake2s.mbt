///|
/// BLAKE2s-256 (RFC 7693).
///
/// mooncry 0.95.0's `blake2s` treats a non-empty multiple of the 64-byte block
/// as a non-final block and then hashes an extra empty final block. Noise
/// mixes several 64-byte strings, so this implementation is used instead.
let blake2s_iv : Array[UInt32] = [
  0x6A09E667U, 0xBB67AE85U, 0x3C6EF372U, 0xA54FF53AU, 0x510E527FU, 0x9B05688CU, 0x1F83D9ABU,
  0x5BE0CD19U,
]

///|
let blake2s_sigma : Array[Array[Int32]] = [
  [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
  [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
  [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
  [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
  [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
  [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
  [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
  [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
  [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
  [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
]

///|
fn blake2s_rotr(x : UInt32, n : Int32) -> UInt32 {
  (x >> n) | (x << (32 - n))
}

///|
fn blake2s_g(
  v : Array[UInt32],
  a : Int32,
  b : Int32,
  c : Int32,
  d : Int32,
  x : UInt32,
  y : UInt32,
) -> Unit {
  v[a] = v[a] + v[b] + x
  v[d] = blake2s_rotr(v[d] ^ v[a], 16)
  v[c] = v[c] + v[d]
  v[b] = blake2s_rotr(v[b] ^ v[c], 12)
  v[a] = v[a] + v[b] + y
  v[d] = blake2s_rotr(v[d] ^ v[a], 8)
  v[c] = v[c] + v[d]
  v[b] = blake2s_rotr(v[b] ^ v[c], 7)
}

///|
fn blake2s_compress(
  h : Array[UInt32],
  block : Array[UInt32],
  t : UInt64,
  last : Bool,
) -> Unit {
  let v = Array::make(16, 0U)
  for i in 0..<=7 {
    v[i] = h[i]
    v[i + 8] = blake2s_iv[i]
  }
  v[12] = v[12] ^ (t & 0xFFFFFFFFUL).to_uint()
  v[13] = v[13] ^ ((t >> 32) & 0xFFFFFFFFUL).to_uint()
  if last {
    v[14] = v[14] ^ 0xFFFFFFFFU
  }
  for r in 0..<=9 {
    let s = blake2s_sigma[r]
    blake2s_g(v, 0, 4, 8, 12, block[s[0]], block[s[1]])
    blake2s_g(v, 1, 5, 9, 13, block[s[2]], block[s[3]])
    blake2s_g(v, 2, 6, 10, 14, block[s[4]], block[s[5]])
    blake2s_g(v, 3, 7, 11, 15, block[s[6]], block[s[7]])
    blake2s_g(v, 0, 5, 10, 15, block[s[8]], block[s[9]])
    blake2s_g(v, 1, 6, 11, 12, block[s[10]], block[s[11]])
    blake2s_g(v, 2, 7, 8, 13, block[s[12]], block[s[13]])
    blake2s_g(v, 3, 4, 9, 14, block[s[14]], block[s[15]])
  }
  for i in 0..<=7 {
    h[i] = h[i] ^ v[i] ^ v[i + 8]
  }
}

///|
fn blake2s_read_word(data : Bytes, offset : Int32) -> UInt32 {
  data[offset].to_uint() |
  (data[offset + 1].to_uint() << 8) |
  (data[offset + 2].to_uint() << 16) |
  (data[offset + 3].to_uint() << 24)
}

///|
fn blake2s_block(data : Bytes, offset : Int32) -> Array[UInt32] {
  let block = Array::make(16, 0U)
  for i in 0..<=15 {
    let at = offset + i * 4
    if at + 3 < data.length() {
      block[i] = blake2s_read_word(data, at)
    } else if at < data.length() {
      let mut word = 0U
      let mut shift = 0
      let mut j = 0
      while at + j < data.length() && j < 4 {
        word = word | (data[at + j].to_uint() << shift)
        shift = shift + 8
        j = j + 1
      }
      block[i] = word
    }
  }
  block
}

///|
/// BLAKE2s-256 digest.
pub fn blake2s_256(data : Bytes) -> Bytes {
  let h = Array::make(8, 0U)
  for i in 0..<=7 {
    h[i] = blake2s_iv[i]
  }
  h[0] = h[0] ^ (0x01010000U + 32U)
  let len = data.length()
  if len == 0 {
    blake2s_compress(h, Array::make(16, 0U), 0UL, true)
  } else {
    let mut offset = 0
    while offset + 64 < len {
      let block = blake2s_block(data, offset)
      blake2s_compress(h, block, (offset + 64).to_uint64(), false)
      offset = offset + 64
    }
    let block = blake2s_block(data, offset)
    blake2s_compress(h, block, len.to_uint64(), true)
  }
  let out = Array::make(32, b'\x00')
  for i in 0..<=7 {
    let w = h[i]
    for j in 0..<4 {
      let idx = i * 4 + j
      out[idx] = ((w >> (j * 8)) & 0xFFU).to_byte()
    }
  }
  Bytes::from_array(out[:])
}
