///|
/// BLAKE2b-512 (RFC 7693).
///
/// mooncry 0.95.0's `blake2b` has the same extra-empty-block bug as its
/// `blake2s` when the input length is a positive multiple of the block size.
/// Noise `Split` hashes an exact block through HMAC, so this implementation
/// is used instead.
let blake2b_iv : Array[UInt64] = [
  0x6a09e667f3bcc908UL, 0xbb67ae8584caa73bUL, 0x3c6ef372fe94f82bUL, 0xa54ff53a5f1d36f1UL,
  0x510e527fade682d1UL, 0x9b05688c2b3e6c1fUL, 0x1f83d9abfb41bd6bUL, 0x5be0cd19137e2179UL,
]

///|
let blake2b_sigma : Array[Array[Int32]] = [
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
  [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
  [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
]

///|
fn rotr64(x : UInt64, n : Int32) -> UInt64 {
  (x >> n) | (x << (64 - n))
}

///|
fn blake2b_g(
  v : Array[UInt64],
  a : Int32,
  b : Int32,
  c : Int32,
  d : Int32,
  x : UInt64,
  y : UInt64,
) -> Unit {
  v[a] = v[a] + v[b] + x
  v[d] = rotr64(v[d] ^ v[a], 32)
  v[c] = v[c] + v[d]
  v[b] = rotr64(v[b] ^ v[c], 24)
  v[a] = v[a] + v[b] + y
  v[d] = rotr64(v[d] ^ v[a], 16)
  v[c] = v[c] + v[d]
  v[b] = rotr64(v[b] ^ v[c], 63)
}

///|
fn blake2b_compress(
  h : Array[UInt64],
  block : Array[UInt64],
  t : UInt64,
  last : Bool,
) -> Unit {
  let v = Array::make(16, 0UL)
  for i in 0..<=7 {
    v[i] = h[i]
    v[i + 8] = blake2b_iv[i]
  }
  v[12] = v[12] ^ t
  if last {
    v[14] = v[14] ^ 0xFFFFFFFFFFFFFFFFUL
  }
  for r in 0..<=11 {
    let s = blake2b_sigma[r]
    blake2b_g(v, 0, 4, 8, 12, block[s[0]], block[s[1]])
    blake2b_g(v, 1, 5, 9, 13, block[s[2]], block[s[3]])
    blake2b_g(v, 2, 6, 10, 14, block[s[4]], block[s[5]])
    blake2b_g(v, 3, 7, 11, 15, block[s[6]], block[s[7]])
    blake2b_g(v, 0, 5, 10, 15, block[s[8]], block[s[9]])
    blake2b_g(v, 1, 6, 11, 12, block[s[10]], block[s[11]])
    blake2b_g(v, 2, 7, 8, 13, block[s[12]], block[s[13]])
    blake2b_g(v, 3, 4, 9, 14, block[s[14]], block[s[15]])
  }
  for i in 0..<=7 {
    h[i] = h[i] ^ v[i] ^ v[i + 8]
  }
}

///|
fn blake2b_lane(data : Bytes, offset : Int32) -> UInt64 {
  let mut word = 0UL
  let mut shift = 0
  for j in 0..<8 {
    if offset + j < data.length() {
      word = word | (data[offset + j].to_uint64() << shift)
    }
    shift = shift + 8
  }
  word
}

///|
fn blake2b_block(data : Bytes, offset : Int32) -> Array[UInt64] {
  let block = Array::make(16, 0UL)
  for i in 0..<=15 {
    block[i] = blake2b_lane(data, offset + i * 8)
  }
  block
}

///|
/// BLAKE2b-512 digest.
pub fn blake2b_512(data : Bytes) -> Bytes {
  let h = Array::make(8, 0UL)
  for i in 0..<=7 {
    h[i] = blake2b_iv[i]
  }
  h[0] = h[0] ^ (0x01010000UL + 64UL)
  let len = data.length()
  if len == 0 {
    blake2b_compress(h, Array::make(16, 0UL), 0UL, true)
  } else {
    let mut offset = 0
    while offset + 128 < len {
      blake2b_compress(
        h,
        blake2b_block(data, offset),
        (offset + 128).to_uint64(),
        false,
      )
      offset = offset + 128
    }
    blake2b_compress(h, blake2b_block(data, offset), len.to_uint64(), true)
  }
  let out = Array::make(64, b'\x00')
  for i in 0..<=7 {
    let w = h[i]
    for j in 0..<8 {
      out[i * 8 + j] = ((w >> (j * 8)) & 0xFFUL).to_byte()
    }
  }
  Bytes::from_array(out[:])
}
