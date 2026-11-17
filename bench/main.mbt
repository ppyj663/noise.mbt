///|
/// Fixed benchmark secrets. Not for production.
fn bench_key(label : Bytes) -> Bytes {
  @noise.sha256(label)
}

///|
let sink : Array[Int32] = [0]

///|
fn mix(buf : Bytes) -> Unit {
  if buf.length() > 0 {
    sink[0] = sink[0] ^ buf[0].to_int() ^ buf.length()
  }
}

///|
fn emit_point(
  name : String,
  kind : String,
  index : Int32,
  iters : Int32,
  elapsed_us : Double,
  per_iter_us : Double,
) -> Unit {
  println(
    "{\"name\":\"" +
    name +
    "\",\"kind\":\"" +
    kind +
    "\",\"index\":" +
    index.to_string() +
    ",\"iters\":" +
    iters.to_string() +
    ",\"elapsed_us\":" +
    elapsed_us.to_string() +
    ",\"per_iter_us\":" +
    per_iter_us.to_string() +
    "}",
  )
}

///|
fn emit_summary(
  name : String,
  unit : String,
  iters : Int32,
  warmup : Array[Double],
  samples : Array[Double],
) -> Unit {
  let sorted = samples.copy()
  sorted.sort()
  let median = sorted[sorted.length() / 2]
  let mut body = ""
  for i in 0..<samples.length() {
    if i > 0 {
      body = body + ","
    }
    body = body + samples[i].to_string()
  }
  let mut warm = ""
  for i in 0..<warmup.length() {
    if i > 0 {
      warm = warm + ","
    }
    warm = warm + warmup[i].to_string()
  }
  println(
    "{\"name\":\"" +
    name +
    "\",\"kind\":\"summary\",\"unit\":\"" +
    unit +
    "\",\"iters\":" +
    iters.to_string() +
    ",\"warmup_us\":[" +
    warm +
    "],\"samples_us\":[" +
    body +
    "],\"median_us\":" +
    median.to_string() +
    ",\"min_us\":" +
    sorted[0].to_string() +
    ",\"max_us\":" +
    sorted[sorted.length() - 1].to_string() +
    "}",
  )
}

///|
fn measure(
  name : String,
  unit : String,
  iters : Int32,
  body : () -> Unit raise @noise.NoiseError,
) -> Unit raise @noise.NoiseError {
  let warmup : Array[Double] = []
  for i in 0..<2 {
    let start = @clock.monotonic_clock_start()
    for _ in 0..<iters {
      body()
    }
    let elapsed = @clock.monotonic_clock_end(start)
    let per = elapsed / iters.to_double()
    warmup.push(per)
    emit_point(name, "warmup", i, iters, elapsed, per)
  }
  let samples : Array[Double] = []
  for i in 0..<9 {
    let start = @clock.monotonic_clock_start()
    for _ in 0..<iters {
      body()
    }
    let elapsed = @clock.monotonic_clock_end(start)
    let per = elapsed / iters.to_double()
    samples.push(per)
    emit_point(name, "sample", i, iters, elapsed, per)
  }
  emit_summary(name, unit, iters, warmup, samples)
}

///|
fn handshake_nn(
  protocol : String,
  payload : Bytes,
) -> Unit raise @noise.NoiseError {
  let init = @noise.Builder::new(protocol)
    .local_ephemeral_private(bench_key(b"bench-nn-i"))
    .build_initiator(None)
  let resp = @noise.Builder::new(protocol)
    .local_ephemeral_private(bench_key(b"bench-nn-r"))
    .build_responder(None)
  let m1 = init.write_message(payload)
  mix(m1)
  let _ = resp.read_message(m1)
  let m2 = resp.write_message(payload)
  mix(m2)
  let _ = init.read_message(m2)
  let _a = init.into_transport()
  let _b = resp.into_transport()
}

///|
fn handshake_xx(
  protocol : String,
  payload : Bytes,
) -> Unit raise @noise.NoiseError {
  let init = @noise.Builder::new(protocol)
    .local_private_key(bench_key(b"bench-i-s"))
    .local_ephemeral_private(bench_key(b"bench-i-e"))
    .build_initiator(None)
  let resp = @noise.Builder::new(protocol)
    .local_private_key(bench_key(b"bench-r-s"))
    .local_ephemeral_private(bench_key(b"bench-r-e"))
    .build_responder(None)
  let m1 = init.write_message(payload)
  mix(m1)
  let _ = resp.read_message(m1)
  let m2 = resp.write_message(payload)
  mix(m2)
  let _ = init.read_message(m2)
  let m3 = init.write_message(payload)
  mix(m3)
  let _ = resp.read_message(m3)
  let _a = init.into_transport()
  let _b = resp.into_transport()
}

///|
fn handshake_ik(
  protocol : String,
  payload : Bytes,
) -> Unit raise @noise.NoiseError {
  let init_s = bench_key(b"bench-ik-i")
  let resp_s = bench_key(b"bench-ik-r")
  let init = @noise.Builder::new(protocol)
    .local_private_key(init_s)
    .local_ephemeral_private(bench_key(b"bench-ik-ie"))
    .remote_public_key(@noise.public_key_25519(resp_s))
    .build_initiator(None)
  let resp = @noise.Builder::new(protocol)
    .local_private_key(resp_s)
    .local_ephemeral_private(bench_key(b"bench-ik-re"))
    .build_responder(None)
  let m1 = init.write_message(payload)
  mix(m1)
  let _ = resp.read_message(m1)
  let m2 = resp.write_message(payload)
  mix(m2)
  let _ = init.read_message(m2)
  let _a = init.into_transport()
  let _b = resp.into_transport()
}

///|
struct Pair {
  send : @noise.Transport
  recv : @noise.Transport
}

///|
fn xx_transport(protocol : String) -> Pair raise @noise.NoiseError {
  let init = @noise.Builder::new(protocol)
    .local_private_key(bench_key(b"bench-i-s"))
    .local_ephemeral_private(bench_key(b"bench-i-e"))
    .build_initiator(None)
  let resp = @noise.Builder::new(protocol)
    .local_private_key(bench_key(b"bench-r-s"))
    .local_ephemeral_private(bench_key(b"bench-r-e"))
    .build_responder(None)
  let m1 = init.write_message(b"")
  let _ = resp.read_message(m1)
  let m2 = resp.write_message(b"")
  let _ = init.read_message(m2)
  let m3 = init.write_message(b"")
  let _ = resp.read_message(m3)
  { send: init.into_transport(), recv: resp.into_transport(), }
}

///|
fn main raise {
  let empty = b""
  let n64 = Bytes::make(64, b'\x11')
  let n1024 = Bytes::make(1024, b'\x22')
  let n8192 = Bytes::make(8192, b'\x33')
  let chacha = "Noise_XX_25519_ChaChaPoly_SHA256"
  let aes = "Noise_XX_25519_AESGCM_SHA256"
  measure("handshake_nn_chacha", "us_per_handshake", 8, () => {
    handshake_nn("Noise_NN_25519_ChaChaPoly_SHA256", empty)
  })
  measure("handshake_nn_aes", "us_per_handshake", 8, () => {
    handshake_nn("Noise_NN_25519_AESGCM_SHA256", empty)
  })
  measure("handshake_xx_chacha", "us_per_handshake", 5, () => {
    handshake_xx(chacha, empty)
  })
  measure("handshake_xx_aes", "us_per_handshake", 5, () => {
    handshake_xx(aes, empty)
  })
  measure("handshake_ik_chacha", "us_per_handshake", 5, () => {
    handshake_ik("Noise_IK_25519_ChaChaPoly_SHA256", empty)
  })
  measure("handshake_ik_aes", "us_per_handshake", 5, () => {
    handshake_ik("Noise_IK_25519_AESGCM_SHA256", empty)
  })
  let cc = xx_transport(chacha)
  let ag = xx_transport(aes)
  measure("transport_chacha_encrypt_64", "us_per_message", 40, () => {
    mix(cc.send.write_message(n64))
  })
  measure("transport_chacha_encrypt_1024", "us_per_message", 15, () => {
    mix(cc.send.write_message(n1024))
  })
  measure("transport_chacha_encrypt_8192", "us_per_message", 8, () => {
    mix(cc.send.write_message(n8192))
  })
  let nonce64 = cc.send.sending_nonce()
  let ct64 = cc.send.write_message(n64)
  let nonce1024 = cc.send.sending_nonce()
  let ct1024 = cc.send.write_message(n1024)
  let nonce8192 = cc.send.sending_nonce()
  let ct8192 = cc.send.write_message(n8192)
  measure("transport_chacha_decrypt_64", "us_per_message", 40, () => {
    cc.recv.set_receiving_nonce(nonce64)
    mix(cc.recv.read_message(ct64))
  })
  measure("transport_chacha_decrypt_1024", "us_per_message", 15, () => {
    cc.recv.set_receiving_nonce(nonce1024)
    mix(cc.recv.read_message(ct1024))
  })
  measure("transport_chacha_decrypt_8192", "us_per_message", 8, () => {
    cc.recv.set_receiving_nonce(nonce8192)
    mix(cc.recv.read_message(ct8192))
  })
  measure("transport_aes_encrypt_64", "us_per_message", 40, () => {
    mix(ag.send.write_message(n64))
  })
  measure("transport_aes_encrypt_1024", "us_per_message", 15, () => {
    mix(ag.send.write_message(n1024))
  })
  measure("transport_aes_encrypt_8192", "us_per_message", 8, () => {
    mix(ag.send.write_message(n8192))
  })
  let an64 = ag.send.sending_nonce()
  let act64 = ag.send.write_message(n64)
  let an1024 = ag.send.sending_nonce()
  let act1024 = ag.send.write_message(n1024)
  let an8192 = ag.send.sending_nonce()
  let act8192 = ag.send.write_message(n8192)
  measure("transport_aes_decrypt_64", "us_per_message", 40, () => {
    ag.recv.set_receiving_nonce(an64)
    mix(ag.recv.read_message(act64))
  })
  measure("transport_aes_decrypt_1024", "us_per_message", 15, () => {
    ag.recv.set_receiving_nonce(an1024)
    mix(ag.recv.read_message(act1024))
  })
  measure("transport_aes_decrypt_8192", "us_per_message", 8, () => {
    ag.recv.set_receiving_nonce(an8192)
    mix(ag.recv.read_message(act8192))
  })
  measure("rekey_chacha_send", "us_per_rekey", 40, () => cc.send.rekey_send())
  println("{\"kind\":\"sink\",\"value\":" + sink[0].to_string() + "}")
}
