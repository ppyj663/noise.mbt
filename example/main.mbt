///|
/// Derive a 32-byte demo secret. This is not a CSPRNG.
fn material(label : String) -> Bytes {
  @noise.sha256(@utf8.encode(label))
}

///|
/// Two parties run Noise_XX_25519_ChaChaPoly_SHA256 and exchange messages.
///
/// Static and ephemeral keys are deterministic so `moon run example` prints
/// the same transcript every time. Pass a random function to
/// `build_initiator` / `build_responder` when the keys must be fresh.
fn main raise {
  let prologue = @utf8.encode("noise.mbt example")
  let initiator = @noise.Builder::new("Noise_XX_25519_ChaChaPoly_SHA256")
    .prologue(prologue)
    .local_private_key(material("example-init-static"))
    .local_ephemeral_private(material("example-init-ephemeral"))
    .build_initiator(None)
  let responder = @noise.Builder::new("Noise_XX_25519_ChaChaPoly_SHA256")
    .prologue(prologue)
    .local_private_key(material("example-resp-static"))
    .local_ephemeral_private(material("example-resp-ephemeral"))
    .build_responder(None)
  let m1 = initiator.write_message(@utf8.encode("你好，我是发起方"))
  let p1 = responder.read_message(m1)
  let m2 = responder.write_message(@utf8.encode("你好，我是响应方"))
  let p2 = initiator.read_message(m2)
  let m3 = initiator.write_message(@utf8.encode("握手第三步"))
  let p3 = responder.read_message(m3)
  let send = initiator.into_transport()
  let recv = responder.into_transport()
  let t1 = send.write_message(@utf8.encode("传输消息：ping"))
  let r1 = recv.read_message(t1)
  let t2 = recv.write_message(@utf8.encode("传输消息：pong"))
  let r2 = send.read_message(t2)
  send.rekey_send()
  recv.rekey_recv()
  let t3 = send.write_message(@utf8.encode("rekey 之后"))
  let r3 = recv.read_message(t3)
  println("Noise_XX_25519_ChaChaPoly_SHA256")
  println("responder read: " + @utf8.decode(p1))
  println("initiator read: " + @utf8.decode(p2))
  println("responder read: " + @utf8.decode(p3))
  println("transport: " + @utf8.decode(r1))
  println("transport: " + @utf8.decode(r2))
  println("transport: " + @utf8.decode(r3))
  println("handshake hash: " + @noise.to_hex(send.handshake_hash()))
}
