///|
/// Test-only secret. Not a CSPRNG and not for production.
fn pipe_key(label : String) -> Bytes {
  @noise.sha256(@utf8.encode(label))
}

///|
/// In-memory byte pipe. Each party only sees the bytes the other wrote.
/// There is no TCP socket in the pinned dependencies, so this is the
/// complete session example.
pub fn run_memory_session() -> String raise Error {
  let prologue = @utf8.encode("memory-pipe")
  let alice = @noise.Builder::new("Noise_XX_25519_ChaChaPoly_SHA256")
    .prologue(prologue)
    .local_private_key(pipe_key("pipe-alice-static"))
    .local_ephemeral_private(pipe_key("pipe-alice-e"))
    .build_initiator(None)
  let bob = @noise.Builder::new("Noise_XX_25519_ChaChaPoly_SHA256")
    .prologue(prologue)
    .local_private_key(pipe_key("pipe-bob-static"))
    .local_ephemeral_private(pipe_key("pipe-bob-e"))
    .build_responder(None)
  let m1 = alice.write_message(@utf8.encode("hello from alice"))
  let p1 = bob.read_message(m1)
  let m2 = bob.write_message(@utf8.encode("hello from bob"))
  let p2 = alice.read_message(m2)
  let m3 = alice.write_message(@utf8.encode("xx done"))
  let p3 = bob.read_message(m3)
  let a_tx = alice.into_transport()
  let b_tx = bob.into_transport()
  let t1 = a_tx.write_message(@utf8.encode("transport a"))
  let r1 = b_tx.read_message(t1)
  let t2 = b_tx.write_message(@utf8.encode("transport b"))
  let r2 = a_tx.read_message(t2)
  // Fallback: Alice's ephemeral is already known. Bob sends the next message.
  let alice_e = pipe_key("fallback-alice-e")
  let alice_e_pub = @noise.public_key_25519(alice_e)
  let fall_a = @noise.Builder::new("Noise_XXfallback_25519_ChaChaPoly_SHA256")
    .prologue(prologue)
    .local_private_key(pipe_key("fallback-alice-static"))
    .local_ephemeral_private(alice_e)
    .build_initiator(None)
  let fall_b = @noise.Builder::new("Noise_XXfallback_25519_ChaChaPoly_SHA256")
    .prologue(prologue)
    .local_private_key(pipe_key("fallback-bob-static"))
    .local_ephemeral_private(pipe_key("fallback-bob-e"))
    .remote_ephemeral_public(alice_e_pub)
    .build_responder(None)
  let f1 = fall_b.write_message(@utf8.encode("bob starts fallback"))
  let q1 = fall_a.read_message(f1)
  let f2 = fall_a.write_message(@utf8.encode("alice replies"))
  let q2 = fall_b.read_message(f2)
  let fa = fall_a.into_transport()
  let fb = fall_b.into_transport()
  let f3 = fb.write_message(@utf8.encode("fallback transport"))
  let q3 = fa.read_message(f3)
  "xx " +
  @utf8.decode(p1) +
  " | " +
  @utf8.decode(p2) +
  " | " +
  @utf8.decode(p3) +
  " | " +
  @utf8.decode(r1) +
  " | " +
  @utf8.decode(r2) +
  " || fallback " +
  @utf8.decode(q1) +
  " | " +
  @utf8.decode(q2) +
  " | " +
  @utf8.decode(q3)
}
