///|
/// Differential vectors for `XXfallback` produced by an independent Python
/// oracle (cryptography 41.x ChaCha20Poly1305 / AESGCM and X25519, hashlib
/// SHA-256). Keys and prologue match the Cacophony XX fixture. They are not
/// production keys.
fn fb_hex(s : String) -> Bytes {
  @lib.hex_to_bytes(s)
}

///|
struct FallbackOracle {
  protocol : String
  m1 : String
  m2 : String
  m3 : String
  m4 : String
  handshake_hash : String
}

///|
fn fallback_oracles() -> Array[FallbackOracle] {
  [
    {
      protocol: "Noise_XXfallback_25519_ChaChaPoly_SHA256",
      handshake_hash: "66706e005cb4f97b0574938e8d6ff4ac361e16bed0fa9222c62dfa414955e104",
      m1: "95ebc60d2b1fa672c1f46a8aa265ef51bfe38e7ccb39ec5be34069f144808843c95caa5acaf9a7cf34254947f0d8da9233b3a4a57993c4d824696e4b1cef496cfc415150bc303711ab22d63e0b682d48084b2a393fd6abd60235cc1b608d2df6c6f61259ab04d5a6317cd5649565b0",
      m2: "1ec24f2fa67db6f7335bb7e2848571f4be76ae6702fd2123465e59e6f92f020a55cbea5db2a784c2e95955db3a2f8ca75bf745ec726d4ff246b6d412ac7cc8d24df1fe17d71c768fbb09d4",
      m3: "2298f891ef5a025762c194a758050b154dd6c9981e70a5ff143dd0",
      m4: "acbba3c811c00a4fc7f71cddfe5e401d53ab7d529b09fa9b13b7c457eb5b866041",
    },
    {
      protocol: "Noise_XXfallback_25519_AESGCM_SHA256",
      handshake_hash: "c496f058c365d5caf7e902a85a0645132c6bdee71d92b18dd1ca5e49d7c4bcb1",
      m1: "95ebc60d2b1fa672c1f46a8aa265ef51bfe38e7ccb39ec5be34069f144808843824e059afdb8c2f7397b7b398d84a6cde4178068ad7976bd04793a16ce9d308ca91c7f9663d71e706f1696026fa2146d2c279ebeeab1283fe1543fce646f4b55dd79db767250ef0a42fd3a3258c985",
      m2: "8c2db1c7f7485b1c5dcc2275c19665b2aed8f0fd9dcb02944ffbbd4ea4f4553f303e4708d46f1d421eb0fd5919d276be616c6fbc51d425b1c8f4e110807ac2211009bf9e20c51530685c26",
      m3: "58e4ca05319f8011433395e96952f79bc8f048facbae9ad5023d0f",
      m4: "d3207f11a4fee2cbb28e9920cac46b671825c27012972d50778090b5d090593bd4",
    },
  ]
}

///|
fn run_fallback_oracle(oracle : FallbackOracle) -> Unit raise Error {
  let prologue = fb_hex("4a6f686e2047616c74")
  let init_e = fb_hex(
    "893e28b9dc6ca8d611ab664754b8ceb7bac5117349a4439a6b0569da977c464a",
  )
  let resp_e = fb_hex(
    "bbdb4cdbd309f1a1f2e1456967fe288cadd6f712d65dc7b7793d5e63da6b375b",
  )
  let init_s = fb_hex(
    "e61ef9919cde45dd5f82166404bd08e38bceb5dfdfded0a34c8df7ed542214d1",
  )
  let resp_s = fb_hex(
    "4a3acbfdb163dec651dfa3194dece676d437029c62a408b4c5ea9114246e4893",
  )
  let alice_pub_e = public_key_25519(init_e)
  let init = Builder::new(oracle.protocol)
    .prologue(prologue)
    .local_private_key(init_s)
    .local_ephemeral_private(init_e)
    .build_initiator(None)
  let resp = Builder::new(oracle.protocol)
    .prologue(prologue)
    .local_private_key(resp_s)
    .local_ephemeral_private(resp_e)
    .remote_ephemeral_public(alice_pub_e)
    .build_responder(None)
  assert_true(init.responder_sends_first())
  assert_false(init.initiator_sends_at(0))
  assert_true(init.initiator_sends_at(1))
  let p0 = fb_hex("4d757272617920526f746862617264")
  let m1 = resp.write_message(p0)
  assert_eq(@lib.bytes_to_hex(m1), oracle.m1)
  assert_eq(init.read_message(m1), p0)
  let p1 = fb_hex("462e20412e20486179656b")
  let m2 = init.write_message(p1)
  assert_eq(@lib.bytes_to_hex(m2), oracle.m2)
  assert_eq(resp.read_message(m2), p1)
  assert_eq(@lib.bytes_to_hex(init.handshake_hash()), oracle.handshake_hash)
  let a = init.into_transport()
  let b = resp.into_transport()
  let p2 = fb_hex("4361726c204d656e676572")
  let m3 = b.write_message(p2)
  assert_eq(@lib.bytes_to_hex(m3), oracle.m3)
  assert_eq(a.read_message(m3), p2)
  let p3 = fb_hex("4a65616e2d426170746973746520536179")
  let m4 = a.write_message(p3)
  assert_eq(@lib.bytes_to_hex(m4), oracle.m4)
  assert_eq(b.read_message(m4), p3)
}

///|
test "xxfallback matches independent python oracle" {
  for oracle in fallback_oracles() {
    run_fallback_oracle(oracle)
  }
}

///|
test "fallback rejects a first message that is not a pre-message" {
  let rejected = try {
    let _ = Pattern::by_name("NKfallback")
    true
  } catch {
    InvalidInput(_) => false
    _ => true
  }
  assert_false(rejected)
}

///|
test "nnfallback matches the python oracle and keeps responder direction" {
  let prologue = fb_hex("4a6f686e2047616c74")
  let init_e = fb_hex(
    "893e28b9dc6ca8d611ab664754b8ceb7bac5117349a4439a6b0569da977c464a",
  )
  let resp_e = fb_hex(
    "bbdb4cdbd309f1a1f2e1456967fe288cadd6f712d65dc7b7793d5e63da6b375b",
  )
  let init = Builder::new("Noise_NNfallback_25519_ChaChaPoly_SHA256")
    .prologue(prologue)
    .local_ephemeral_private(init_e)
    .build_initiator(None)
  let resp = Builder::new("Noise_NNfallback_25519_ChaChaPoly_SHA256")
    .prologue(prologue)
    .local_ephemeral_private(resp_e)
    .remote_ephemeral_public(public_key_25519(init_e))
    .build_responder(None)
  assert_true(init.responder_sends_first())
  assert_false(init.initiator_sends_at(0))
  assert_true(init.initiator_sends_at(1))
  expect_noise_turn(() => {
    let _ = init.write_message(b"")
  })
  let p0 = fb_hex("4d757272617920526f746862617264")
  let m1 = resp.write_message(p0)
  assert_eq(
    @lib.bytes_to_hex(m1),
    "95ebc60d2b1fa672c1f46a8aa265ef51bfe38e7ccb39ec5be34069f1448088430a999c3d6d87db6785bbdb7ee87c545bed40bc4daabf9b74eea0e276acffe9",
  )
  assert_eq(init.read_message(m1), p0)
  assert_eq(
    @lib.bytes_to_hex(init.handshake_hash()),
    "6cdea0a808eee16546ab45795eab788b186af1d59d06fe1603a2497ec7711fd8",
  )
  let a = init.into_transport()
  let b = resp.into_transport()
  let p1 = fb_hex("462e20412e20486179656b")
  let m2 = a.write_message(p1)
  assert_eq(
    @lib.bytes_to_hex(m2),
    "ca37dc49ea3a4220c885e616c6bcc8db8d5b28ca64fa59594629bc",
  )
  assert_eq(b.read_message(m2), p1)
}

///|
test "xxfallback plus psk0 matches the python oracle" {
  let prologue = fb_hex("4a6f686e2047616c74")
  let init_e = fb_hex(
    "893e28b9dc6ca8d611ab664754b8ceb7bac5117349a4439a6b0569da977c464a",
  )
  let resp_e = fb_hex(
    "bbdb4cdbd309f1a1f2e1456967fe288cadd6f712d65dc7b7793d5e63da6b375b",
  )
  let init_s = fb_hex(
    "e61ef9919cde45dd5f82166404bd08e38bceb5dfdfded0a34c8df7ed542214d1",
  )
  let resp_s = fb_hex(
    "4a3acbfdb163dec651dfa3194dece676d437029c62a408b4c5ea9114246e4893",
  )
  let psk = fb_hex(
    "a7554cd5dfc72e5b7e2146beccc1c87ac59fdc6a1f1355a540c89e358363d3b4",
  )
  let init = Builder::new("Noise_XXfallback+psk0_25519_ChaChaPoly_SHA256")
    .prologue(prologue)
    .local_private_key(init_s)
    .local_ephemeral_private(init_e)
    .psk(psk)
    .build_initiator(None)
  let resp = Builder::new("Noise_XXfallback+psk0_25519_ChaChaPoly_SHA256")
    .prologue(prologue)
    .local_private_key(resp_s)
    .local_ephemeral_private(resp_e)
    .remote_ephemeral_public(public_key_25519(init_e))
    .psk(psk)
    .build_responder(None)
  let p0 = fb_hex("4d757272617920526f746862617264")
  let m1 = resp.write_message(p0)
  assert_eq(
    @lib.bytes_to_hex(m1),
    "95ebc60d2b1fa672c1f46a8aa265ef51bfe38e7ccb39ec5be34069f144808843a395d49b47dc98a56cf25b89ef6dff933cd51b2efaefc455b62a8f20caef67bfd1a702094ca8e9bd3950821b6095e59f6ace57de29e6be8088261a4d4bdc407b783775bcc8d239d0e783d6553f4038",
  )
  assert_eq(init.read_message(m1), p0)
  let p1 = fb_hex("462e20412e20486179656b")
  let m2 = init.write_message(p1)
  assert_eq(
    @lib.bytes_to_hex(m2),
    "90a871af2c5609b10e4e43a8cb3a095eb518b917ac268dcedae76914adf6f628cdf0745c8abdc1d71ed7539f6d7121ed75e21a916b0ae64d2c70aa91c591ea675dd4b5e8163821d485b6b5",
  )
  assert_eq(resp.read_message(m2), p1)
  assert_eq(
    @lib.bytes_to_hex(init.handshake_hash()),
    "25ebeb2f816269092295291a34ce53c42a18cb5f79370b468f940770d2b29602",
  )
  let a = init.into_transport()
  let b = resp.into_transport()
  let m3 = b.write_message(fb_hex("4361726c204d656e676572"))
  assert_eq(
    @lib.bytes_to_hex(m3),
    "57393d7b5089d2ed4040a52976031db00b3e569495f8cb046689b0",
  )
  let m4 = a.write_message(fb_hex("4a65616e2d426170746973746520536179"))
  assert_eq(
    @lib.bytes_to_hex(m4),
    "5d8fac1606c985a800eefa899b22fe95ecf6b0dfea221d1ab07a4c7d4e43c2ed21",
  )
}

///|
test "fallback protocol name is part of the transcript" {
  let prologue = fb_hex("4a6f686e2047616c74")
  let init_e = fb_hex(
    "893e28b9dc6ca8d611ab664754b8ceb7bac5117349a4439a6b0569da977c464a",
  )
  let resp_e = fb_hex(
    "bbdb4cdbd309f1a1f2e1456967fe288cadd6f712d65dc7b7793d5e63da6b375b",
  )
  let init_s = fb_hex(
    "e61ef9919cde45dd5f82166404bd08e38bceb5dfdfded0a34c8df7ed542214d1",
  )
  let resp_s = fb_hex(
    "4a3acbfdb163dec651dfa3194dece676d437029c62a408b4c5ea9114246e4893",
  )
  let xx_i = Builder::new("Noise_XX_25519_ChaChaPoly_SHA256")
    .prologue(prologue)
    .local_private_key(init_s)
    .local_ephemeral_private(init_e)
    .build_initiator(None)
  let xx_r = Builder::new("Noise_XX_25519_ChaChaPoly_SHA256")
    .prologue(prologue)
    .local_private_key(resp_s)
    .local_ephemeral_private(resp_e)
    .build_responder(None)
  let _ = xx_r.read_message(xx_i.write_message(b""))
  let _ = xx_i.read_message(xx_r.write_message(b""))
  let _ = xx_r.read_message(xx_i.write_message(b""))
  let fb = Builder::new("Noise_XXfallback_25519_ChaChaPoly_SHA256")
    .prologue(prologue)
    .local_private_key(resp_s)
    .local_ephemeral_private(resp_e)
    .remote_ephemeral_public(public_key_25519(init_e))
    .build_responder(None)
  let fa = Builder::new("Noise_XXfallback_25519_ChaChaPoly_SHA256")
    .prologue(prologue)
    .local_private_key(init_s)
    .local_ephemeral_private(init_e)
    .build_initiator(None)
  let _ = fa.read_message(fb.write_message(b""))
  let _ = fb.read_message(fa.write_message(b""))
  assert_false(xx_i.handshake_hash() == fa.handshake_hash())
}

///|
test "illegal fallback modifiers and a missing pre-message fail closed" {
  let names = ["IKfallback", "NKfallback", "XXpsk0+fallback"]
  for name in names {
    let rejected = try {
      let _ = Pattern::by_name(name)
      true
    } catch {
      InvalidInput(_) => false
      _ => true
    }
    assert_false(rejected)
  }
  let missing = try {
    let _ = Builder::new("Noise_XXfallback_25519_ChaChaPoly_SHA256")
      .local_private_key(@lib.sha256(b"s"))
      .local_ephemeral_private(@lib.sha256(b"e"))
      .build_responder(None)
    true
  } catch {
    MissingKey => false
    _ => true
  }
  assert_false(missing)
}

///|
fn expect_noise_turn(body : () -> Unit raise NoiseError) -> Unit raise {
  let ok = try {
    body()
    true
  } catch {
    WrongTurn => false
    _ => true
  }
  assert_false(ok)
}

///|
test "fallback then psk0 is a different placement from psk then fallback" {
  let switched = Pattern::by_name("XXfallback+psk0")
  assert_true(switched.responder_sends_first())
  assert_eq(switched.psk_slots(), [0])
  let rejected = try {
    let _ = Pattern::by_name("XXpsk0+fallback")
    true
  } catch {
    InvalidInput(_) => false
    _ => true
  }
  assert_false(rejected)
}
