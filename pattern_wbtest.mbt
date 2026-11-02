///|
test "builtin pattern shapes" {
  let nn = Pattern::by_name("NN")
  assert_eq(nn.name(), "NN")
  assert_eq(nn.message_count(), 2)
  assert_false(nn.has_psk())
  assert_eq(Pattern::by_name("NK").message_count(), 2)
  assert_eq(Pattern::by_name("XX").message_count(), 3)
  assert_eq(Pattern::by_name("IK").message_count(), 2)
}

///|
test "parse custom pattern string" {
  let nx = Pattern::parse("NX:\n-> e\n<- e, ee, s, es\n")
  assert_eq(nx.name(), "NX")
  assert_eq(nx.message_count(), 2)
  let psk = Pattern::parse("-> psk, e\n<- e, ee")
  assert_true(psk.has_psk())
  let bad = try {
    let _ = Pattern::parse("e, ee")
    true
  } catch {
    InvalidInput(_) => false
    _ => true
  }
  assert_false(bad)
}

///|
test "builtin patterns include one-way, deferred, and psk" {
  assert_true(Pattern::by_name("N").is_oneway())
  assert_eq(Pattern::by_name("NX").message_count(), 2)
  assert_eq(Pattern::by_name("X1X1").message_count(), 4)
  let psk = Pattern::by_name("NNpsk0")
  assert_true(psk.has_psk())
  assert_eq(psk.psk_slots(), [0])
  let later = Pattern::by_name("NNpsk2")
  assert_eq(later.psk_slots(), [2])
}

///|
test "unknown builtin pattern" {
  let ok = try {
    let _ = Pattern::by_name("ZZ")
    true
  } catch {
    Unsupported(_) => false
    _ => true
  }
  assert_false(ok)
}
