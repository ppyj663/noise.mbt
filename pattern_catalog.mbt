///|
/// Base patterns from Noise sections 7 and 8, longest name first so `XX1`
/// is not parsed as `XX`.
fn known_patterns() -> Array[String] {
  [
    "I1K1", "I1X1", "K1K1", "K1X1", "X1K1", "X1X1", "I1K", "I1N", "I1X", "IK1", "IX1",
    "K1K", "K1N", "K1X", "KK1", "KX1", "NK1", "NX1", "X1K", "X1N", "X1X", "XK1",
    "XX1", "IK", "IN", "IX", "KK", "KN", "KX", "NK", "NN", "NX", "XK", "XN", "XX",
    "K", "N", "X",
  ]
}

///|
fn pattern_definition(name : String) -> String raise NoiseError {
  match name {
    "N" => "<- s\n...\n-> e, es"
    "K" => "-> s\n<- s\n...\n-> e, es, ss"
    "X" => "<- s\n...\n-> e, es, s, ss"
    "NN" => "-> e\n<- e, ee"
    "NK" => "<- s\n...\n-> e, es\n<- e, ee"
    "NX" => "-> e\n<- e, ee, s, es"
    "XN" => "-> e\n<- e, ee\n-> s, se"
    "XK" => "<- s\n...\n-> e, es\n<- e, ee\n-> s, se"
    "XX" => "-> e\n<- e, ee, s, es\n-> s, se"
    "KN" => "-> s\n...\n-> e\n<- e, ee, se"
    "KK" => "-> s\n<- s\n...\n-> e, es, ss\n<- e, ee, se"
    "KX" => "-> s\n...\n-> e\n<- e, ee, se, s, es"
    "IN" => "-> e, s\n<- e, ee, se"
    "IK" => "<- s\n...\n-> e, es, s, ss\n<- e, ee, se"
    "IX" => "-> e, s\n<- e, ee, se, s, es"
    "NK1" => "<- s\n...\n-> e\n<- e, ee, es"
    "NX1" => "-> e\n<- e, ee, s\n-> es"
    "X1N" => "-> e\n<- e, ee\n-> s\n<- se"
    "X1K" => "<- s\n...\n-> e, es\n<- e, ee\n-> s\n<- se"
    "XK1" => "<- s\n...\n-> e\n<- e, ee, es\n-> s, se"
    "X1K1" => "<- s\n...\n-> e\n<- e, ee, es\n-> s\n<- se"
    "X1X" => "-> e\n<- e, ee, s, es\n-> s\n<- se"
    "XX1" => "-> e\n<- e, ee, s\n-> es, s, se"
    "X1X1" => "-> e\n<- e, ee, s\n-> es, s\n<- se"
    "K1N" => "-> s\n...\n-> e\n<- e, ee\n-> se"
    "K1K" => "-> s\n<- s\n...\n-> e, es\n<- e, ee\n-> se"
    "KK1" => "-> s\n<- s\n...\n-> e\n<- e, ee, se, es"
    "K1K1" => "-> s\n<- s\n...\n-> e\n<- e, ee, es\n-> se"
    "K1X" => "-> s\n...\n-> e\n<- e, ee, s, es\n-> se"
    "KX1" => "-> s\n...\n-> e\n<- e, ee, se, s\n-> es"
    "K1X1" => "-> s\n...\n-> e\n<- e, ee, s\n-> se, es"
    "I1N" => "-> e, s\n<- e, ee\n-> se"
    "I1K" => "<- s\n...\n-> e, es, s\n<- e, ee\n-> se"
    "IK1" => "<- s\n...\n-> e, s\n<- e, ee, se, es"
    "I1K1" => "<- s\n...\n-> e, s\n<- e, ee, es\n-> se"
    "I1X" => "-> e, s\n<- e, ee, s, es\n-> se"
    "IX1" => "-> e, s\n<- e, ee, se, s\n-> es"
    "I1X1" => "-> e, s\n<- e, ee, s\n-> se, es"
    _ => raise Unsupported("unknown pattern " + name)
  }
}

///|
fn split_pattern_name(
  name : String,
) -> (String, Array[String]) raise NoiseError {
  for base in known_patterns() {
    if name == base {
      return (base, [])
    }
    if name.has_prefix(base) {
      let rest = name[base.length():].to_owned()
      if rest.has_prefix("psk") || rest.has_prefix("+") {
        return (base, parse_modifier_list(rest))
      }
    }
  }
  raise Unsupported("unknown pattern " + name)
}

///|
fn parse_modifier_list(rest : String) -> Array[String] raise NoiseError {
  let body = if rest.has_prefix("+") { rest[1:].to_owned() } else { rest }
  let modifiers : Array[String] = []
  for piece in body.split("+") {
    let word = piece.trim().to_owned()
    if word.length() == 0 {
      continue
    }
    if !word.has_prefix("psk") {
      raise Unsupported("modifier " + word)
    }
    modifiers.push(word)
  }
  if modifiers.length() == 0 {
    raise InvalidInput("missing pattern modifier")
  }
  modifiers
}

///|
fn parse_psk_index(word : String) -> Int32 raise NoiseError {
  if !word.has_prefix("psk") || word.length() == 3 {
    raise InvalidInput("psk modifier needs an index")
  }
  let digits = word[3:].to_owned()
  let mut value = 0
  for i in 0..<digits.length() {
    let digit = digits[i].to_int() - '0'.to_int()
    if digit < 0 || digit > 9 {
      raise InvalidInput("bad psk modifier " + word)
    }
    value = value * 10 + digit
  }
  value
}
