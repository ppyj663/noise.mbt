///|
/// One token in a handshake pattern.
pub enum Token {
  E
  S
  Ee
  Es
  Se
  Ss
  Psk
}

///|
/// A handshake pattern parsed from a pattern string.
///
/// Built-in names are `NN`, `NK`, `XX`, and `IK`. Any other pattern that
/// follows the spec diagram can be loaded with `Pattern::parse`, for example:
///
/// ```text
/// -> e
/// <- e, ee, s, es
/// ```
///
/// A line `...` separates pre-messages from handshake messages. `psk` is
/// accepted so a caller can place that token explicitly. Pattern modifiers
/// such as `psk0` are not applied automatically.
pub struct Pattern {
  priv mut name : String
  priv pre_i : Array[Token]
  priv pre_r : Array[Token]
  priv messages : Array[Array[Token]]
  priv is_psk : Bool
}

///|
pub fn Pattern::name(self : Pattern) -> String {
  self.name
}

///|
pub fn Pattern::message_count(self : Pattern) -> Int32 {
  self.messages.length()
}

///|
pub fn Pattern::has_psk(self : Pattern) -> Bool {
  self.is_psk
}

///|
pub fn Pattern::by_name(name : String) -> Pattern raise NoiseError {
  let src = match name {
    "NN" => "-> e\n<- e, ee"
    "NK" => "<- s\n...\n-> e, es\n<- e, ee"
    "XX" => "-> e\n<- e, ee, s, es\n-> s, se"
    "IK" => "<- s\n...\n-> e, es, s, ss\n<- e, ee, se"
    _ => raise Unsupported("unknown pattern " + name)
  }
  let pattern = parse_pattern(src)
  pattern.name = name
  pattern
}

///|
pub fn Pattern::parse(definition : String) -> Pattern raise NoiseError {
  parse_pattern(definition)
}

///|
fn parse_pattern(definition : String) -> Pattern raise NoiseError {
  let lines : Array[String] = []
  let mut header = "custom"
  for view in definition.split("\n") {
    let line = view.trim().to_owned()
    if line.length() == 0 || line.has_prefix("#") {
      continue
    }
    if ends_with_colon(line) && !line.has_prefix("->") && !line.has_prefix("<-") {
      header = line[0:line.length() - 1].to_owned()
      continue
    }
    lines.push(line)
  }
  let mut saw_sep = false
  for line in lines {
    if line == "..." {
      saw_sep = true
    }
  }
  let pre_i : Array[Token] = []
  let pre_r : Array[Token] = []
  let messages : Array[Array[Token]] = []
  let mut after = false
  let mut is_psk = false
  for line in lines {
    if line == "..." {
      after = true
      continue
    }
    let (from_init, tokens) = parse_message_line(line)
    for token in tokens {
      if token is Psk {
        is_psk = true
      }
    }
    if saw_sep && !after {
      if from_init {
        for token in tokens {
          pre_i.push(token)
        }
      } else {
        for token in tokens {
          pre_r.push(token)
        }
      }
    } else {
      messages.push(tokens)
    }
  }
  if messages.length() == 0 {
    raise InvalidInput("pattern has no handshake messages")
  }
  { name: header, pre_i, pre_r, messages, is_psk, }
}

///|
fn ends_with_colon(s : String) -> Bool {
  let n = s.length()
  n > 0 && s[n - 1] == ':'
}

///|
fn parse_message_line(line : String) -> (Bool, Array[Token]) raise NoiseError {
  let from_init = if line.has_prefix("->") {
    true
  } else if line.has_prefix("<-") {
    false
  } else {
    raise InvalidInput("pattern line must start with -> or <-")
  }
  let rest = line[2:].trim().to_owned()
  let tokens : Array[Token] = []
  if rest.length() == 0 {
    return (from_init, tokens)
  }
  for piece in rest.split(",") {
    let word = piece.trim().to_owned()
    if word.length() == 0 {
      continue
    }
    tokens.push(parse_token(word))
  }
  (from_init, tokens)
}

///|
fn parse_token(word : String) -> Token raise NoiseError {
  match word {
    "e" => E
    "s" => S
    "ee" => Ee
    "es" => Es
    "se" => Se
    "ss" => Ss
    "psk" => Psk
    _ => raise InvalidInput("unknown token " + word)
  }
}

///|
fn pattern_sender_is_initiator(index : Int32) -> Bool {
  index % 2 == 0
}

///|
fn token_eq(a : Token, b : Token) -> Bool {
  match (a, b) {
    (E, E) | (S, S) | (Ee, Ee) | (Es, Es) | (Se, Se) | (Ss, Ss) | (Psk, Psk) =>
      true
    _ => false
  }
}

///|
fn tokens_contain(tokens : Array[Token], want : Token) -> Bool {
  for token in tokens {
    if token_eq(token, want) {
      return true
    }
  }
  false
}

///|
fn pattern_needs_local_static(pattern : Pattern, initiator : Bool) -> Bool {
  let pre = if initiator { pattern.pre_i } else { pattern.pre_r }
  if tokens_contain(pre, S) {
    return true
  }
  let mut index = 0
  for message in pattern.messages {
    if pattern_sender_is_initiator(index) == initiator &&
      tokens_contain(message, S) {
      return true
    }
    index = index + 1
  }
  false
}

///|
fn pattern_needs_remote_static(pattern : Pattern, initiator : Bool) -> Bool {
  let pre = if initiator { pattern.pre_r } else { pattern.pre_i }
  tokens_contain(pre, S) || tokens_contain(pre, E)
}

///|
fn pattern_needs_local_ephemeral_now(
  pattern : Pattern,
  initiator : Bool,
) -> Bool {
  let pre = if initiator { pattern.pre_i } else { pattern.pre_r }
  tokens_contain(pre, E)
}
