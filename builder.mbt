///|
/// Builds a `Handshake` from a protocol name such as
/// `Noise_XX_25519_ChaChaPoly_SHA256`.
pub struct Builder {
  priv protocol_name : String
  priv pattern : Pattern
  priv cipher : CipherKind
  priv hash : HashKind
  priv dh : DhKind
  priv mut prologue : Bytes
  priv mut local_static : Bytes?
  priv mut remote_static : Bytes?
  priv mut local_ephemeral : Bytes?
  priv mut psk_pairs : Array[(Int32, Bytes)]
}

///|
priv struct ProtocolParts {
  pattern_name : String
  cipher : CipherKind
  hash : HashKind
  dh : DhKind
}

///|
fn parse_protocol(name : String) -> ProtocolParts raise NoiseError {
  let parts : Array[String] = []
  for view in name.split("_") {
    parts.push(view.to_owned())
  }
  if parts.length() != 5 || parts[0] != "Noise" {
    raise InvalidInput(
      "protocol name must be Noise_<pattern>_<dh>_<cipher>_<hash>",
    )
  }
  let dh = match parts[2] {
    "25519" => Curve25519
    "448" => X448
    _ => raise Unsupported("dh " + parts[2])
  }
  let cipher = match parts[3] {
    "ChaChaPoly" => ChaChaPoly
    "AESGCM" => AesGcm
    _ => raise Unsupported("cipher " + parts[3])
  }
  let hash = match parts[4] {
    "SHA256" => Sha256
    "SHA512" => Sha512
    "BLAKE2s" => Blake2s
    "BLAKE2b" => Blake2b
    _ => raise Unsupported("hash " + parts[4])
  }
  { pattern_name: parts[1], cipher, hash, dh, }
}

///|
pub fn Builder::new(protocol_name : String) -> Builder raise NoiseError {
  let parts = parse_protocol(protocol_name)
  Builder::make(
    protocol_name,
    Pattern::by_name(parts.pattern_name),
    parts.cipher,
    parts.hash,
    parts.dh,
  )
}

///|
/// Use `pattern` instead of the pattern named in `protocol_name`.
/// The protocol name is still the byte string mixed into `h`.
pub fn Builder::from_pattern(
  protocol_name : String,
  pattern : Pattern,
) -> Builder raise NoiseError {
  let parts = parse_protocol(protocol_name)
  Builder::make(protocol_name, pattern, parts.cipher, parts.hash, parts.dh)
}

///|
fn Builder::make(
  protocol_name : String,
  pattern : Pattern,
  cipher : CipherKind,
  hash : HashKind,
  dh : DhKind,
) -> Builder {
  {
    protocol_name,
    pattern,
    cipher,
    hash,
    dh,
    prologue: b"",
    local_static: None,
    remote_static: None,
    local_ephemeral: None,
    psk_pairs: [],
  }
}

///|
pub fn Builder::dh_name(self : Builder) -> String {
  self.dh.name()
}

///|
pub fn Builder::prologue(self : Builder, prologue : Bytes) -> Builder {
  self.prologue = prologue
  self
}

///|
pub fn Builder::local_private_key(
  self : Builder,
  key : Bytes,
) -> Builder raise NoiseError {
  if key.length() != self.dh.dh_len() {
    raise InvalidInput("local private key has the wrong length")
  }
  self.local_static = Some(key)
  self
}

///|
pub fn Builder::remote_public_key(
  self : Builder,
  key : Bytes,
) -> Builder raise NoiseError {
  if key.length() != self.dh.dh_len() {
    raise InvalidInput("remote public key has the wrong length")
  }
  self.remote_static = Some(key)
  self
}

///|
/// Private key used for the local ephemeral.
/// If the pattern has a pre-message `e`, this key is installed up front.
/// Otherwise it is used the next time this party writes an `e` token.
pub fn Builder::local_ephemeral_private(
  self : Builder,
  key : Bytes,
) -> Builder raise NoiseError {
  if key.length() != self.dh.dh_len() {
    raise InvalidInput("ephemeral private key has the wrong length")
  }
  self.local_ephemeral = Some(key)
  self
}

///|
/// One 32-byte PSK for slot 0. Use `psks` when the pattern has `psk1` or later.
pub fn Builder::psk(self : Builder, key : Bytes) -> Builder raise NoiseError {
  self.psks([key])
}

///|
/// PSKs in modifier order. `NNpsk0` takes one key; `NNpsk2` also takes one
/// key, stored in slot 2.
pub fn Builder::psks(
  self : Builder,
  keys : Array[Bytes],
) -> Builder raise NoiseError {
  let slots = self.pattern.psk_slots()
  if keys.length() != slots.length() {
    raise InvalidInput("psk count does not match the pattern")
  }
  let pairs : Array[(Int32, Bytes)] = []
  for i in 0..<keys.length() {
    if keys[i].length() != 32 {
      raise InvalidInput("psk must be 32 bytes")
    }
    pairs.push((slots[i], keys[i]))
  }
  self.psk_pairs = pairs
  self
}

///|
pub fn Builder::build_initiator(
  self : Builder,
  random : ((Int32) -> Bytes)?,
) -> Handshake raise NoiseError {
  Handshake::create(self, Initiator, random)
}

///|
pub fn Builder::build_responder(
  self : Builder,
  random : ((Int32) -> Bytes)?,
) -> Handshake raise NoiseError {
  Handshake::create(self, Responder, random)
}
