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
  priv mut psk : Bytes?
}

///|
priv struct ProtocolParts {
  pattern_name : String
  cipher : CipherKind
  hash : HashKind
}

///|
fn parse_protocol(name : String) -> ProtocolParts raise NoiseError {
  let parts : Array[String] = []
  for view in name.split("_") {
    parts.push(view.to_owned())
  }
  if parts.length() != 5 || parts[0] != "Noise" {
    raise InvalidInput(
      "protocol name must be Noise_<pattern>_25519_<cipher>_<hash>",
    )
  }
  if parts[2] != "25519" {
    raise Unsupported("only DH 25519 is implemented")
  }
  let cipher = match parts[3] {
    "ChaChaPoly" => ChaChaPoly
    "AESGCM" => AesGcm
    _ => raise Unsupported("cipher " + parts[3])
  }
  let hash = match parts[4] {
    "SHA256" => Sha256
    "BLAKE2s" => Blake2s
    _ => raise Unsupported("hash " + parts[4])
  }
  { pattern_name: parts[1], cipher, hash, }
}

///|
pub fn Builder::new(protocol_name : String) -> Builder raise NoiseError {
  let parts = parse_protocol(protocol_name)
  Builder::make(
    protocol_name,
    Pattern::by_name(parts.pattern_name),
    parts.cipher,
    parts.hash,
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
  Builder::make(protocol_name, pattern, parts.cipher, parts.hash)
}

///|
fn Builder::make(
  protocol_name : String,
  pattern : Pattern,
  cipher : CipherKind,
  hash : HashKind,
) -> Builder {
  {
    protocol_name,
    pattern,
    cipher,
    hash,
    dh: Curve25519,
    prologue: b"",
    local_static: None,
    remote_static: None,
    local_ephemeral: None,
    psk: None,
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
  if key.length() != 32 {
    raise InvalidInput("local private key must be 32 bytes")
  }
  self.local_static = Some(key)
  self
}

///|
pub fn Builder::remote_public_key(
  self : Builder,
  key : Bytes,
) -> Builder raise NoiseError {
  if key.length() != 32 {
    raise InvalidInput("remote public key must be 32 bytes")
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
  if key.length() != 32 {
    raise InvalidInput("ephemeral private key must be 32 bytes")
  }
  self.local_ephemeral = Some(key)
  self
}

///|
/// One 32-byte PSK, reused for every `psk` token in the pattern.
pub fn Builder::psk(self : Builder, key : Bytes) -> Builder raise NoiseError {
  if key.length() != 32 {
    raise InvalidInput("psk must be 32 bytes")
  }
  self.psk = Some(key)
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
