///|
/// Which side of the handshake this state machine plays.
pub enum Role {
  Initiator
  Responder
}

///|
/// HandshakeState from Noise spec section 5.3.
pub struct Handshake {
  priv sym : SymmetricState
  priv pattern : Pattern
  priv initiator : Bool
  priv mut my_turn : Bool
  priv mut index : Int32
  priv mut failed : Bool
  priv mut moved : Bool
  priv mut s_priv : Bytes?
  priv mut s_pub : Bytes?
  priv mut e_priv : Bytes?
  priv mut e_pub : Bytes?
  priv mut rs : Bytes?
  priv mut re : Bytes?
  priv mut ephemeral_once : Bytes?
  priv dh : DhKind
  priv random : ((Int32) -> Bytes)?
  priv is_psk : Bool
  priv psk_pairs : Array[(Int32, Bytes)]
  priv dh_policy : DhOutputPolicy
  priv mut send_cs : CipherState?
  priv mut recv_cs : CipherState?
}

///|
pub fn Handshake::is_initiator(self : Handshake) -> Bool {
  self.initiator
}

///|
pub fn Handshake::is_my_turn(self : Handshake) -> Bool {
  self.my_turn
}

///|
pub fn Handshake::is_oneway(self : Handshake) -> Bool {
  self.pattern.is_oneway()
}

///|
/// True when this pattern's first handshake message is sent by the responder.
pub fn Handshake::responder_sends_first(self : Handshake) -> Bool {
  self.pattern.responder_sends_first()
}

///|
/// Whether the initiator sends handshake or transport message `index`.
///
/// Fallback is checked first. `NNfallback` has one remaining message, so
/// `is_oneway` is true, but that message is sent by the responder. One-way
/// patterns `N`, `K`, and `X` are not fallback patterns, so the initiator
/// keeps sending.
pub fn Handshake::initiator_sends_at(self : Handshake, index : Int32) -> Bool {
  if self.responder_sends_first() {
    index % 2 == 1
  } else if self.is_oneway() {
    true
  } else {
    index % 2 == 0
  }
}

///|
pub fn Handshake::is_finished(self : Handshake) -> Bool {
  !self.failed && !self.moved && self.index == self.pattern.messages.length()
}

///|
/// Remote static public key, once it is known.
pub fn Handshake::remote_static(self : Handshake) -> Bytes? {
  self.rs
}

///|
/// Handshake hash `h`. The spec value is the one present after `Split`.
pub fn Handshake::handshake_hash(self : Handshake) -> Bytes raise NoiseError {
  if self.index != self.pattern.messages.length() || self.failed {
    raise InvalidInput("handshake hash is available after the handshake")
  }
  self.sym.get_hash()
}

///|
fn Handshake::create(
  builder : Builder,
  role : Role,
  random : ((Int32) -> Bytes)?,
) -> Handshake raise NoiseError {
  let initiator = match role {
    Initiator => true
    Responder => false
  }
  let pattern = builder.pattern
  let dh = builder.dh
  require_psk_slots(pattern, builder.psk_pairs)
  let sym = SymmetricState::new(builder.cipher, builder.hash)
  sym.initialize(builder.protocol_name)
  sym.mix_hash(builder.prologue)
  let hs = Handshake::{
    sym,
    pattern,
    initiator,
    my_turn: if pattern.responder_sends_first() {
      !initiator
    } else {
      initiator
    },
    index: 0,
    failed: false,
    moved: false,
    s_priv: None,
    s_pub: None,
    e_priv: None,
    e_pub: None,
    rs: builder.remote_static,
    re: builder.remote_ephemeral,
    ephemeral_once: None,
    dh,
    random,
    is_psk: pattern.has_psk(),
    psk_pairs: builder.psk_pairs,
    dh_policy: builder.dh_policy,
    send_cs: None,
    recv_cs: None,
  }
  match builder.local_static {
    Some(sk) => {
      hs.s_pub = Some(dh_public(dh, sk))
      hs.s_priv = Some(sk)
    }
    None => ()
  }
  match builder.local_ephemeral {
    Some(ek) =>
      if pattern_needs_local_ephemeral_now(pattern, initiator) {
        hs.e_pub = Some(dh_public(dh, ek))
        hs.e_priv = Some(ek)
      } else {
        hs.ephemeral_once = Some(ek)
      }
    None => ()
  }
  let missing_static = match hs.s_priv {
    Some(_) => false
    None => true
  }
  if pattern_needs_local_static(pattern, initiator) && missing_static {
    raise MissingKey
  }
  if pattern_needs_remote_static(pattern, initiator) {
    match hs.rs {
      Some(pk) =>
        if pk.length() != dh.dh_len() {
          raise InvalidInput("remote static key has the wrong length")
        }
      None => raise MissingKey
    }
  }
  if pattern_needs_remote_ephemeral(pattern, initiator) {
    match hs.re {
      Some(pk) =>
        if pk.length() != dh.dh_len() {
          raise InvalidInput("remote ephemeral key has the wrong length")
        }
      None => raise MissingKey
    }
  }
  hs.mix_premessages(pattern.pre_i, true)
  hs.mix_premessages(pattern.pre_r, false)
  hs
}

///|
fn Handshake::mix_premessages(
  self : Handshake,
  tokens : Array[Token],
  initiator_side : Bool,
) -> Unit raise NoiseError {
  let ours = initiator_side == self.initiator
  for token in tokens {
    let public = match token {
      E =>
        if ours {
          match self.e_pub {
            Some(pk) => pk
            None => raise MissingKey
          }
        } else {
          match self.re {
            Some(pk) => pk
            None => raise MissingKey
          }
        }
      S =>
        if ours {
          match self.s_pub {
            Some(pk) => pk
            None => raise MissingKey
          }
        } else {
          match self.rs {
            Some(pk) => pk
            None => raise MissingKey
          }
        }
      _ => raise InvalidInput("pre-message token must be e or s")
    }
    self.sym.mix_hash(public)
    match token {
      E => if self.is_psk { self.sym.mix_key(public) }
      _ => ()
    }
  }
}

///|
fn Handshake::next_ephemeral(self : Handshake) -> Bytes raise NoiseError {
  let expect = self.dh.dh_len()
  match self.ephemeral_once {
    Some(key) => {
      self.ephemeral_once = None
      if key.length() != expect {
        raise InvalidInput("ephemeral private key has the wrong length")
      }
      key
    }
    None =>
      match self.random {
        Some(fill) => {
          let key = fill(expect)
          if key.length() != expect {
            raise InvalidInput("random source returned the wrong length")
          }
          key
        }
        None => raise MissingRandom
      }
  }
}

///|
fn Handshake::dh_ee(self : Handshake) -> Bytes raise NoiseError {
  self.dh_pair(self.e_priv, self.re)
}

///|
fn Handshake::dh_ss(self : Handshake) -> Bytes raise NoiseError {
  self.dh_pair(self.s_priv, self.rs)
}

///|
fn Handshake::dh_es(self : Handshake) -> Bytes raise NoiseError {
  if self.initiator {
    self.dh_pair(self.e_priv, self.rs)
  } else {
    self.dh_pair(self.s_priv, self.re)
  }
}

///|
fn Handshake::dh_se(self : Handshake) -> Bytes raise NoiseError {
  if self.initiator {
    self.dh_pair(self.s_priv, self.re)
  } else {
    self.dh_pair(self.e_priv, self.rs)
  }
}

///|
fn Handshake::dh_pair(
  self : Handshake,
  scalar : Bytes?,
  peer : Bytes?,
) -> Bytes raise NoiseError {
  match (scalar, peer) {
    (Some(sk), Some(pk)) => {
      let shared = dh_exchange(self.dh, sk, pk)
      match self.dh_policy {
        RejectAllZero =>
          if dh_output_is_all_zero(shared) {
            raise InvalidInput(
              "dh output is all zeros; this optional rejection is not peer authentication",
            )
          }
        ReturnOutput => ()
      }
      shared
    }
    _ => raise MissingKey
  }
}

///|
fn lookup_psk(pairs : Array[(Int32, Bytes)], slot : Int32) -> Bytes? {
  for pair in pairs {
    let (index, key) = pair
    if index == slot {
      return Some(key)
    }
  }
  None
}

///|
fn require_psk_slots(
  pattern : Pattern,
  pairs : Array[(Int32, Bytes)],
) -> Unit raise NoiseError {
  for slot in pattern.psk_slots() {
    match lookup_psk(pairs, slot) {
      Some(key) =>
        if key.length() != 32 {
          raise InvalidInput("psk must be 32 bytes")
        }
      None => raise MissingKey
    }
  }
}

///|
fn Handshake::finish_split(self : Handshake) -> Unit raise NoiseError {
  if self.index + 1 == self.pattern.messages.length() {
    let (c1, c2) = self.sym.split()
    if self.initiator {
      self.send_cs = Some(c1)
      self.recv_cs = Some(c2)
    } else {
      self.send_cs = Some(c2)
      self.recv_cs = Some(c1)
    }
  }
}

///|
/// `WriteMessage`. Returns the handshake message bytes.
pub fn Handshake::write_message(
  self : Handshake,
  payload : Bytes,
) -> Bytes raise NoiseError {
  if self.failed || self.moved {
    raise HandshakeFailed
  }
  if self.index >= self.pattern.messages.length() {
    raise HandshakeFinished
  }
  if !self.my_turn {
    raise WrongTurn
  }
  self.failed = true
  let tokens = self.pattern.messages[self.index]
  let buf = @buffer.Buffer()
  for token in tokens {
    match token {
      E => {
        let sk = self.next_ephemeral()
        let pk = dh_public(self.dh, sk)
        self.e_priv = Some(sk)
        self.e_pub = Some(pk)
        buf.write_bytes(pk)
        self.sym.mix_hash(pk)
        if self.is_psk {
          self.sym.mix_key(pk)
        }
      }
      S =>
        match self.s_pub {
          Some(pk) => {
            let ct = self.sym.encrypt_and_hash(pk)
            buf.write_bytes(ct)
          }
          None => raise MissingKey
        }
      Ee => self.sym.mix_key(self.dh_ee())
      Es => self.sym.mix_key(self.dh_es())
      Se => self.sym.mix_key(self.dh_se())
      Ss => self.sym.mix_key(self.dh_ss())
      Psk(slot) =>
        match lookup_psk(self.psk_pairs, slot) {
          Some(key) => self.sym.mix_key_and_hash(key)
          None => raise MissingKey
        }
    }
  }
  let ct = self.sym.encrypt_and_hash(payload)
  buf.write_bytes(ct)
  let message = buf.to_bytes()
  if message.length() > 65535 {
    raise MessageTooLong
  }
  self.finish_split()
  self.index = self.index + 1
  self.my_turn = false
  self.failed = false
  message
}

///|
/// `ReadMessage`. Returns the decrypted payload.
pub fn Handshake::read_message(
  self : Handshake,
  message : Bytes,
) -> Bytes raise NoiseError {
  if self.failed || self.moved {
    raise HandshakeFailed
  }
  if message.length() > 65535 {
    raise MessageTooLong
  }
  if self.index >= self.pattern.messages.length() {
    raise HandshakeFinished
  }
  if self.my_turn {
    raise WrongTurn
  }
  self.failed = true
  let tokens = self.pattern.messages[self.index]
  let mut offset = 0
  for token in tokens {
    match token {
      E => {
        let pk = take_bytes(message, offset, self.dh.dh_len())
        offset = offset + self.dh.dh_len()
        self.re = Some(pk)
        self.sym.mix_hash(pk)
        if self.is_psk {
          self.sym.mix_key(pk)
        }
      }
      S => {
        let dlen = self.dh.dh_len()
        let n = if self.sym.has_key() { dlen + 16 } else { dlen }
        let temp = take_bytes(message, offset, n)
        offset = offset + n
        let pk = self.sym.decrypt_and_hash(temp)
        if pk.length() != dlen {
          raise DecryptFail
        }
        self.rs = Some(pk)
      }
      Ee => self.sym.mix_key(self.dh_ee())
      Es => self.sym.mix_key(self.dh_es())
      Se => self.sym.mix_key(self.dh_se())
      Ss => self.sym.mix_key(self.dh_ss())
      Psk(slot) =>
        match lookup_psk(self.psk_pairs, slot) {
          Some(key) => self.sym.mix_key_and_hash(key)
          None => raise MissingKey
        }
    }
  }
  let rest = take_bytes(message, offset, message.length() - offset)
  let payload = self.sym.decrypt_and_hash(rest)
  self.finish_split()
  self.index = self.index + 1
  self.my_turn = true
  self.failed = false
  payload
}

///|
/// Move the finished handshake into transport ciphers.
/// The first cipher encrypts initiator to responder.
pub fn Handshake::into_transport(
  self : Handshake,
) -> Transport raise NoiseError {
  if self.failed || self.moved || !self.is_finished() {
    raise HandshakeFinished
  }
  match (self.send_cs, self.recv_cs) {
    (Some(send), Some(recv)) => {
      self.moved = true
      { send, recv, hash: self.sym.get_hash(), }
    }
    _ => raise HandshakeFinished
  }
}
