///|
priv struct VecMsg {
  payload : Bytes
  ciphertext : Bytes
}

///|
priv struct VecCase {
  protocol_name : String
  init_prologue : Bytes
  resp_prologue : Bytes
  init_static : Bytes?
  resp_static : Bytes?
  init_ephemeral : Bytes?
  resp_ephemeral : Bytes?
  init_remote_static : Bytes?
  resp_remote_static : Bytes?
  handshake_hash : Bytes
  messages : Array[VecMsg]
}

///|
fn json_string(obj : Map[String, Json], key : String) -> String? {
  match obj.get(key) {
    Some(String(value)) => Some(value)
    _ => None
  }
}

///|
fn json_hex_required(
  obj : Map[String, Json],
  key : String,
) -> Bytes raise NoiseError {
  match json_string(obj, key) {
    Some(value) => @lib.hex_to_bytes(value)
    None => raise InvalidInput("missing " + key)
  }
}

///|
fn json_hex_optional(obj : Map[String, Json], key : String) -> Bytes? {
  match json_string(obj, key) {
    Some(value) => Some(@lib.hex_to_bytes(value))
    None => None
  }
}

///|
fn parse_vector(value : Json) -> VecCase raise NoiseError {
  match value {
    Object(obj) => {
      let messages : Array[VecMsg] = []
      match obj.get("messages") {
        Some(Array(items)) =>
          for item in items {
            match item {
              Object(message) =>
                messages.push({
                  payload: json_hex_required(message, "payload"),
                  ciphertext: json_hex_required(message, "ciphertext"),
                })
              _ => raise InvalidInput("message is not an object")
            }
          }
        _ => raise InvalidInput("missing messages")
      }
      {
        protocol_name: match json_string(obj, "protocol_name") {
          Some(name) => name
          None => raise InvalidInput("missing protocol_name")
        },
        init_prologue: json_hex_required(obj, "init_prologue"),
        resp_prologue: json_hex_required(obj, "resp_prologue"),
        init_static: json_hex_optional(obj, "init_static"),
        resp_static: json_hex_optional(obj, "resp_static"),
        init_ephemeral: json_hex_optional(obj, "init_ephemeral"),
        resp_ephemeral: json_hex_optional(obj, "resp_ephemeral"),
        init_remote_static: json_hex_optional(obj, "init_remote_static"),
        resp_remote_static: json_hex_optional(obj, "resp_remote_static"),
        handshake_hash: json_hex_required(obj, "handshake_hash"),
        messages,
      }
    }
    _ => raise InvalidInput("vector is not an object")
  }
}

///|
fn load_cacophony() -> Array[VecCase] raise Error {
  match @json.parse(cacophony_json()) {
    Object(root) =>
      match root.get("vectors") {
        Some(Array(items)) => {
          let out : Array[VecCase] = []
          for item in items {
            out.push(parse_vector(item))
          }
          out
        }
        _ => raise InvalidInput("missing vectors")
      }
    _ => raise InvalidInput("vector file is not an object")
  }
}

///|
fn apply_optional_key(
  builder : Builder,
  key : Bytes?,
  kind : String,
) -> Unit raise NoiseError {
  match key {
    None => ()
    Some(value) =>
      match kind {
        "local" => {
          let _ = builder.local_private_key(value)
        }
        "remote" => {
          let _ = builder.remote_public_key(value)
        }
        "ephemeral" => {
          let _ = builder.local_ephemeral_private(value)
        }
        _ => raise InvalidInput(kind)
      }
  }
}

///|
fn run_vector(case : VecCase) -> Unit raise Error {
  match (case.resp_static, case.init_remote_static) {
    (Some(secret), Some(public)) => assert_eq(public_key_25519(secret), public)
    _ => ()
  }
  match (case.init_static, case.resp_remote_static) {
    (Some(secret), Some(public)) => assert_eq(public_key_25519(secret), public)
    _ => ()
  }
  let init_builder = Builder::new(case.protocol_name).prologue(
    case.init_prologue,
  )
  let resp_builder = Builder::new(case.protocol_name).prologue(
    case.resp_prologue,
  )
  apply_optional_key(init_builder, case.init_static, "local")
  apply_optional_key(resp_builder, case.resp_static, "local")
  apply_optional_key(init_builder, case.init_remote_static, "remote")
  apply_optional_key(resp_builder, case.resp_remote_static, "remote")
  apply_optional_key(init_builder, case.init_ephemeral, "ephemeral")
  apply_optional_key(resp_builder, case.resp_ephemeral, "ephemeral")
  let initiator = init_builder.build_initiator(None)
  let responder = resp_builder.build_responder(None)
  let mut index = 0
  while !initiator.is_finished() {
    let message = case.messages[index]
    let wrote = if index % 2 == 0 {
      initiator.write_message(message.payload)
    } else {
      responder.write_message(message.payload)
    }
    if wrote != message.ciphertext {
      fail(case.protocol_name + " handshake message mismatch")
    }
    let got = if index % 2 == 0 {
      responder.read_message(wrote)
    } else {
      initiator.read_message(wrote)
    }
    assert_eq(got, message.payload)
    index = index + 1
  }
  assert_eq(initiator.handshake_hash(), case.handshake_hash)
  assert_eq(responder.handshake_hash(), case.handshake_hash)
  let init_transport = initiator.into_transport()
  let resp_transport = responder.into_transport()
  assert_eq(init_transport.handshake_hash(), case.handshake_hash)
  while index < case.messages.length() {
    let message = case.messages[index]
    if index % 2 == 0 {
      let wrote = init_transport.write_message(message.payload)
      if wrote != message.ciphertext {
        fail(case.protocol_name + " transport message mismatch")
      }
      assert_eq(resp_transport.read_message(wrote), message.payload)
    } else {
      let wrote = resp_transport.write_message(message.payload)
      if wrote != message.ciphertext {
        fail(case.protocol_name + " transport message mismatch")
      }
      assert_eq(init_transport.read_message(wrote), message.payload)
    }
    index = index + 1
  }
}

///|
/// Runs every vendored Cacophony vector this library claims to support.
/// Returns a one-line pass count per pattern.
pub fn verify_cacophony_vectors() -> String raise Error {
  let cases = load_cacophony()
  let mut nn = 0
  let mut nk = 0
  let mut xx = 0
  let mut ik = 0
  for case in cases {
    run_vector(case)
    let name = case.protocol_name
    if name.has_prefix("Noise_NN_") {
      nn = nn + 1
    } else if name.has_prefix("Noise_NK_") {
      nk = nk + 1
    } else if name.has_prefix("Noise_XX_") {
      xx = xx + 1
    } else if name.has_prefix("Noise_IK_") {
      ik = ik + 1
    } else {
      raise InvalidInput(name)
    }
  }
  "NN " +
  nn.to_string() +
  "/4, NK " +
  nk.to_string() +
  "/4, XX " +
  xx.to_string() +
  "/4, IK " +
  ik.to_string() +
  "/4"
}
