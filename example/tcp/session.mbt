///|
fn demo_key(label : Bytes) -> Bytes {
  @noise.sha256(label)
}

///|
async fn responder(server : @socket.TcpServer) -> Unit {
  let (conn, _) = server.accept()
  defer conn.close()
  let hs = @noise.Builder::new("Noise_XX_25519_ChaChaPoly_SHA256")
    .prologue(@utf8.encode("tcp loopback"))
    .local_private_key(demo_key(b"tcp-r-s"))
    .local_ephemeral_private(demo_key(b"tcp-r-e"))
    .build_responder(None)
  let _ = hs.read_message(read_noise_frame(conn))
  write_noise_frame(
    conn,
    hs.write_message(@utf8.encode("你好，我是响应方")),
  )
  let _ = hs.read_message(read_noise_frame(conn))
  let transport = hs.into_transport()
  let ping = transport.read_message(read_noise_frame(conn))
  if @utf8.decode(ping) != "传输：ping" {
    raise BadPayload
  }
  write_noise_frame(
    conn,
    transport.write_message(@utf8.encode("传输：pong")),
  )
}

///|
async fn initiator(addr : @socket.Addr) -> String {
  let conn = @socket.Tcp::connect(addr)
  defer conn.close()
  let hs = @noise.Builder::new("Noise_XX_25519_ChaChaPoly_SHA256")
    .prologue(@utf8.encode("tcp loopback"))
    .local_private_key(demo_key(b"tcp-i-s"))
    .local_ephemeral_private(demo_key(b"tcp-i-e"))
    .build_initiator(None)
  write_noise_frame(
    conn,
    hs.write_message(@utf8.encode("你好，我是发起方")),
  )
  let bob = @utf8.decode(hs.read_message(read_noise_frame(conn)))
  write_noise_frame(conn, hs.write_message(@utf8.encode("握手第三步")))
  let transport = hs.into_transport()
  write_noise_frame(
    conn,
    transport.write_message(@utf8.encode("传输：ping")),
  )
  let pong = @utf8.decode(transport.read_message(read_noise_frame(conn)))
  "tcp 127.0.0.1 xx | bob:" + bob + " | pong:" + pong
}

///|
/// One XX handshake and two transport messages over a real TCP loopback.
/// The listener is `127.0.0.1` with an ephemeral port. Each Noise message is
/// preceded by a 16-bit big-endian length.
pub async fn run_tcp_loopback() -> String {
  let box = [""]
  @async.with_task_group(root => {
    let server = @socket.TcpServer(@socket.Addr::parse("127.0.0.1:0"))
    let addr = server.addr
    defer server.close()
    root.spawn_bg(() => responder(server))
    @async.sleep(20)
    box[0] = initiator(addr)
  })
  box[0]
}

///|
/// A peer that advertises 4 payload bytes and then closes. `read_exactly`
/// must fail before any plaintext is produced.
pub async fn run_tcp_short_frame() -> String {
  let box = [""]
  @async.with_task_group(root => {
    let server = @socket.TcpServer(@socket.Addr::parse("127.0.0.1:0"))
    let addr = server.addr
    defer server.close()
    root.spawn_bg(() => {
      let (conn, _) = server.accept()
      defer conn.close()
      try {
        let _ = read_noise_frame(conn)
        box[0] = "accepted"
      } catch {
        @io.ReaderClosed => box[0] = "short-frame"
        err => raise err
      }
    })
    @async.sleep(20)
    let conn = @socket.Tcp::connect(addr)
    defer conn.close()
    conn.write(b"\x00\x04")
  })
  box[0]
}
