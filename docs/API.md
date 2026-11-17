# 公开 API

模块 `ppyj663/noise`，版本字符串 `version` 与 `moon.mod` 同为 `0.2.0`。下面的例子假设：

```moonbit
import "ppyj663/noise"
import "moonbitlang/core/encoding/utf8"
```

错误类型是 `NoiseError`。库外可以捕获这些变体，不能在库外构造它们：

| 变体 | 何时出现 |
| --- | --- |
| `DecryptFail` | AEAD 认证失败。nonce 不增加，明文不返回。握手会被标成失败 |
| `NonceExhausted` | `n` 已经是 `2^64-1` |
| `MissingKey` | 模式需要的静态或预消息公钥没有提供 |
| `MissingRandom` | 需要临时密钥，但既没有预设私钥也没有随机源 |
| `WrongTurn` | 在不该发送或接收的一方调用 |
| `HandshakeFinished` | 握手已经结束，或还没结束就取传输状态 |
| `HandshakeFailed` | 这一轮已经失败，对象应丢弃 |
| `TruncatedMessage` | 握手消息比模式要求的更短 |
| `MessageTooLong` | 握手或传输消息超过 65535 字节。传输在加密前拒绝 |
| `InvalidInput(String)` | 长度、协议名或可选的全零 DH 策略 |
| `Unsupported(String)` | 不认识的算法名，或当前不能应用的修饰符以外的名字 |

## 安装后的最小握手

```moonbit
let init = @noise.Builder::new("Noise_XX_25519_ChaChaPoly_SHA256")
  .prologue(@utf8.encode("app-v1"))
  .local_private_key(init_static)
  .local_ephemeral_private(init_ephemeral)
  .build_initiator(random?)
let resp = @noise.Builder::new("Noise_XX_25519_ChaChaPoly_SHA256")
  .prologue(@utf8.encode("app-v1"))
  .local_private_key(resp_static)
  .local_ephemeral_private(resp_ephemeral)
  .build_responder(random?)
let m1 = init.write_message(payload1)
let _p1 = resp.read_message(m1)
let m2 = resp.write_message(payload2)
let _p2 = init.read_message(m2)
let m3 = init.write_message(payload3)
let _p3 = resp.read_message(m3)
let a = init.into_transport()
let b = resp.into_transport()
let ct = a.write_message(@utf8.encode("ping"))
let pt = b.read_message(ct)
a.rekey_send()
b.rekey_recv()
```

`random` 的类型是 `(Int32) -> Bytes`。传入 `None` 时，每个 `e` 必须已经用 `local_ephemeral_private` 提供。生产环境应传入 CSPRNG，并且每次握手使用新的临时私钥。

`into_transport` 之后，`send` 是本方发出的方向，`recv` 是对方发来的方向。发起方的 `send` 对应 `Split` 的 `c1`。关联数据为空。`set_receiving_nonce` 只设置接收 nonce，不记录重放。

## 谁先发送

`initiator_sends_at(index)` 用于握手和之后的传输序号。`N` / `K` / `X` 始终由发起方发送。`fallback` 时响应方发送第 0 条。`remote_ephemeral_public` 用来安装对方已经通过别的途径收到的临时公钥。

## DH 策略

默认 `DhOutputPolicy::ReturnOutput`。`builder.reject_all_zero_dh()` 改成全零输出报 `InvalidInput`。详见 README 的安全限制。完成握手不等于身份认证。

## 帧

库不负责 TCP，也不依赖 async。`example/pipe` 是内存管道。`example/tcp` 是另一个模块，在 Noise 消息外加 2 字节大端长度，并拒绝超过 65535 字节的消息。发布后的库包没有这个模块。
