# noise.mbt

Noise Protocol Framework 的 MoonBit 握手库。实现规范中的 `CipherState`、`SymmetricState`、`HandshakeState`，以及传输阶段的加密、解密和 `Rekey`。

内置握手模式是 **NN、NK、XX、IK**。模式由模式字符串解析，因此可以按同样的写法增加其它模式。内置算法组合是 **DH 25519**、**ChaChaPoly**、**AESGCM**、**SHA256**、**BLAKE2s**。

This library is a MoonBit implementation of the Noise Protocol Framework handshake. It covers the three core state machines, the patterns NN / NK / XX / IK, and transport encryption with rekey. Patterns are parsed from pattern strings so more patterns can be added without changing the state machine.

## 安装

仓库地址：<https://github.com/ppyj663/noise.mbt>。模块名是 `ppyj663/noise`。

```bash
git clone https://github.com/ppyj663/noise.mbt
cd noise.mbt
moon check
moon test
moon run example
```

依赖 [cc06b/mooncry](https://github.com/cc06b/mooncry) `0.95.0`（Apache-2.0）。`moon.mod` 已经写好这个依赖，`moon test` 会自动下载。

## 快速开始

下面两方完成 `Noise_XX_25519_ChaChaPoly_SHA256`，再各发一条传输消息。完整可运行版本在 `example/main.mbt`（`moon run example`）。演示密钥由 SHA-256 标签导出，方便得到稳定输出。生产环境请把 CSPRNG 产生的 32 字节传给 `build_initiator` / `build_responder`。

```moonbit
let prologue = @utf8.encode("noise.mbt example")
let initiator = @noise.Builder::new("Noise_XX_25519_ChaChaPoly_SHA256")
  .prologue(prologue)
  .local_private_key(init_static)
  .local_ephemeral_private(init_ephemeral)
  .build_initiator(None)
let responder = @noise.Builder::new("Noise_XX_25519_ChaChaPoly_SHA256")
  .prologue(prologue)
  .local_private_key(resp_static)
  .local_ephemeral_private(resp_ephemeral)
  .build_responder(None)

let m1 = initiator.write_message(@utf8.encode("你好，我是发起方"))
let _p1 = responder.read_message(m1)
let m2 = responder.write_message(@utf8.encode("你好，我是响应方"))
let _p2 = initiator.read_message(m2)
let m3 = initiator.write_message(@utf8.encode("握手第三步"))
let _p3 = responder.read_message(m3)

let send = initiator.into_transport()
let recv = responder.into_transport()
let ct = send.write_message(@utf8.encode("传输消息：ping"))
let _pt = recv.read_message(ct)
```

`moon run example` 的传输阶段还会做一次 `rekey`，并打印握手哈希。

## API 概览

| 类型 | 作用 |
| --- | --- |
| `Builder` | 解析 `Noise_<pattern>_25519_<cipher>_<hash>`，设置 prologue、静态密钥、对方静态公钥、本方临时私钥、PSK |
| `Pattern` | `by_name("XX")` 或 `parse` 一段模式字符串。`Builder::from_pattern` 把自定义模式配到协议名上 |
| `Handshake` | `write_message` / `read_message`。完成后 `handshake_hash` 与 `into_transport` |
| `Transport` | 空关联数据的传输加密。`rekey_send` / `rekey_recv` 不重置 nonce。`set_receiving_nonce` 对应规范 11.4 |
| `CipherState` | 规范 5.1：`initialize_key`、`encrypt_with_ad`、`decrypt_with_ad`、`rekey`、`set_nonce` |
| `SymmetricState` | 规范 5.2：`initialize`、`mix_key`、`mix_hash`、`mix_key_and_hash`、`split` |

协议名例子：`Noise_NN_25519_ChaChaPoly_SHA256`、`Noise_IK_25519_AESGCM_BLAKE2s`。

自定义模式示例（NX 不在内置名字里，但状态机可以直接跑）：

```text
-> e
<- e, ee, s, es
```

`...` 之前的行是 pre-message。行内记号可以是 `e`、`s`、`ee`、`es`、`se`、`ss`、`psk`。

## 支持的模式与算法

| 项目 | 支持 |
| --- | --- |
| 握手模式 | NN、NK、XX、IK，以及 `Pattern::parse` 接受的模式字符串 |
| DH | 25519（X25519，RFC 7748） |
| 加密 | ChaChaPoly（RFC 8439，nonce 小端）、AESGCM（AES-256-GCM，nonce 大端） |
| 哈希 | SHA256、BLAKE2s（HASHLEN = 32，BLOCKLEN = 64） |

ChaChaPoly 的 96 位 nonce 是 4 个 0 再加 `n` 的小端编码。AESGCM 使用同样的 4 个 0，但 `n` 是大端。`n == 2^64-1` 保留给 `Rekey`，这时 `EncryptWithAd` / `DecryptWithAd` 返回 `NonceExhausted`。认证失败不增加 nonce，并返回 `DecryptFail`。

## 测试

`moon test` 当前 **23** 项全部通过，其中包括：

- RFC 7748 X25519、RFC 8439 ChaCha20-Poly1305、NIST AES-GCM 空明文、FIPS SHA-256、RFC 4231 HMAC-SHA256、RFC 7693 BLAKE2s
- BLAKE2s 在 64 与 128 字节（整数个分组）上的向量，以及 HMAC-BLAKE2s
- CipherState 的往返、篡改、rekey、nonce 耗尽
- 错误路径：乱序读写、篡改密文、超过 65535 字节、认证失败后握手作废
- 自定义模式字符串与带 `psk` 记号的往返
- 下方 16 条 Cacophony 向量（每条 6 个消息，含握手后的传输消息）

| 协议 | 向量 | 消息 | 结果 |
| --- | ---: | ---: | --- |
| Noise_NN_25519_ChaChaPoly_SHA256 | 1 | 6 | 通过 |
| Noise_NN_25519_ChaChaPoly_BLAKE2s | 1 | 6 | 通过 |
| Noise_NN_25519_AESGCM_SHA256 | 1 | 6 | 通过 |
| Noise_NN_25519_AESGCM_BLAKE2s | 1 | 6 | 通过 |
| Noise_NK_25519_ChaChaPoly_SHA256 | 1 | 6 | 通过 |
| Noise_NK_25519_ChaChaPoly_BLAKE2s | 1 | 6 | 通过 |
| Noise_NK_25519_AESGCM_SHA256 | 1 | 6 | 通过 |
| Noise_NK_25519_AESGCM_BLAKE2s | 1 | 6 | 通过 |
| Noise_XX_25519_ChaChaPoly_SHA256 | 1 | 6 | 通过 |
| Noise_XX_25519_ChaChaPoly_BLAKE2s | 1 | 6 | 通过 |
| Noise_XX_25519_AESGCM_SHA256 | 1 | 6 | 通过 |
| Noise_XX_25519_AESGCM_BLAKE2s | 1 | 6 | 通过 |
| Noise_IK_25519_ChaChaPoly_SHA256 | 1 | 6 | 通过 |
| Noise_IK_25519_ChaChaPoly_BLAKE2s | 1 | 6 | 通过 |
| Noise_IK_25519_AESGCM_SHA256 | 1 | 6 | 通过 |
| Noise_IK_25519_AESGCM_BLAKE2s | 1 | 6 | 通过 |

合计 **16/16** 条向量，**96/96** 条消息。`verify_cacophony_vectors()` 返回 `NN 4/4, NK 4/4, XX 4/4, IK 4/4`。

向量文件是 `vectors/cacophony.json`，来源见 `vectors/ATTRIBUTION.md`。测试实际加载的是 `vectors_data.mbt` 里的紧凑 JSON，SHA-256 为 `abf46916f6dd7fb38e1d7476cb5c42c1f91afcdd3c3132f84542f8c1cb8de7f9`。

## 仓库结构与规模

默认分支是 `main`。完成的源码、README、许可证和提交历史都在这条分支上。

```text
noise.mbt/
├── README.md
├── LICENSE                 Apache-2.0
├── NOTICE
├── CHANGELOG.md
├── source-attribution.md   规范、snow、mooncry、向量来源
├── moon.mod
├── moon.pkg
├── *.mbt                   库实现与测试
├── example/main.mbt        XX 握手示例
├── vectors/                Cacophony 适用向量与署名
├── scripts/check_repo.sh   本地仓库自查
└── .github/workflows/ci.yml
```

`scripts/check_repo.sh` 统计的有效行数不含空行和 `//`、`///` 注释，也不把嵌入的向量文本算进实现。章程里的 4~10k 行是参考范围。当前实现规模以该脚本的输出为准。

来源、许可证和移植范围见 [source-attribution.md](source-attribution.md)。

## 架构

```text
Builder / Pattern::parse
        |
        v
HandshakeState ---- SymmetricState ---- CipherState ---- AEAD
        |                  |                |
        |                  HKDF(HMAC)       nonce || rekey
        v
Transport (Split 得到的两个 CipherState)
```

- `crypto.mbt` 把 Noise 的 `ENCRYPT` / `DECRYPT` / `DH` / `HASH` / `HMAC` 接到具体算法。
- `symmetricstate.mbt` 按规范实现 HKDF（`ck` 作 HMAC 密钥，`ikm` 作消息，再按 `0x01`、`0x02`、`0x03` 展开）。
- `handshake.mbt` 按模式记号执行 `e`、`s`、`ee`、`es`、`se`、`ss`、`psk`。`Split` 之后，发起方用 `c1` 发送、`c2` 接收；响应方相反。
- 解密失败会把握手标成失败，调用方应丢掉这个 `Handshake`。

## 实现说明与规范差距

已用 mooncry 0.95.0（Apache-2.0），并用标准向量核对过：

| 原语 | 来源 |
| --- | --- |
| X25519 | mooncry `x25519` / `x25519_public_key`（内部会 clamp） |
| ChaCha20-Poly1305 | mooncry |
| AES-256-GCM | mooncry |
| SHA-256、HMAC-SHA256 | mooncry |
| BLAKE2s-256 | **本仓库** `blake2s.mbt` |
| HMAC-BLAKE2s | **本仓库**（RFC 2104，不是 BLAKE2 的 keyed 模式） |

mooncry 0.95.0 的 `blake2s` 在输入长度是 64 的正整数倍时，会把最后一个满分组当成非结束分组，再多压缩一个空的结束分组。Noise 的 `MixHash(h \|\| 公钥)` 经常正好是 64 字节，因此不能用它。空串、`"abc"`、64 字节和 128 字节向量都由本仓库实现通过。

尚未实现、调用对应协议名会返回 `Unsupported`：

- DH `448`，哈希 `SHA512` / `BLAKE2b`
- 内置名字只有 NN、NK、XX、IK。其它基础模式需要自己写模式字符串，再用 `Builder::from_pattern`
- 不会自动展开 `psk0`、`psk2` 这类修饰符。模式字符串里的 `psk` 记号可以跑，多个 `psk` 记号共用 `Builder::psk` 设置的那一个 32 字节密钥
- 不实现 `fallback`
- 全零 DH 输出按规范建议的做法原样返回，不额外报错
- 不提供 CSPRNG，也不记录已用 nonce。重放防护由调用方在 `set_receiving_nonce` 之外自己做（规范 11.4）

## 移植来源与许可证

本仓库保持 **Apache-2.0**，见 `LICENSE` 与 `NOTICE`。

握手状态机的划分参考了 [mcginty/snow](https://github.com/mcginty/snow)（Rust）。snow 以 **Apache-2.0 OR MIT** 授权，版权归 Jake McGinty 及其他贡献者。本库是按 Noise 规范重新写出的 MoonBit 实现，不是 snow 源码的逐行翻译。

密码学依赖是 [cc06b/mooncry](https://github.com/cc06b/mooncry)，**Apache-2.0**，版权 2026 Solo Crypto Contributors。

Cacophony 测试向量经 snow 的 `tests/vectors/cacophony.txt` 收录，原始项目是 [centromere/cacophony](https://github.com/centromere/cacophony)（Unlicense）。

## English summary

`noise.mbt` implements the Noise handshake for MoonBit: `CipherState`, `SymmetricState`, `HandshakeState`, patterns NN / NK / XX / IK (plus pattern strings), X25519, ChaChaPoly, AES-GCM, SHA-256, and BLAKE2s. Transport messages use an empty associated-data field and support `Rekey`. `moon test` passes the 16 applicable Cacophony vectors (6 messages each). BLAKE2s-256 and HMAC-BLAKE2s live in this repo because mooncry 0.95.0's BLAKE2s mishandles inputs whose length is a positive multiple of 64 bytes. See the sections above for the API, the spec gaps, and the snow / mooncry / Cacophony credits.
