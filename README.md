# noise.mbt

Noise Protocol Framework 的 MoonBit 握手库。实现规范中的 `CipherState`、`SymmetricState`、`HandshakeState`，以及传输阶段的加密、解密和 `Rekey`。

内置握手模式覆盖规范里的单向模式（N、K、X）、基础交互模式（NN、NK、NX、XN、XK、XX、KN、KK、KX、IN、IK、IX）和延迟模式（NK1、XX1、X1X1 等）。`psk0`、`psk2` 这类修饰符会按规范插入 `psk`。算法组合是 **DH 25519 / 448**、**ChaChaPoly**、**AESGCM**、**SHA256 / SHA512**、**BLAKE2s / BLAKE2b**。

This library is a MoonBit implementation of the Noise Protocol Framework handshake. It covers the three core state machines, one-way, fundamental, and deferred patterns, `pskN`, `fallback`, and transport encryption with rekey.

## 安装

仓库地址：<https://github.com/ppyj663/noise.mbt>。模块名是 `ppyj663/noise`。

库根只依赖 [cc06b/mooncry](https://github.com/cc06b/mooncry) `0.95.0`（Apache-2.0）。不依赖 `moonbitlang/async`。在 moonc 0.10.17 上应能执行下面的库命令；本仓库在 moonc 0.10.20 上复测。

```bash
git clone https://github.com/ppyj663/noise.mbt
cd noise.mbt
moon update
moon check --deny-warn --target native
moon test --target native
moon run --target native example
moon run --target native example/pipe
```

TCP 不在这些命令里。它是 `example/tcp` 里的独立模块，见下文。

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

`moon run example` 的传输阶段还会做一次 `rekey`，并打印握手哈希。`moon run example/pipe` 在同一进程里串起 XX 和 XXfallback，它不是 TCP。

TCP 回环在独立模块 `example/tcp`，需要带 `moonbitlang/core/async` 的工具链。moonc 0.10.17 的 core 没有这个导入，所以该示例注明 moonc 0.10.19 或更新；这里用 moonc 0.10.20 跑通。它不进入库根的 `moon check` / `moon test`。

```bash
moon -C example/tcp update
moon -C example/tcp check --deny-warn --target native
moon -C example/tcp test --target native --package ppyj663/noise-tcp-example
moon -C example/tcp run --target native .
```

`example/tcp/moon.work` 的成员是 `.` 和 `../..`。因此 `ppyj663/noise@0.2.0` 解析到本仓库的库，而不是 mooncakes。这是文档中的 workspace 本地依赖：<https://docs.moonbitlang.com/en/latest/toolchain/moon/module.html#dependency-management>。`moon.mod` 的 import 不能写本地 path，所以没有把 path 写进库根。

该示例在 `127.0.0.1` 的临时端口上收发，每条 Noise 消息前有 16 位大端长度，超过 65535 字节会在写入套接字之前拒绝。生产密钥必须来自 CSPRNG。发布后的 `ppyj663/noise` 不包含这个目录，也不依赖 async。要跑 TCP，用仓库，不要用已发布的库包。

## API 概览

| 类型 | 作用 |
| --- | --- |
| `Builder` | 解析 `Noise_<pattern>_<dh>_<cipher>_<hash>`，设置 prologue、静态密钥、对方静态公钥、预消息临时公钥、本方临时私钥、PSK。`reject_all_zero_dh` 是可选策略 |
| `Pattern` | `by_name("XX")` 或 `parse` 一段模式字符串。`Builder::from_pattern` 把自定义模式配到协议名上 |
| `Handshake` | `write_message` / `read_message`。完成后 `handshake_hash` 与 `into_transport` |
| `Transport` | 空关联数据的传输加密。`rekey_send` / `rekey_recv` 不重置 nonce。`set_receiving_nonce` 对应规范 11.4 |
| `CipherState` | 规范 5.1：`initialize_key`、`encrypt_with_ad`、`decrypt_with_ad`、`rekey`、`set_nonce` |
| `SymmetricState` | 规范 5.2：`initialize`、`mix_key`、`mix_hash`、`mix_key_and_hash`、`split` |

协议名例子：`Noise_XX_25519_ChaChaPoly_SHA256`、`Noise_NNpsk0_25519_AESGCM_SHA512`、`Noise_IK_448_ChaChaPoly_BLAKE2b`。

自定义模式示例（NX 不在内置名字里，但状态机可以直接跑）：

```text
-> e
<- e, ee, s, es
```

`...` 之前的行是 pre-message。行内记号可以是 `e`、`s`、`ee`、`es`、`se`、`ss`、`psk`。

## 支持的模式与算法

| 项目 | 支持 |
| --- | --- |
| 握手模式 | N、K、X、NN、NK、NX、XN、XK、XX、KN、KK、KX、IN、IK、IX，以及 NK1、NX1、X1N、X1K、XK1、X1K1、X1X、XX1、X1X1、K1N、K1K、KK1、K1K1、K1X、KX1、K1X1、I1N、I1K、IK1、I1K1、I1X、IX1、I1X1。另支持 `pskN` 修饰符和 `Pattern::parse` |
| DH | 25519（32 字节）、448（56 字节），均为 RFC 7748 |
| 加密 | ChaChaPoly（RFC 8439，nonce 小端）、AESGCM（AES-256-GCM，nonce 大端） |
| 哈希 | SHA256、BLAKE2s（32 字节）、SHA512、BLAKE2b（64 字节，密钥截取前 32 字节） |

ChaChaPoly 的 96 位 nonce 是 4 个 0 再加 `n` 的小端编码。AESGCM 使用同样的 4 个 0，但 `n` 是大端。`n == 2^64-1` 保留给 `Rekey`，这时 `EncryptWithAd` / `DecryptWithAd` 返回 `NonceExhausted`。认证失败不增加 nonce，并返回 `DecryptFail`。

## 测试

最近一次完整 `moon test --target native` 的通过数以 `docs/VERIFICATION.md` 和测试日志为准，不要把旧的 “40 项” 当成当前数字。覆盖包括：

- RFC 7748 的 X25519 / X448 运算向量、RFC 8439 ChaCha20-Poly1305、NIST AES-GCM 空明文、FIPS SHA-256 / SHA-512、RFC 4231 HMAC、RFC 7693 BLAKE2s / BLAKE2b
- BLAKE2s、BLAKE2b 在整数个分组上的向量，以及对应的 HMAC
- CipherState 的往返、篡改、rekey、nonce 耗尽
- 一条固定传输密文的每个更短前缀、空消息、65535 字节上限、超限不消耗 nonce、认证失败后握手作废且不返回明文、重复读取、nonce 耗尽、rekey。这不是“所有随机输入”或“所有截断输入”的全称命题
- 全零和列出的低阶 X25519 公钥、全零 X448 公钥、错误长度。默认返回全零 DH 输出。`reject_all_zero_dh` 可选拒绝，这不是身份认证
- 自定义模式字符串、`psk`、`XXfallback`、`NNfallback`、`XXfallback+psk0`，以及 `scripts/fallback_oracle.py` 的预期 JSON
- 内存管道 `example/pipe`。TCP 的 3 项测试属于 `example/tcp`，不计入库根的 `moon test`

Cacophony 中本库执行的组合是 **944** 条向量、**5664** 条消息比较、**0** 条跳过。`cacophony_report()` 把这三个数分开断言，不靠一个笼统的通过字符串代替计数。单向模式 `N` / `K` / `X` 的传输消息只由发起方发送。`NNfallback` 虽然只剩一条握手消息，但那条由响应方发送，下一条传输由发起方发送。

向量文件是 `vectors/cacophony.json`，来源见 `vectors/ATTRIBUTION.md`。测试实际加载的是 `vectors_data.mbt` 里的紧凑 JSON，SHA-256 为 `e2f1ddfbf5297125bdd10558ba7701fbae5d5b2b423b65d022d013ad066aacd0`。

`fallback` 把发起方第一条可作预消息的报文（`e`、`s` 或 `e, s`）改成发起方预消息，并由响应方发送下一条。DH 记号不交换。协议名会进入 `h`，所以 `XXfallback` 不是 XX 的续传。响应方必须事先调用 `remote_ephemeral_public`。可复现预言机是 `scripts/fallback_oracle.py`，预期输出是 `scripts/fallback_oracle.json`（cryptography 41.0.7）。`python3 scripts/fallback_oracle.py --check` 会重算并比对。

## 安装与使用

```bash
git clone https://github.com/ppyj663/noise.mbt
cd noise.mbt
moon update
moon check --deny-warn --target native
moon check --target wasm-gc
moon test --target native
moon fmt --check
moon info
moon run --target native example
moon run --target native example/pipe
python3 scripts/fallback_oracle.py --check
```

库的直接依赖只有 `cc06b/mooncry@0.95.0`。模块名是 `ppyj663/noise`。`.moonignore` 排除 `example/tcp/`，所以 `moon package` 的文件列表不包含 TCP 模块，消费者不会因此装上 async。

发布之后，依赖方使用已发布的 `ppyj663/noise`，仍然只需要 mooncry。TCP 示例不会出现在那个包里。仓库里的 TCP 命令是：

```bash
moon -C example/tcp update
moon -C example/tcp test --target native --package ppyj663/noise-tcp-example
moon -C example/tcp run --target native .
```

GitHub Actions 把库和 TCP 分成两个 job。库 job 不调用 `example/tcp`。wasm-gc 在库 job 里只做 check。库 job 在官方最新稳定工具链（Ubuntu、Windows）以及已核实可下载的 `0.10.17+d971670cd`（Ubuntu）上运行；TCP job 只在带 `core/async` 的官方最新稳定工具链上运行（Ubuntu、Windows），不会在 0.10.17 上跑。安装脚本、版本钉死方式和 Windows 上 `moonc` 命令行过长的说明见 [docs/TOOLCHAIN.md](docs/TOOLCHAIN.md)。本地可用 `scripts/accept.sh` 或 `scripts/accept.ps1` 按当前工具链复测，失败返回非 0。`ppyj663/noise@0.2.0` 已发布到 mooncakes，本轮仓库改动不再覆盖该版本。

## 基准

`scripts/bench.sh` 用 `moon run --target native --release bench` 计时。时钟是 MoonBit `monotonic_clock`，单位微秒。每个项目先记 2 次热身，再记 9 次样本；`samples.jsonl` 里每一行是一次热身、一次样本或一行汇总，不是只有汇总。项目包括 NN / XX / IK 的 ChaChaPoly 与 AESGCM 空握手，两种加密下 64 / 1024 / 8192 字节的传输加密和解密，以及 ChaCha 的 rekey。密钥由固定标签做 SHA-256，只给测试和基准用。`meta.json` 记录基线 commit、工作区是否脏、源码树 SHA-256、工具链和 CPU。补丁 SHA-256 在补丁封存后的验证日志里，不写进被补丁包含的 meta，避免自引用。这些数字只描述跑出它们的那一台机器。

## 安全限制

本库没有经过独立安全审计。

Noise rev 34 第 12.1 和 12.2 节规定，无效公钥的 `DH` 输出是全零。默认实现返回这个输出，以保持和规范主规则以及现有实现的一致。同一节允许检测到全零后改报错，但写明这样做增加差异、并不提高安全性。`Builder::reject_all_zero_dh` 提供这个可选项。无论选哪一种，握手成功都不表示对方身份已被接受。第 14 节把“远程静态公钥是否可信”留给应用，例如证书、预共享名单或 pinning。全零 DH 也不能被当成“对方知道某个公钥”。NN 没有静态密钥，完成 NN 只说明双方算出了相同的临时 DH，不是身份认证。

不提供 CSPRNG，不记录已用 nonce，重放防护由调用方负责。认证失败会丢弃握手或拒绝传输明文。`n == 2^64-1` 不能再加密。传输明文超过 65519 字节会在加密前拒绝，避免白白消耗 nonce。

出处：<https://noiseprotocol.org/noise.html> ，修订 34，2026-11-17 抓取。第 4.1 节要求无效公钥要么给出只依赖公钥的输出，要么报错。第 12.1 / 12.2 节选择全零输出，并劝阻改为报错。第 14 节 “Misusing public keys as secrets” 说明无效公钥会造成可预测的全零 DH。RFC 7748 第 6.1 和 7 节只说明曲线运算和 cofactor，不代替上述 Noise 条款。

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
├── scripts/accept.sh       当前工具链验收（Unix）
├── scripts/accept.ps1      当前工具链验收（Windows）
├── docs/TOOLCHAIN.md       官方稳定版本与 Windows 排障
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
| X25519、X448 | mooncry（内部会 clamp） |
| ChaCha20-Poly1305、AES-256-GCM | mooncry |
| SHA-256、SHA-512、HMAC-SHA256、HMAC-SHA512 | mooncry |
| BLAKE2s-256、BLAKE2b-512 | **本仓库** |
| HMAC-BLAKE2s、HMAC-BLAKE2b | **本仓库**（RFC 2104，不是 BLAKE2 的 keyed 模式） |

mooncry 0.95.0 的 `blake2s` / `blake2b` 在输入长度是分组的正整数倍时，会把最后一个满分组当成非结束分组，再多压缩一个空的结束分组。Noise 的 `MixHash` 和 `Split` 会走到这个长度，因此这两条哈希在本仓库实现。

仍不支持、会返回 `Unsupported` 的名字包括 `hfs` 以及第一条消息不能当成预消息的 `fallback`（例如 `NKfallback`）。`pskN` 与 `fallback` 按名字里的顺序应用。`XXpsk0+fallback` 不合法，因为插入 `psk` 后的第一条消息不再是预消息。多个 PSK 用 `Builder::psks` 按修饰符出现顺序提供。

## 移植来源与许可证

本仓库保持 **Apache-2.0**，见 `LICENSE` 与 `NOTICE`。

握手状态机的划分参考了 [mcginty/snow](https://github.com/mcginty/snow)（Rust）。snow 以 **Apache-2.0 OR MIT** 授权，版权归 Jake McGinty 及其他贡献者。本库是按 Noise 规范重新写出的 MoonBit 实现，不是 snow 源码的逐行翻译。

密码学依赖是 [cc06b/mooncry](https://github.com/cc06b/mooncry)，**Apache-2.0**，版权 2026 Solo Crypto Contributors。

Cacophony 测试向量经 snow 的 `tests/vectors/cacophony.txt` 收录，原始项目是 [centromere/cacophony](https://github.com/centromere/cacophony)（Unlicense）。

## English summary

`noise.mbt` is a MoonBit Noise handshake library: one-way, fundamental, and deferred patterns, `pskN`, `fallback` (including `XXfallback`), X25519, X448, ChaChaPoly, AES-GCM, SHA-256, SHA-512, BLAKE2s, and BLAKE2b. It is not a claim to be the only such library, and it has not had an independent security audit. `moon test` checks the 944 vendored Cacophony vectors plus an independent Python oracle for `XXfallback`. BLAKE2s and BLAKE2b are implemented in this repository.
