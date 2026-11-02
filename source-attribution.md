# 来源说明

本文件说明 noise.mbt 参考、依赖和收录的第三方材料。项目许可证是 Apache-2.0，见根目录 `LICENSE`。

## 规范

Noise 握手规则以 Noise Protocol Framework 修订 34 为准：

- 名称：The Noise Protocol Framework
- 链接：https://noiseprotocol.org/noise.html
- 使用范围：`CipherState`、`SymmetricState`、`HandshakeState`，单向、基础和延迟握手模式，`pskN` 修饰符，以及 25519、448、ChaChaPoly、AESGCM、SHA256、SHA512、BLAKE2s、BLAKE2b。

## snow

- 名称：snow
- 作者：Jake McGinty 及其他贡献者
- 链接：https://github.com/mcginty/snow
- 许可证：Apache-2.0 OR MIT
- 参考范围：状态机拆分（`CipherState`、`SymmetricState`、`HandshakeState`、`Builder`、传输阶段）和 Cacophony 向量的使用方式。
- 不是逐行翻译。握手、模式解析和传输代码是按规范重新写的 MoonBit 实现。

## mooncry

- 名称：mooncry
- 模块：`cc06b/mooncry@0.95.0`
- 链接：https://github.com/cc06b/mooncry
- 许可证：Apache-2.0
- 使用范围：X25519、X448、ChaCha20-Poly1305、AES-256-GCM、SHA-256、SHA-512、HMAC-SHA256、HMAC-SHA512。
- 这些原语已用 RFC 7748、RFC 8439、NIST AES-GCM 空明文、FIPS SHA-256 / SHA-512 和 RFC 4231 向量在本仓库测试中核对。

## 仓库内实现

- BLAKE2s-256：`blake2s.mbt`，依据 RFC 7693。
- BLAKE2b-512：`blake2b.mbt`，依据 RFC 7693。
- HMAC-BLAKE2s 与 HMAC-BLAKE2b：`crypto.mbt`，依据 RFC 2104。mooncry 的 keyed BLAKE2 不是 HMAC，不能用于 Noise。
- 未使用 mooncry 0.95.0 的 `blake2s` 和 `blake2b`。该版本在输入长度是分组的正整数倍时会多压缩一个空分组。

## 测试向量

- 名称：Cacophony Noise test vectors
- 原始项目：https://github.com/centromere/cacophony
- 原始许可证：Unlicense
- 收录来源：snow 的 `tests/vectors/cacophony.txt`（snow 许可证 Apache-2.0 OR MIT）
- 本仓库文件：`vectors/cacophony.json`、`vectors/ATTRIBUTION.md`、`vectors_data.mbt`
- 范围：不含 `fail`、`fallback`、`hybrid` 的全部 Cacophony 向量，共 944 条。
- 紧凑 JSON 的 SHA-256：`e2f1ddfbf5297125bdd10558ba7701fbae5d5b2b423b65d022d013ad066aacd0`
