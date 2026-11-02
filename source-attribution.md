# 来源说明

本文件说明 noise.mbt 参考、依赖和收录的第三方材料。项目许可证是 Apache-2.0，见根目录 `LICENSE`。

## 规范

Noise 握手规则以 Noise Protocol Framework 修订 34 为准：

- 名称：The Noise Protocol Framework
- 链接：https://noiseprotocol.org/noise.html
- 使用范围：`CipherState`、`SymmetricState`、`HandshakeState` 的步骤，NN / NK / XX / IK 的模式定义，以及 25519、ChaChaPoly、AESGCM、SHA256、BLAKE2s 的算法参数。

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
- 使用范围：X25519、ChaCha20-Poly1305、AES-256-GCM、SHA-256、HMAC-SHA256。
- 这些原语已用 RFC 7748、RFC 8439、NIST AES-GCM 空明文、FIPS SHA-256 和 RFC 4231 向量在本仓库测试中核对。

## 仓库内实现

- BLAKE2s-256：`blake2s.mbt`，依据 RFC 7693。
- HMAC-BLAKE2s：`crypto.mbt`，依据 RFC 2104。mooncry 的 keyed BLAKE2s 不是 HMAC，不能用于 Noise。
- 未使用 mooncry 0.95.0 的 `blake2s`。该版本在输入长度是 64 的正整数倍时会多压缩一个空分组，而 Noise 的 `MixHash(h || 公钥)` 经常正好是 64 字节。

## 测试向量

- 名称：Cacophony Noise test vectors
- 原始项目：https://github.com/centromere/cacophony
- 原始许可证：Unlicense
- 收录来源：snow 的 `tests/vectors/cacophony.txt`（snow 许可证 Apache-2.0 OR MIT）
- 本仓库文件：`vectors/cacophony.json`、`vectors/ATTRIBUTION.md`、`vectors_data.mbt`
- 范围：只保留 NN、NK、XX、IK 与 25519、ChaChaPoly、AESGCM、SHA256、BLAKE2s 的组合，共 16 条。
- 紧凑 JSON 的 SHA-256：`abf46916f6dd7fb38e1d7476cb5c42c1f91afcdd3c3132f84542f8c1cb8de7f9`
