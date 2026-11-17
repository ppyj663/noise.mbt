# 更新日志

## 0.2.0

- 实现 Noise 10.2 的 `fallback`。`scripts/fallback_oracle.py`（cryptography 41.0.7）给出 `XXfallback`、`NNfallback` 和 `XXfallback+psk0` 的预期 JSON。
- 增加内存管道 `example/pipe`。TCP 回环在独立模块 `example/tcp`，用 workspace 引用本地库。库根不依赖 `moonbitlang/async`，发布包用 `.moonignore` 排除该目录。TCP 需要 moonc 0.10.19 或更新。
- 默认按 Noise 12.1 / 12.2 返回全零 DH 输出。`reject_all_zero_dh` 是可选且不被规范推荐的拒绝策略，不构成身份认证。
- 传输明文超过 65519 字节时在加密前拒绝，不消耗 nonce。
- `cacophony_report` 分开断言 944 条向量和 5664 条消息比较。
- 基准脚本记录每次热身和 9 个样本。
- 本版本只准备发布元数据，工作区里没有执行 `moon publish`。

## 0.1.0

- 实现 Noise 的 `CipherState`、`SymmetricState` 和 `HandshakeState`。
- 内置单向、基础和延迟握手模式，并支持 `pskN` 修饰符与模式字符串。
- 支持 25519、448、ChaChaPoly、AESGCM、SHA256、SHA512、BLAKE2s、BLAKE2b。
- 传输阶段支持加密、解密、`Rekey` 和 `SetNonce`。
- 用 16 条 Cacophony 向量和错误路径测试覆盖上述组合。
- BLAKE2s-256 与 HMAC-BLAKE2s 在仓库内实现。其余原语使用 mooncry 0.95.0。
