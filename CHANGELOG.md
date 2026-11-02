# 更新日志

## 0.1.0

- 实现 Noise 的 `CipherState`、`SymmetricState` 和 `HandshakeState`。
- 内置 NN、NK、XX、IK，并支持从模式字符串解析更多模式。
- 支持 25519、ChaChaPoly、AESGCM、SHA256、BLAKE2s。
- 传输阶段支持加密、解密、`Rekey` 和 `SetNonce`。
- 用 16 条 Cacophony 向量和错误路径测试覆盖上述组合。
- BLAKE2s-256 与 HMAC-BLAKE2s 在仓库内实现。其余原语使用 mooncry 0.95.0。
