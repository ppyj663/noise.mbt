# 更新日志

## Unreleased

这些改动只在仓库里，不是新的 mooncakes 版本。已发布的 `ppyj663/noise@0.2.0` 保持不变。

- 修复 Windows 上 TCP 短帧测试在监听套接字关闭过早时的失败（WSAENOTSOCK），并避免等待读取方时客户端未关闭造成的死锁。
- 增加 `scripts/accept.sh` 与 `scripts/accept.ps1`，按当前工具链复测库、可选 TCP 和可选预言机，失败返回非 0。不运行、不改写基准结果。
- CI 打印 `moon version --all`，在官方最新稳定工具链和已核实的 `0.10.17+d971670cd` 上检查库，并在 Windows 上运行库与 TCP job。Windows runner 向 GITHUB_PATH 写入原生 `.moon\bin` 路径，避免 Git Bash 的 `/c/Users/...` 形式让后续 PowerShell 步骤找不到 moon。说明见 `docs/TOOLCHAIN.md`。

## 0.2.0

- 实现 Noise 10.2 的 `fallback`。`scripts/fallback_oracle.py`（cryptography 41.0.7）给出 `XXfallback`、`NNfallback` 和 `XXfallback+psk0` 的预期 JSON。
- 增加内存管道 `example/pipe`。TCP 回环在独立模块 `example/tcp`，用 workspace 引用本地库。库根不依赖 `moonbitlang/async`，发布包用 `.moonignore` 排除该目录。TCP 需要 moonc 0.10.19 或更新。
- 默认按 Noise 12.1 / 12.2 返回全零 DH 输出。`reject_all_zero_dh` 是可选且不被规范推荐的拒绝策略，不构成身份认证。
- 传输明文超过 65519 字节时在加密前拒绝，不消耗 nonce。
- `cacophony_report` 分开断言 944 条向量和 5664 条消息比较。
- 基准脚本记录每次热身和 9 个样本。
- 本版本已作为 `ppyj663/noise@0.2.0` 发布到 mooncakes。校验和与文档以注册表为准。

## 0.1.0

- 实现 Noise 的 `CipherState`、`SymmetricState` 和 `HandshakeState`。
- 内置单向、基础和延迟握手模式，并支持 `pskN` 修饰符与模式字符串。
- 支持 25519、448、ChaChaPoly、AESGCM、SHA256、SHA512、BLAKE2s、BLAKE2b。
- 传输阶段支持加密、解密、`Rekey` 和 `SetNonce`。
- 用 16 条 Cacophony 向量和错误路径测试覆盖上述组合。
- BLAKE2s-256 与 HMAC-BLAKE2s 在仓库内实现。其余原语使用 mooncry 0.95.0。
