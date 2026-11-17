# 第三方与许可证清单

本文件是直接依赖和参考材料的清单，不是完整的传递性 SBOM 扫描器输出。

| 名称 | 角色 | 版本或位置 | 许可证 |
| --- | --- | --- | --- |
| mooncry | 运行时依赖：X25519、X448、ChaCha20-Poly1305、AES-256-GCM、SHA-256、SHA-512、HMAC-SHA256、HMAC-SHA512 | `cc06b/mooncry@0.95.0`，https://github.com/cc06b/mooncry | Apache-2.0 |
| snow | 结构参考，不是逐行移植 | https://github.com/mcginty/snow | Apache-2.0 OR MIT |
| Cacophony 向量 | 测试数据，经 snow 的 `tests/vectors/cacophony.txt` 收录 | https://github.com/centromere/cacophony | Unlicense |
| Noise Protocol Framework rev 34 | 行为规范 | https://noiseprotocol.org/noise.html | 规范文本，实现代码为本仓库 |
| BLAKE2s-256、BLAKE2b-512、对应 HMAC | 本仓库按 RFC 7693 与 RFC 2104 编写 | `blake2s.mbt`、`blake2b.mbt`、`crypto.mbt` | 与本仓库相同，Apache-2.0 |
| moonbitlang/async | 只属于独立模块 `example/tcp`。库根 `moon.mod` 不列出它，发布包也不包含该目录 | `moonbitlang/async@0.22.9`，https://github.com/moonbitlang/async ，Copyright 2025 International Digital Economy Academy | Apache-2.0 |
| Python oracle | `scripts/fallback_oracle.py` 与 `scripts/fallback_oracle.json`。不参与库的运行时 | cryptography 41.0.7，PyCA，Apache-2.0 OR BSD-3-Clause；Python hashlib / hmac 来自 CPython 标准库 | 测试脚本 |

## 源文件归属

| 文件 | 归属 |
| --- | --- |
| `cipherstate.mbt`、`symmetricstate.mbt`、`handshake.mbt`、`transport.mbt`、`pattern.mbt`、`pattern_catalog.mbt`、`builder.mbt`、`crypto.mbt`、`error.mbt`、`lib.mbt`、`bytesutil.mbt` | 本仓库按 Noise rev 34 编写。结构参考 snow，不是逐行复制。版权 2026 ppyj663，Apache-2.0 |
| `blake2s.mbt`、`blake2b.mbt` | 本仓库按 RFC 7693 编写的算法实现，不是某个第三方源文件的拷贝 |
| `vectors_data.mbt`、`vectors/cacophony.json` | 测试数据，来自 Cacophony / snow，Unlicense。见 `vectors/ATTRIBUTION.md` |
| `*_wbtest.mbt`、`example/`、`bench/`、`scripts/` | 本仓库测试、示例和脚本。`example/tcp` 调用 async，不复制其源码 |
| `LICENSE` | Apache-2.0 全文 |
| `NOTICE` | 本仓库版权，以及 snow、mooncry、BLAKE2 和 Cacophony 的归属 |

BLAKE2 实现依据公开 RFC，没有把 mooncry 的错误实现复制进来。snow 的版权声明保留在 `NOTICE`。这不是传递性 SBOM，也不是法务意见。
