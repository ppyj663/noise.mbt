# Test vector attribution

`cacophony.json` is the applicable subset of the Cacophony Noise Protocol test
vectors (patterns NN, NK, XX, IK; DH 25519; ciphers ChaChaPoly and AESGCM;
hashes SHA256 and BLAKE2s).

- Vendored from [mcginty/snow](https://github.com/mcginty/snow) `tests/vectors/cacophony.txt`
  (license: Apache-2.0 OR MIT).
- Original suite: [centromere/cacophony](https://github.com/centromere/cacophony)
  (Unlicense / public domain).
- The embedded copy used by `moon test` is `vectors_data.mbt`.
  Compact JSON SHA-256: `abf46916f6dd7fb38e1d7476cb5c42c1f91afcdd3c3132f84542f8c1cb8de7f9`.

## 测试向量来源

`cacophony.json` 是 Cacophony 官方 Noise 测试向量中，本库支持的模式与算法组合
（NN、NK、XX、IK；25519；ChaChaPoly、AESGCM；SHA256、BLAKE2s）。

文件来自 [mcginty/snow](https://github.com/mcginty/snow)（Apache-2.0 OR MIT）所收录的
`tests/vectors/cacophony.txt`，原始套件为
[centromere/cacophony](https://github.com/centromere/cacophony)（Unlicense）。
`moon test` 实际读取的是 `vectors_data.mbt` 中的紧凑 JSON，其 SHA-256 为
`abf46916f6dd7fb38e1d7476cb5c42c1f91afcdd3c3132f84542f8c1cb8de7f9`。
