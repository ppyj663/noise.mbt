# Test vector attribution

`cacophony.json` contains the 944 Cacophony vectors for the patterns, DH
functions, ciphers, and hashes implemented by this library. Vectors marked
`fail`, `fallback`, or `hybrid` in the upstream file are not included.

- Vendored from [mcginty/snow](https://github.com/mcginty/snow) `tests/vectors/cacophony.txt`
  (license: Apache-2.0 OR MIT).
- Original suite: [centromere/cacophony](https://github.com/centromere/cacophony)
  (Unlicense / public domain).
- The embedded copy used by `moon test` is `vectors_data.mbt`.
  Compact JSON SHA-256: `e2f1ddfbf5297125bdd10558ba7701fbae5d5b2b423b65d022d013ad066aacd0`.

## 测试向量来源

`cacophony.json` 是本库已实现的模式、DH、加密和哈希所对应的 944 条 Cacophony 向量。
上游文件里带 `fail`、`fallback` 或 `hybrid` 的条目没有收进来。

文件来自 [mcginty/snow](https://github.com/mcginty/snow)（Apache-2.0 OR MIT）所收录的
`tests/vectors/cacophony.txt`，原始套件为
[centromere/cacophony](https://github.com/centromere/cacophony)（Unlicense）。
`moon test` 实际读取的是 `vectors_data.mbt` 中的紧凑 JSON，其 SHA-256 为
`e2f1ddfbf5297125bdd10558ba7701fbae5d5b2b423b65d022d013ad066aacd0`。
