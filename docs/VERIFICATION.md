# 验证记录（工作区，未提交）

基线：`71fe9cf0d38ff6509ab34e719ead8e228d7aa6a5`。  
工具链：`moon 0.1.20261104`，`moonc v0.10.20+65efd5b93`。  
日期：2026-11-17。没有 commit、push、tag 或 `moon publish`。

## 测试

库根和 TCP 分开记录。TCP 从根模块拆出之后要重跑库根测试，因为测试集合变了；密码算法和 `bench/main.mbt` 没有改，基准不重跑。

- 库根 `moon test -v --target native`：49 通过，0 失败。日志里没有 TCP 测试。其中 `cacophony vectors for supported suites` 通过，断言仍是加载 944、执行 944、跳过 0、消息比较 5664。
- `moon -C example/tcp test -v --target native --package ppyj663/noise-tcp-example`：3 通过，0 失败。分别是 loopback、短帧和超长帧。不带 `--package` 时 workspace 会把库根测试也算进去，所以记录以这条命令为准。
- 上一轮在拆分之前，`moon test --target wasm-gc --package ppyj663/noise` 和 js 都是 48 通过。那次库包不含 TCP。本轮没有改这些包的算法测试；wasm-gc / js 不作为本轮新的全量结论，除非日志里有新的运行。
- `moon publish --dry-run` 未登录时失败，原文是 `Registry login is required; run moon login`。没有登录，也没有读取凭据。`moon package --list` 不需要登录。

GitHub Actions 还没有被这次改动触发。库 job 不跑 TCP。TCP job 需要 moonc 0.10.19 或更新。不能说 CI 全绿。

## 基准

`bench/results/samples.jsonl` 仍是拆分 TCP 之前的测量：229 行，约 31867 字节。`meta.json` 的 `source_tree_sha256` 是 `3dec70a5ee5e9f423d83b28b6e1ccffc7f4606be51a675c359ad38d3a444248c`，排除了 `bench/results/`。本轮没有修改 `bench/main.mbt`、`crypto.mbt`、`handshake.mbt`、`cipherstate.mbt`、`symmetricstate.mbt`、`transport.mbt`、`blake2s.mbt`、`blake2b.mbt`。因此不重跑基准，也不要把拆分之后的整树哈希写成那次计时的源码哈希。补丁 SHA 不写进 `meta.json`。
