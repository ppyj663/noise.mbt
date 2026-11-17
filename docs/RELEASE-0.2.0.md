# 0.2.0 发布前检查（尚未发布）

这不是已经完成的发布。

## 候选

- 版本：`moon.mod` 和 `lib.mbt` 的 `0.2.0`
- 模块：`ppyj663/noise`
- 仓库：https://github.com/ppyj663/noise.mbt
- 许可证：Apache-2.0
- 直接依赖：只有 `cc06b/mooncry@0.95.0`。`moonbitlang/async@0.22.9` 只写在 `example/tcp/moon.mod`
- 变更：`CHANGELOG.md`

## 包里应有的源码

库：`*.mbt`（不含测试专用逻辑以外的测试文件；MoonBit 模块发布通常连同仓库源码）。  
示例：`example/`、`example/pipe/`。`example/tcp/` 被根目录 `.moonignore` 排除，不进入 `moon package` 列出的库归档。  
测试与向量：`*_wbtest.mbt`、`vectors/`、`vectors_data.mbt`。  
预言机：`scripts/fallback_oracle.py`、`scripts/fallback_oracle.json`。  
基准：`bench/`、`scripts/bench.sh`、当次 `bench/results/`。  
文档：`README.md`、`docs/API.md`、`LICENSE`、`NOTICE`、`THIRD_PARTY.md`、`source-attribution.md`。

不应进入补丁或包的内容：`_build/`、`.mooncakes/`、`pkg.generated.mbti`、任何 token。

## 建议命令

在已登录 ppyj663 且 `moon login` 已保存的机器上，应用补丁并复测之后：

```bash
moon update
moon check --deny-warn --target native
moon test --target native
moon package --list
moon publish --dry-run
moon publish
```

`moon package --list` 不需要登录，用来确认归档里没有 `example/tcp` 和 async。`moon publish --dry-run` 在未登录时会停在 “Registry login is required”；不要为了干跑去读或打印凭据。本工作区没有执行真正的 `moon publish`，也没有打 tag。

TCP 不随库发布。仓库里的单独命令是 `moon -C example/tcp test --target native --package ppyj663/noise-tcp-example`，需要 moonc 0.10.19 或更新。不带 `--package` 时，`example/tcp/moon.work` 会把库根也算进同一次 `moon test`。

## 发布前仍要人工看的事

- 复测日志是否仍是 944 条向量、5664 条消息、0 跳过。
- `python3 scripts/fallback_oracle.py --check` 在本机的 cryptography 版本上是否仍一致。生成该 JSON 时是 41.0.7。
- `moon search ppyj663/noise` 是否仍没有同名已发布模块。
- GitHub Actions 只有在推送之后才会跑。推送前不能写成 CI 已绿。
