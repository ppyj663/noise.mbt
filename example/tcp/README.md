# TCP 回环示例

这是独立模块 `ppyj663/noise-tcp-example`，不是 `ppyj663/noise` 的依赖，也不会打进库的发布包。

它使用 `moonbitlang/async` 0.22.9。该版本导入 `moonbitlang/core/async`。moonc 0.10.17 附带的 core 没有这个路径，所以本示例需要 moonc 0.10.19 或更新。仓库里的实测工具链是 moon 0.1.20261104 / moonc 0.10.20。

`moon.work` 把本目录和仓库根列为成员。`moon.mod` 里的 `ppyj663/noise@0.2.0` 因此使用旁边的本地库，版本号不从 mooncakes 解析。库根的 `moon.mod` 不引用本模块。

```bash
moon -C example/tcp update
moon -C example/tcp check --deny-warn --target native
moon -C example/tcp test --target native --package ppyj663/noise-tcp-example
moon -C example/tcp run --target native .
```

`moon test` 应看到 3 项：完整 XX 回环、截断帧不产生明文、超过 65535 字节的帧被拒绝。监听地址是 `127.0.0.1` 的临时端口。每条 Noise 消息前是 16 位大端长度。
