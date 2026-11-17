# 工具链与发布排障

本页说明本仓库支持的官方稳定 MoonBit 版本、CI 如何安装它们，以及 Windows 上 `moon publish` 遇到命令行过长时的处理办法。不记录某台机器的私有路径，也不改写 `bench/results` 里已有的基准数字。

## 官方来源

- 下载页：<https://www.moonbitlang.com/download/>
- `moon` 命令文档（含 `moon upgrade`）：<https://docs.moonbitlang.com/en/stable/toolchain/moon/commands.html>
- Unix 安装脚本：<https://cli.moonbitlang.com/install/unix.sh>
- Windows 安装脚本：<https://cli.moonbitlang.com/install/powershell.ps1>
- 官方默认通道 `latest`（稳定版，不是 nightly / pre-release）：<https://cli.moonbitlang.com/binaries/latest/>

文档里的 `moon upgrade`（不要加 `--dev`）对应稳定通道，但在非交互环境可能因“not a terminal”失败。这种情况下使用上面的官方 installer，默认同样是 `latest`。不要用 nightly 或 beta 来满足“最新稳定版”的要求。

## 本仓库的最低支持版本

- **库根**（`moon check` / `moon test --target native`、两个根目录 example）：moonc **0.10.17** 或更新。库根不依赖 `moonbitlang/async`。
- **TCP 示例**（`example/tcp`）：需要工具链附带的 `moonbitlang/core/async`。moonc **0.10.17** 的 core 没有这个导入，因此 TCP 不能在 0.10.17 上构建。当前官方 `latest`（本仓库核验时为 moonc **0.10.20+65efd5b93**，core 同版本且含 `core/async`）可以运行 TCP。

安装脚本接受带完整修订号的版本串，例如：

```bash
curl -fsSL https://cli.moonbitlang.com/install/unix.sh | bash -s "0.10.17+d971670cd"
curl -fsSL https://cli.moonbitlang.com/install/unix.sh | bash -s "0.10.20+65efd5b93"
curl -fsSL https://cli.moonbitlang.com/install/unix.sh | bash -s latest
```

Windows 可以把同样的字符串赋给 `MOONBIT_INSTALL_VERSION`，再执行官方 `powershell.ps1`。这些钉死版本已对 `https://cli.moonbitlang.com/binaries/<version>/` 做过存在性检查（`+` 在 URL 里编码为 `%2B`）。**不要使用不带哈希的 `0.10.19` 作为安装标签**，该路径会返回 403。若要使用 0.10.19 及以上的能力（例如 TCP），请安装官方 `latest`，或使用已确认存在的完整版本串。

## CI 实际做什么

`.github/workflows/ci.yml` 只用上述官方 installer，不会安装 nightly。

- 库 job：Ubuntu 上跑 `latest` 和已核实的 `0.10.17+d971670cd`；Windows 上跑 `latest`。每条作业在检查前打印 `moon version --all`。Windows 原生编译会先启用 MSVC 开发者环境。向 GITHUB_PATH 追加路径时，Windows 必须写原生路径（例如 `%USERPROFILE%\.moon\bin`）；若写成 Git Bash 的 `/c/Users/...`，后续默认的 PowerShell 步骤会找不到 `moon`。
- TCP job：只在 Ubuntu 与 Windows 的官方 `latest` 上跑。它不会在 0.10.17 上运行。

本地可用 `scripts/accept.sh` 或 `scripts/accept.ps1` 复测当前工具链。脚本会跑库检查、两个根 example，并在存在 `core/async` 时跑 TCP，在 Python 能导入 `cryptography` 时跑 `scripts/fallback_oracle.py --check`。失败返回非 0。可选环境变量：

- `MOON_HOME`：MoonBit 安装根目录，默认是用户主目录下的 `.moon`。
- `NOISE_ORACLE_PYTHON`：用来跑预言机的 Python 解释器。
- `MOONC_OVERRIDE`：若已设置，脚本只打印这个路径，不会改持久环境。

## Windows：`moonc` 命令行过长

在 Windows 上，`moon publish` 或其它会拉起一次很长 `moonc` 命令的步骤，可能失败并提示 `The command line is too long.` 这是 **cmd.exe 约 8191 字符的命令行限制**，不是注册表拒绝。

官方安装布局里，有时会出现一个 `moonc.cmd` 兼容包装，内容相当于用 Node 转调真正的编译器（`node run-tool.js moonc %*`）。如果当前进程的 `MOONC_OVERRIDE`（或实际被调用的 `moonc`）指向这个 `.cmd` 包装，整条命令会走 cmd.exe，就容易撞上 8191 限制。真正的 `moonc.exe` 不经过这条限制；官方 `moonc` 也支持 `@` 响应文件 / `-rsp-file`，可以把参数放到文件里。

建议的处理顺序（都是进程级，不要改未知的自定义 shim 文件，也不要跳过校验或复制凭据）：

1. 确认 `moon` 和 `moonc` 来自官方安装目录的 `bin`，例如用户主目录下的 `.moon\bin\moon.exe` 与 `.moon\bin\moonc.exe`。
2. 若必须绕过 `.cmd` 包装，只在当前终端设置：

   ```powershell
   $env:MOONC_OVERRIDE = Join-Path $env:USERPROFILE ".moon\bin\moonc.exe"
   ```

   先 `Get-Command moonc` 和 `moon version --all`，确认新的 shell 用的是这份 `moonc.exe`，再重试 `moon publish --dry-run` 或实际发布。
3. 不要编辑 `moonc.cmd`，不要把凭据文件复制到别的位置，也不要用 `subst` 指望缩短路径：Windows 可能会把盘符规范化回原来的长路径，命令仍然超长。
4. 发布后如不再需要覆盖，关掉该终端即可。不要把本机绝对路径写进仓库或 issue。

`ppyj663/noise@0.2.0` 已发布。本页描述的仓库改动不会自动覆盖这个已发布版本。
