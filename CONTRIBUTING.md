# 参与贡献

欢迎 issue 和 pull request。这个项目刻意保持小而透明：单进程、无网络、无后台服务、C# 5 语法、只依赖 .NET Framework 4.x 自带组件。

## 开发环境

- Windows 10/11
- .NET Framework 4.x（系统自带 `C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe`）
- 可选：Visual Studio / VS Code（不提供 .sln，构建脚本就是唯一入口）

```powershell
powershell -ExecutionPolicy Bypass -File build.ps1
powershell -ExecutionPolicy Bypass -File build-installer.ps1
powershell -ExecutionPolicy Bypass -File release.ps1
```

构建后运行自检：

```powershell
.\dist\满唯杀毒.exe --selftest
```

## 改规则

规则在 `rules/signatures.json`，格式见 README 的“规则文件”一节。新增检测项时请一并说明：

1. 它针对什么样本/行为；
2. 误报风险（哪些正常软件可能命中）；
3. 是否加入 `tests/samples` 作为自检样本（注意不要提交真实恶意代码，用无害标记字符串代替）。

## 提交 PR 前

- `--selftest` 全部通过；
- 至少跑一次 `--scan C:\Windows\System32`，确认没有新增误报（当前基线 0 命中）；
- 不要提交 `dist/`、`*.pfx`、`*.settings.json`、报告或日志；
- 保持 C# 5 语法（不要用 `?.`、`nameof`、字符串插值等新语法），因为构建用的是旧版 csc。

## 提交信息

用一句话说明“改了什么、为什么”，例如：

```
rules: 增加对伪装成 svchost 的脚本的检测
ui: 扫描中禁用彻底扫描开关，避免误解
```

## 许可证

贡献的代码默认以 MIT 许可证发布（见 `LICENSE`）。
