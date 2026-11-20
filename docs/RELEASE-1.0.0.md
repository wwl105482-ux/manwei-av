# 满唯杀毒 1.0.0

首个公开版本。轻量、离线、只读的 Windows 风险排查工具。

## 下载

| 文件 | 说明 |
| --- | --- |
| `manwei-av-setup.exe` | 推荐。双击安装，写入“应用和功能”，可正常卸载；有管理员权限时装到 `C:\Program Files\满唯杀毒`，没有时装到 `%LOCALAPPDATA%\Programs\满唯杀毒` |
| `满唯杀毒.exe` | 便携版，需与 `rules\signatures.json` 放在同一目录 |

## 功能

- 本地查杀：MD5 哈希、特征串、文件名/路径规则、脚本行为规则（组合命中，降低单关键词误报）
- 脚本编码载荷：`-EncodedCommand` / base64 字面量先解码再匹配
- 宏文档检测：读取 Office 内嵌 VBA 工程，按危险调用分级（无调用 / 可疑 / 高危）
- Windows Defender 二次复核：只读、异步，最多 20 个疑似项，结果缓存 7 天（可关闭）
- 启动项审计：自启动项、服务、计划任务、hosts、浏览器扩展；支持定位、复制、删除（二次确认）
- 大文件垃圾扫描：按“放心删 / 疑似垃圾”分组
- 扫描体验：结果筛选、点列头排序、暂停/继续、用时与速度、重复文件哈希复用
- 诊断与支持：关于框、`--diag`、`--info`、规则包导入与 SHA256 完整性校验
- 安装包：无管理员也可安装到用户目录；卸载自动清理配置、报告、快捷方式与注册表

## 系统要求

Windows 10 / 11（32 位或 64 位），自带 .NET Framework 4.8，无需安装运行时。

## 已知限制

- 未签名，首次运行可能出现 SmartScreen“未知发布者”提示；点“更多信息 → 仍要运行”
- 不是常驻杀毒软件：没有实时监控、没有云查杀、没有隔离区；删除是永久删除
- 规则库较小，主要覆盖已知样本、脚本行为与宏文档；不要用它替代系统杀毒软件
- 名称含“杀毒”，但定位是“本机风险排查 + 启动项审计”，请按此理解其能力

## 校验

发布产物由 GitHub Actions 在本仓库内构建，可下载 `manwei-av-<sha>` artifact 或在本仓库 Release 附件中核对 SHA256。

## English

Manwei AV is a small offline Windows risk scanner: local signature/hash checks, behavior
rules for scripts, VBA macro inspection, optional Defender second opinion, and a startup
audit. No service, no telemetry, no network access. MIT licensed.
