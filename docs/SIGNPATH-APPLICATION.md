# SignPath Foundation 申请材料

把下面内容按表单字段复制粘贴即可。表单地址：<https://signpath.org/apply>（选择 "Open Source" 项目）。

## 可直接粘贴的英文

**Project name**

```
Manwei AV (满唯杀毒)
```

**Repository URL**

```
https://github.com/wwl105482-ux/manwei-av
```

**License**

```
MIT
```

**Project description**

```
Manwei AV is a small, offline Windows risk scanner written in C# (.NET Framework 4.8, WinForms).
It performs only local, read-only checks: MD5 hashes, byte signatures, filename/path rules,
behavior rules for scripts, VBA macro inspection inside Office documents, and an optional
second opinion from the locally installed Windows Defender. It also audits startup items,
services, scheduled tasks, hosts entries and browser extensions.

The application is a single ~220 KB executable with no background service, no network access,
no telemetry and no auto-update. It is distributed as a portable exe and as a small installer
that writes an uninstall entry so users can remove it from "Apps & features".

We would like free code signing for the released binaries so that Windows users do not see
"Unknown publisher" / SmartScreen warnings when running the installer.
```

**How are binaries built?**

```
GitHub Actions (windows-latest) builds both binaries from source on every push:
build.ps1 compiles dist/满唯杀毒.exe with the .NET Framework csc,
build-installer.ps1 embeds it into dist/满唯杀毒-安装程序.exe.
The workflow .github/workflows/build.yml then runs --selftest and uploads the artifacts.
No prebuilt or third-party binaries are signed.
```

**Signing use case**

```
Sign the release executable and the installer for public Windows 10/11 users.
Artifacts are produced by the public CI workflow from this repository.
```

**Artifact configuration**

```
Project slug:            manwei-av
Artifact config slug:    default
Signing policy slug:     release-signing
Artifacts:               unsigned/*.exe (two PE files: app + installer)
```

## 申请前必须满足

- [ ] 仓库公开，`LICENSE` 为 OSI 认可许可证（当前 MIT）
- [ ] 至少一个真实 release（不是 draft），带 tag `v1.0.0`
- [ ] README 说明项目用途、构建方式、许可证（已具备）
- [ ] CI 为绿色（badge 或最近一次 run 链接）
- [ ] 维护者身份可核验（GitHub 账号有真实活动；必要时会要求邮箱/身份证明）
- [ ] 项目非商业性质（免费、无付费版本、无广告、无商业支持合同）

## 审核通过后要做的

1. SignPath 控制台 → Projects → 新建 `manwei-av`
2. Artifact Configurations → 新建 `default`，匹配 `unsigned/*.exe`，类型为 PE
3. Signing Policies → 新建 `release-signing`（release 证书）与可选的 `test-signing`
4. GitHub 仓库 Settings → Secrets and variables → Actions：
   - Secret `SIGNPATH_API_TOKEN`
   - Secret `SIGNPATH_ORGANIZATION_ID`
   - Variable `SIGNPATH_ENABLED` = `true`
5. 打 tag / 发布 release 后，`.github/workflows/signpath.yml` 会自动提交签名请求，产物在 `signed-binaries` artifact 中
6. 下载后用 `signtool verify /pa /v 满唯杀毒.exe` 验证

## 常见被拒原因

- 仓库里没有可复现的构建脚本（本仓库有）
- 许可证缺失或非 OSI（本仓库是 MIT）
- 发布物与源码不一致、或有预编译二进制（本仓库全部由 CI 生成）
- 项目带商业性质或收费
- 身份无法核验（账号太新、无活动）
