# 代码签名：开源项目免费方案

本文说明如何用 **SignPath Foundation** 给本项目做免费、受信任的代码签名，消除大部分“未知发布者 / Windows 已保护你的电脑”提示。

> 前提：项目以 OSI 认可的开源许可证公开（本仓库用 MIT），源码托管在 GitHub 或 GitLab 上。

## 1. 为什么需要签名

未签名的 exe 会触发：

- 浏览器下载时的“通常不会下载”（Chrome/Edge 的文件信誉提示）；
- 首次运行的“Windows 已保护你的电脑”（SmartScreen）；
- UAC 弹窗里的“未知发布者”。

签名不能保证不被杀软误报，但能显著降低用户的信任成本，也是 SignPath Foundation 的价值所在。

## 2. SignPath Foundation 是什么

[SignPath Foundation](https://signpath.org/foundation) 为符合条件的开源项目免费提供代码签名服务：证书由 SignPath 持有并托管在 HSM 中，项目通过 CI 提交“签名请求”，拿回已签名的产物。私钥不会离开 SignPath。

条件（以官方页面为准）：

- 公开仓库 + OSI 认可许可证（MIT 可以）；
- 项目有真实的发布流程（用 Git tag / Release）；
- 维护者身份可核验（GitHub 账号、邮箱、必要时的实名信息）；
- 产物不含恶意代码（本项目的 `tests/samples` 是无害的测试样本，注意在申请说明里讲清楚）。

## 3. 申请步骤

1. **把仓库放到 GitHub**

   ```powershell
   git init
   git add .
   git commit -m "Initial open-source release"
   git branch -M main
   git remote add origin https://github.com/<你的账号>/manwei-av.git
   git push -u origin main
   ```

   仓库名建议用英文（例如 `manwei-av`），便于审核。

2. **在 SignPath 注册并申请 Foundation**

   - 打开 <https://signpath.io/> 注册账号（用 GitHub 登录最方便）；
   - 在账号里找到 Foundation / Open Source 申请入口，填写项目 URL、许可证、项目简介（英文一句话，例如 “A small offline Windows risk scanner and startup auditor”）；
   - 等待审核（通常几个工作日，可能需要补充信息或视频确认）。

3. **审批通过后配置项目**

   - 在 SignPath 控制台创建 Project（slug 例如 `manwei-av`）；
   - 创建 Artifact Configuration（把 `满唯杀毒.exe`、`满唯杀毒-安装程序.exe` 放进一个 zip，或逐文件配置）；
   - 创建 Signing Policy（slug 例如 `release-signing`，指定用 Foundation 的证书）；
   - 在 GitHub 仓库的 Settings 里添加：
     - Secret `SIGNPATH_API_TOKEN`（SignPath 用户设置里生成）
     - Secret `SIGNPATH_ORGANIZATION_ID`（控制台可见）
     - Variable `SIGNPATH_ENABLED` = `true`
   - 按实际值修改 `.github/workflows/signpath.yml` 里的 `project-slug`、`signing-policy-slug`、`artifact-configuration-slug`。

4. **发版并签名**

   ```powershell
   git tag v1.0.1
   git push origin v1.0.1
   ```

   在 GitHub 上把该 tag 发布成 Release（`signpath.yml` 会触发），或手动运行 `signpath` 工作流。完成后在 Actions 的 artifact 里下载 `signed-binaries`。

5. **验证签名**

   ```powershell
   signtool verify /pa /v "满唯杀毒-安装程序.exe"
   ```

   或右键 exe → 属性 → 数字签名，应看到发布者与时间戳。

## 4. 备选方案

- **Certum Open Source Code Signing**：面向开源项目的免费/低价证书，需要项目审核；若仍发硬件令牌，需考虑邮寄成本。
- **自签名**：完全免费，但只在导入了证书的机器上有效，公共分发没有意义（见 README 的说明）。

## 5. 注意事项

- 签名后的文件与未签名版本哈希不同：发布时以 CI 产物的 SHA256 为准。
- 不要提交任何 `*.pfx` / `*.p12` / 私钥；SignPath 模式下你也不需要它们。
- 签名只解决“来源可信”，不解决“杀软误报”；误报仍需向厂商提交样本。
- 每次发版都要重新走签名流程，**不要**在签名后再改 exe。
