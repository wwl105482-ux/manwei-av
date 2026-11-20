using System;
using System.IO;
using System.Reflection;
using System.Text;
using System.Web.Script.Serialization;
using System.Windows.Forms;

namespace GuardScan
{
    // 生成一份可直接发给开发者排障的文本：版本、环境、规则、目录、权限、设置与最近日志。
    internal static class Diagnostics
    {
        public static AppSettings LoadSettings()
        {
            try
            {
                string file = AppPaths.SettingsFile;
                if (!File.Exists(file)) return new AppSettings();
                JavaScriptSerializer ser = new JavaScriptSerializer();
                AppSettings s = ser.Deserialize<AppSettings>(File.ReadAllText(file, Encoding.UTF8));
                return s == null ? new AppSettings() : s;
            }
            catch { return new AppSettings(); }
        }

        public static string BuildStamp()
        {
            try
            {
                string exe = Assembly.GetExecutingAssembly().Location;
                if (string.IsNullOrEmpty(exe)) exe = Application2.ExePath;
                return File.GetLastWriteTime(exe).ToString("yyyy-MM-dd HH:mm:ss");
            }
            catch { return "未知"; }
        }

        public static string Build(SignatureStore sigs, AppSettings settings, string logText)
        {
            if (settings == null) settings = new AppSettings();
            StringBuilder sb = new StringBuilder();
            sb.AppendLine("满唯杀毒 诊断信息");
            sb.AppendLine("版本: v" + Program.AppVersion);
            sb.AppendLine("程序构建时间: " + BuildStamp());
            sb.AppendLine("程序 SHA256: " + SignatureStore.Sha256File(Application.ExecutablePath));
            sb.AppendLine("生成时间: " + DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss"));
            sb.AppendLine("系统: " + Environment.OSVersion.VersionString + " (" + (Environment.Is64BitOperatingSystem ? "64 位" : "32 位") + ")");
            sb.AppendLine(".NET: " + typeof(object).Assembly.GetName().Version);
            sb.AppendLine("管理员: " + Program.IsAdmin());
            if (sigs != null)
            {
                sb.AppendLine("规则文件: " + SignatureStore.DefaultRulePath);
                sb.AppendLine("规则版本: " + sigs.Rules.Version + "（哈希 " + sigs.Rules.Hashes.Count
                    + " / 特征串 " + sigs.Rules.Strings.Count
                    + " / 文件名 " + sigs.Rules.Names.Count
                    + " / 路径 " + sigs.Rules.Paths.Count
                    + " / 行为 " + sigs.Rules.Behaviors.Count + "）");
                if (!string.IsNullOrEmpty(sigs.LoadError)) sb.AppendLine("规则加载提示: " + sigs.LoadError);
            }
            sb.AppendLine("配置与报告目录: " + AppPaths.DataDir + (AppPaths.IsPortable ? "（便携模式）" : "（程序目录不可写，已改用用户目录）"));
            sb.AppendLine("Defender: " + (DefenderCheck.MpCmdRunPath == null ? "未找到" : DefenderCheck.MpCmdRunPath));
            sb.AppendLine("启动提权选择: " + (string.IsNullOrEmpty(settings.Elevation) ? "ask" : settings.Elevation));
            sb.AppendLine("彻底扫描: " + (settings.ThoroughScan ? "开" : "关"));
            sb.AppendLine("Defender 复核: " + (settings.DefenderCheck ? "开" : "关"));
            sb.AppendLine("排除项: " + (settings.Exclusions == null || settings.Exclusions.Count == 0
                ? "无" : string.Join("; ", settings.Exclusions.ToArray())));
            if (!string.IsNullOrEmpty(logText))
            {
                sb.AppendLine();
                sb.AppendLine("---- 日志 ----");
                sb.AppendLine(logText);
            }
            return sb.ToString();
        }

        public static string Save(string text)
        {
            string dir = AppPaths.ReportsDir;
            Directory.CreateDirectory(dir);
            string file = Path.Combine(dir, "满唯杀毒-诊断-" + DateTime.Now.ToString("yyyyMMdd-HHmmss") + ".txt");
            File.WriteAllText(file, text, Encoding.UTF8);
            return file;
        }
    }

    internal static class Application2
    {
        public static string ExePath
        {
            get
            {
                try { return System.Windows.Forms.Application.ExecutablePath; }
                catch { return ""; }
            }
        }
    }
}
