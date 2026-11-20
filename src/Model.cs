using System;
using System.Collections.Generic;

namespace GuardScan
{
    public enum Severity { Low = 1, Medium = 2, High = 3 }

    public static class Sev
    {
        public static Severity Parse(string s)
        {
            if (string.IsNullOrEmpty(s)) return Severity.Low;
            switch (s.Trim().ToLowerInvariant())
            {
                case "high": return Severity.High;
                case "medium": return Severity.Medium;
                default: return Severity.Low;
            }
        }

        public static string Text(Severity s)
        {
            switch (s)
            {
                case Severity.High: return "高";
                case Severity.Medium: return "中";
                default: return "低";
            }
        }
    }

    public class HashRule
    {
        public string Md5 { get; set; }
        public string Name { get; set; }
        public string Severity { get; set; }
        public string Description { get; set; }
    }

    public class StringRule
    {
        public string Pattern { get; set; }
        public string Encoding { get; set; }
        public string Name { get; set; }
        public string Severity { get; set; }
        public string Description { get; set; }
    }

    public class NameRule
    {
        public string Regex { get; set; }
        public string Name { get; set; }
        public string Severity { get; set; }
        public string Description { get; set; }
    }

    public class PathRule
    {
        public string Contains { get; set; }
        public string Extensions { get; set; }
        public string Name { get; set; }
        public string Severity { get; set; }
        public string Description { get; set; }
    }

    // 行为规则：一个文件同时命中同一条规则里足够多的可疑模式才判定，
    // 用来识别“下载 + 执行”“删卷影 + 破坏引导”这类组合行为，单个关键词不报。
    public class BehaviorRule
    {
        public string Name { get; set; }
        public string Severity { get; set; }
        public string Description { get; set; }
        public string Extensions { get; set; }
        public List<string> Patterns { get; set; }
        public int MinHits { get; set; }

        public BehaviorRule()
        {
            Patterns = new List<string>();
            MinHits = 2;
        }
    }

    public class RuleSet
    {
        public string Version { get; set; }
        public List<HashRule> Hashes { get; set; }
        public List<StringRule> Strings { get; set; }
        public List<NameRule> Names { get; set; }
        public List<PathRule> Paths { get; set; }
        public List<BehaviorRule> Behaviors { get; set; }

        public RuleSet()
        {
            Version = "unknown";
            Hashes = new List<HashRule>();
            Strings = new List<StringRule>();
            Names = new List<NameRule>();
            Paths = new List<PathRule>();
            Behaviors = new List<BehaviorRule>();
        }
    }

    public class Threat
    {
        public string Path { get; set; }
        public string Name { get; set; }
        public string Kind { get; set; }
        public Severity Sev { get; set; }
        public long Size { get; set; }
        public string Detail { get; set; }
        public bool Removed { get; set; }
        // Windows Defender 复核结论："threat" 检出 / "clean" 未检出 / "timeout" 超时 / "error" 失败 / "" 未复核
        public string Defender { get; set; }

        public Threat()
        {
            Kind = "";
            Detail = "";
            Defender = "";
        }
    }

    // 把查杀结果分成"放心删"和"疑似垃圾"两类：
    // 内容级证据（哈希命中、特征串命中）说明文件本体确实匹配恶意特征，删掉是安全的；
    // 仅凭文件名/路径/启发式判定的可能误报，删前需要确认。
    public static class ThreatSafety
    {
        // 正规厂商签名：命中这些签名的文件即使名字带 360/Ludashi 也当正常软件，不归入放心删。
        private static readonly string[] TrustedVendors = new string[]
        {
            "microsoft", "apple", "google", "nvidia", "intel", "amd", "realtek", "adobe", "oracle",
            "mozilla", "valve", "tencent", "alibaba", "netease", "kingsoft", "inspur", "huawei",
            "xiaomi", "lenovo", "dell", "hp ", "samsung", "autodesk", "jetbrains"
        };

        private static readonly Dictionary<string, bool> SignCache = new Dictionary<string, bool>(StringComparer.OrdinalIgnoreCase);
        private static readonly object SignLock = new object();

        public static bool IsSafeToDelete(Threat t)
        {
            if (t == null || t.Kind == null) return false;
            // Defender 复核确认是恶意文件的，也算内容级证据，可以放心删。
            if (t.Defender == DefenderCheck.VerdictThreat) return true;
            // 只有内容级证据（哈希命中 / 特征串命中）才算放心删；
            // 名字里带 360、鲁大师等的仍按原来的规则落在"疑似垃圾"，由人工确认。
            return t.Kind == "哈希" || t.Kind == "特征串";
        }

        // 只有"垃圾常去的位置"里的关键词命中才当放心删；装在 Program Files 里的正常软件不算。
        private static bool LooksLikeJunkLocation(string path)
        {
            if (string.IsNullOrEmpty(path)) return false;
            string dir = System.IO.Path.GetDirectoryName(path);
            if (string.IsNullOrEmpty(dir)) return false;
            // 盘根目录下的散落文件（如 C:\xxx.exe）。
            string root = System.IO.Path.GetPathRoot(path);
            if (!string.IsNullOrEmpty(root) && string.Equals(dir.TrimEnd('\\'), root.TrimEnd('\\'), StringComparison.OrdinalIgnoreCase)) return true;

            string[] parts = dir.Split(new char[] { '\\', '/' }, StringSplitOptions.RemoveEmptyEntries);
            foreach (string part in parts)
            {
                string s = part.ToLowerInvariant();
                if (s == "temp" || s == "tmp" || s == "downloads" || s == "cache" || s == "caches") return true;
                if (s == "desktop" || s == "public" || s == "appdata") return true;
                if (s == "360" || s.StartsWith("360")) return true;
                if (s.Contains("ludashi") || s.Contains("鲁大师")) return true;
            }
            return false;
        }

        private static bool HasJunkKeyword(Threat t)
        {
            string name = (t.Name == null ? "" : t.Name).ToLowerInvariant();
            if (name.Contains("360") || name.Contains("ludashi") || name.Contains("鲁大师")) return true;
            string file = (t.Path == null ? "" : System.IO.Path.GetFileName(t.Path)).ToLowerInvariant();
            return file.Contains("360") || file.Contains("ludashi") || file.Contains("鲁大师");
        }

        // 有受信任厂商的有效签名，就认为它是正常软件（结果按路径缓存，避免重复验签）。
        public static bool LooksLikeLegitSoftware(string path)
        {
            if (string.IsNullOrEmpty(path)) return false;
            lock (SignLock)
            {
                bool cached;
                if (SignCache.TryGetValue(path, out cached)) return cached;
            }
            bool legit = false;
            try
            {
                string signer;
                if (FileChecks.TrySignature(path, out signer) && !string.IsNullOrEmpty(signer))
                {
                    string s = signer.ToLowerInvariant();
                    foreach (string v in TrustedVendors)
                    {
                        if (s.Contains(v)) { legit = true; break; }
                    }
                }
            }
            catch { legit = false; }
            lock (SignLock)
            {
                if (SignCache.Count < 8192) SignCache[path] = legit;
            }
            return legit;
        }
    }

    public class AuditItem
    {
        public string Category { get; set; }
        public string Name { get; set; }
        public string Command { get; set; }
        public string Location { get; set; }
        public string Signer { get; set; }
        public Severity Sev { get; set; }
        public string Note { get; set; }
        public string DeleteKind { get; set; }
        public string DeleteRef { get; set; }
        public string DeleteValue { get; set; }

        public AuditItem()
        {
            Category = "";
            Signer = "";
            Note = "";
            DeleteKind = "";
            DeleteRef = "";
            DeleteValue = "";
        }
    }

    public class AppSettings
    {
        public List<string> Exclusions { get; set; }
        public int Threads { get; set; }
        public int MaxFileMB { get; set; }
        public bool Notifications { get; set; }
        // 扫描结束后把"疑似"结果交给 Windows Defender 复核（只报告，不删除）。
        public bool DefenderCheck { get; set; }
        // 彻底扫描：不跳过缓存目录与素材文件，行为规则也不限前 64 KB（更慢、更全）。
        // 默认关闭（快速扫描）；需要更全面的检查时在界面上勾选。
        public bool ThoroughScan { get; set; }
        // 扫描范围是否包含可移动磁盘（U 盘/移动硬盘）；默认关闭，避免误扫。
        public bool IncludeRemovable { get; set; }
        // 启动提权选择："ask" = 每次询问，"always" = 自动以管理员身份重启，"never" = 直接以普通用户运行。
        public string Elevation { get; set; }

        public AppSettings()
        {
            Exclusions = new List<string>();
            Threads = 0; // 0 = 自动（按 CPU 核心数）
            MaxFileMB = 256;
            Notifications = false;
            DefenderCheck = true;
            ThoroughScan = false;
            IncludeRemovable = false;
            Elevation = "ask";
        }
    }
}
