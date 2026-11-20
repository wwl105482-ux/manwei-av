using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;
using System.Web.Script.Serialization;

namespace GuardScan
{
    public class SignatureStore
    {
        public RuleSet Rules;
        public string LoadError = "";
        public int RegexErrors;
        public string FirstRegexError = "";

        private List<KeyValuePair<NameRule, Regex>> _nameRules = new List<KeyValuePair<NameRule, Regex>>();
        private List<StringRule> _asciiStrings = new List<StringRule>();
        private List<StringRule> _utf16Strings = new List<StringRule>();
        private byte[][] _asciiPats;
        private byte[][] _utf16Pats;
        private List<int>[] _asciiFirst;
        private List<int>[] _utf16First;
        private Dictionary<string, HashRule> _hashes = new Dictionary<string, HashRule>(StringComparer.OrdinalIgnoreCase);
        private List<PathRule> _pathRules = new List<PathRule>();
        private List<KeyValuePair<BehaviorRule, List<Regex>>> _behaviorRules = new List<KeyValuePair<BehaviorRule, List<Regex>>>();

        public static string DefaultRulePath
        {
            get { return Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "rules", "signatures.json"); }
        }

        public bool Load(string file)
        {
            Rules = new RuleSet();
            try
            {
                if (!File.Exists(file))
                {
                    LoadError = "规则库不存在: " + file;
                    Rules = BuiltinRules();
                    Build();
                    return false;
                }
                string json = File.ReadAllText(file, Encoding.UTF8);
                JavaScriptSerializer ser = new JavaScriptSerializer();
                ser.MaxJsonLength = 8 * 1024 * 1024;
                RuleSet rs = ser.Deserialize<RuleSet>(json);
                if (rs != null) Rules = rs;
                Build();
                return true;
            }
            catch (Exception ex)
            {
                LoadError = "规则库解析失败: " + ex.Message + "，已改用内置规则";
                Rules = BuiltinRules();
                Build();
                return false;
            }
        }

        // 直接从 JSON 文本加载（用于导入前校验，不落临时文件）。
        public bool LoadFromText(string json, string label)
        {
            Rules = new RuleSet();
            try
            {
                JavaScriptSerializer ser = new JavaScriptSerializer();
                ser.MaxJsonLength = 8 * 1024 * 1024;
                RuleSet rs = ser.Deserialize<RuleSet>(json);
                if (rs != null) Rules = rs;
                Build();
                return true;
            }
            catch (Exception ex)
            {
                LoadError = (label == null ? "规则文本" : label) + " 解析失败: " + ex.Message;
                Rules = BuiltinRules();
                Build();
                return false;
            }
        }

        private static RuleSet BuiltinRules()
        {
            RuleSet rs = new RuleSet();
            rs.Version = "builtin-1";
            rs.Strings.Add(new StringRule { Pattern = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE", Encoding = "ascii", Name = "EICAR.TestFile", Severity = "high", Description = "标准反病毒测试文件特征" });
            rs.Names.Add(new NameRule { Regex = "playfinder|traplayfinder", Name = "Adware.PlayFinder", Severity = "high", Description = "游戏推广弹窗广告程序" });
            rs.Names.Add(new NameRule { Regex = "^(360|360safe|360tray|360sd|qhsafe|qhpcmgr)", Name = "PUP.360", Severity = "medium", Description = "360 系捆绑推广组件" });
            rs.Names.Add(new NameRule { Regex = "ludashi|ldhelper", Name = "PUP.Ludashi", Severity = "medium", Description = "鲁大师推广组件" });
            rs.Names.Add(new NameRule { Regex = "qqpcmgr", Name = "PUP.QQPCMgr", Severity = "medium", Description = "腾讯电脑管家企业版组件" });
            return rs;
        }

        private void Build()
        {
            _nameRules.Clear();
            _asciiStrings.Clear();
            _utf16Strings.Clear();
            _hashes.Clear();
            _pathRules.Clear();
            _behaviorRules.Clear();
            RegexErrors = 0;
            FirstRegexError = "";

            if (Rules.Names != null)
            {
                foreach (NameRule r in Rules.Names)
                {
                    if (r == null || string.IsNullOrEmpty(r.Regex)) continue;
                    try
                    {
                        Regex re = new Regex(r.Regex, RegexOptions.IgnoreCase | RegexOptions.Compiled | RegexOptions.CultureInvariant);
                        _nameRules.Add(new KeyValuePair<NameRule, Regex>(r, re));
                    }
                    catch (Exception ex)
                    {
                        RegexErrors++;
                        if (FirstRegexError.Length == 0) FirstRegexError = "名称规则 " + r.Name + ": " + ex.Message;
                    }
                }
            }
            if (Rules.Strings != null)
            {
                foreach (StringRule r in Rules.Strings)
                {
                    if (r == null || string.IsNullOrEmpty(r.Pattern)) continue;
                    if (string.Equals(r.Encoding, "utf16", StringComparison.OrdinalIgnoreCase)) _utf16Strings.Add(r);
                    else _asciiStrings.Add(r);
                }
            }
            if (Rules.Hashes != null)
            {
                foreach (HashRule r in Rules.Hashes)
                {
                    if (r == null || string.IsNullOrEmpty(r.Md5)) continue;
                    _hashes[r.Md5.Trim()] = r;
                }
            }
            if (Rules.Paths != null)
            {
                foreach (PathRule r in Rules.Paths)
                {
                    if (r == null || string.IsNullOrEmpty(r.Contains)) continue;
                    _pathRules.Add(r);
                }
            }
            if (Rules.Behaviors != null)
            {
                foreach (BehaviorRule r in Rules.Behaviors)
                {
                    if (r == null || r.Patterns == null || r.Patterns.Count == 0) continue;
                    List<Regex> compiled = new List<Regex>();
                    foreach (string p in r.Patterns)
                    {
                        if (string.IsNullOrEmpty(p)) continue;
                        try { compiled.Add(new Regex(p, RegexOptions.IgnoreCase | RegexOptions.Compiled | RegexOptions.CultureInvariant)); }
                        catch (Exception ex)
                        {
                            RegexErrors++;
                            if (FirstRegexError.Length == 0) FirstRegexError = "行为规则 " + r.Name + ": " + ex.Message;
                        }
                    }
                    if (compiled.Count > 0) _behaviorRules.Add(new KeyValuePair<BehaviorRule, List<Regex>>(r, compiled));
                }
            }
            CompilePatterns();
        }

        private void CompilePatterns()
        {
            _asciiPats = new byte[_asciiStrings.Count][];
            _asciiFirst = new List<int>[256];
            for (int i = 0; i < _asciiStrings.Count; i++)
            {
                byte[] pat = Encoding.ASCII.GetBytes(_asciiStrings[i].Pattern);
                _asciiPats[i] = pat;
                AddFirstByte(_asciiFirst, pat, i);
            }
            _utf16Pats = new byte[_utf16Strings.Count][];
            _utf16First = new List<int>[256];
            for (int i = 0; i < _utf16Strings.Count; i++)
            {
                byte[] pat = Encoding.Unicode.GetBytes(_utf16Strings[i].Pattern);
                _utf16Pats[i] = pat;
                AddFirstByte(_utf16First, pat, i);
            }
        }

        private static void AddFirstByte(List<int>[] map, byte[] pat, int index)
        {
            if (pat == null || pat.Length == 0) return;
            int b = pat[0];
            if (map[b] == null) map[b] = new List<int>();
            map[b].Add(index);
        }

        public List<Threat> MatchPath(string fullPath)
        {
            List<Threat> list = new List<Threat>();
            string fileName = Path.GetFileName(fullPath);
            foreach (KeyValuePair<NameRule, Regex> kv in _nameRules)
            {
                if (kv.Value.IsMatch(fileName))
                {
                    list.Add(MakeThreat(fullPath, kv.Key.Name, "文件名规则", Sev.Parse(kv.Key.Severity), kv.Key.Description));
                }
            }
            foreach (PathRule r in _pathRules)
            {
                if (fullPath.IndexOf(r.Contains, StringComparison.OrdinalIgnoreCase) < 0) continue;
                if (!string.IsNullOrEmpty(r.Extensions))
                {
                    string ext = (Path.GetExtension(fullPath) ?? "").ToLowerInvariant();
                    bool ok = false;
                    string[] parts = r.Extensions.Split(new char[] { ',', ';', ' ' }, StringSplitOptions.RemoveEmptyEntries);
                    foreach (string p in parts)
                    {
                        if (ext == p.Trim().ToLowerInvariant()) { ok = true; break; }
                    }
                    if (!ok) continue;
                }
                list.Add(MakeThreat(fullPath, r.Name, "路径规则", Sev.Parse(r.Severity), r.Description));
            }
            return list;
        }

        // 行为规则：同一文件命中同一条规则里足够多的可疑模式才报，
        // 这样能把“下载 + 执行”“删卷影 + 破坏引导”等组合识别出来，而不是见到一个关键词就报。
        // 行为规则的前置关键词：先用便宜的字符串查找筛掉绝大多数正常脚本，
        // 只有出现可疑关键词时才跑正则组合判定（WPS 插件目录里有 5000 多个前端 JS，
        // 对每个文件跑全部正则会把扫描拖慢一个数量级）。
        private static readonly string[] BehaviorHints = new string[]
        {
            "downloadstring", "downloadfile", "downloaddata", "invoke-webrequest", "invoke-restmethod",
            "start-bitstransfer", "bitsadmin", "certutil", "mshta", "regsvr32", "rundll32",
            "vssadmin", "shadowcopy", "bcdedit", "wbadmin", "set-mppreference", "wevtutil",
            "schtasks", "sc create", "new-service", "reg add", "currentversion\\run",
            "mimikatz", "lsass", "ntds.dit", "amsi", "frombase64string", "-encodedcommand",
            "wscript.shell", "javascript:", "powershell -", "iex("
        };

        private static bool HasBehaviorHint(string text)
        {
            int n = Math.Min(text.Length, 8192);
            string probe = n == text.Length ? text : text.Substring(0, n);
            foreach (string h in BehaviorHints)
            {
                if (probe.IndexOf(h, StringComparison.OrdinalIgnoreCase) >= 0) return true;
            }
            return false;
        }

        public List<Threat> MatchBehavior(string fullPath, string text)
        {
            return MatchBehavior(fullPath, text, true);
        }

        // prefilter 为 false 时跳过关键词预筛（彻底扫描用），直接跑全部行为正则。
        public List<Threat> MatchBehavior(string fullPath, string text, bool prefilter)
        {
            List<Threat> list = new List<Threat>();
            if (string.IsNullOrEmpty(text)) return list;
            if (prefilter && !HasBehaviorHint(text)) return list;
            string ext = (Path.GetExtension(fullPath) ?? "").ToLowerInvariant();
            foreach (KeyValuePair<BehaviorRule, List<Regex>> kv in _behaviorRules)
            {
                BehaviorRule rule = kv.Key;
                if (!ExtMatch(rule.Extensions, ext)) continue;
                int hits = 0;
                foreach (Regex re in kv.Value)
                {
                    if (re.IsMatch(text)) hits++;
                }
                int need = rule.MinHits > 0 ? rule.MinHits : 1;
                if (hits >= need)
                {
                    string detail = rule.Description + "（命中 " + hits + " 项行为特征）";
                    list.Add(MakeThreat(fullPath, rule.Name, "行为特征", Sev.Parse(rule.Severity), detail));
                }
            }
            return list;
        }

        private static bool ExtMatch(string extensions, string ext)
        {
            if (string.IsNullOrEmpty(ext)) return false;
            if (string.IsNullOrEmpty(extensions)) return true;
            string[] parts = extensions.Split(new char[] { ',', ';', ' ' }, StringSplitOptions.RemoveEmptyEntries);
            foreach (string p in parts)
            {
                if (string.Equals(p.Trim(), ext, StringComparison.OrdinalIgnoreCase)) return true;
            }
            return false;
        }

        public int BehaviorRuleCount { get { return _behaviorRules.Count; } }

        public int HashRuleCount { get { return _hashes.Count; } }

        // 压缩包内条目没有真实文件路径，用虚拟路径显示，命中文件名规则同样报告。
        public List<Threat> MatchArchiveEntry(string entryName, string virtualPath)
        {
            List<Threat> list = new List<Threat>();
            foreach (KeyValuePair<NameRule, Regex> kv in _nameRules)
            {
                if (kv.Value.IsMatch(entryName))
                {
                    list.Add(MakeThreat(virtualPath, kv.Key.Name, "文件名规则", Sev.Parse(kv.Key.Severity), kv.Key.Description));
                }
            }
            return list;
        }

        public List<Threat> MatchBody(string fullPath, byte[] buffer, int length)
        {
            List<Threat> list = new List<Threat>();
            if (buffer == null || length <= 0) return list;
            ScanPatterns(fullPath, buffer, length, _asciiPats, _asciiFirst, _asciiStrings, list);
            ScanPatterns(fullPath, buffer, length, _utf16Pats, _utf16First, _utf16Strings, list);
            return list;
        }

        // 把所有特征串合并到一次字节遍历里：只有首字节命中候选才做完整比较。
        private static void ScanPatterns(string fullPath, byte[] hay, int len, byte[][] pats,
            List<int>[] first, List<StringRule> rules, List<Threat> list)
        {
            if (pats == null || pats.Length == 0) return;
            bool[] hit = new bool[pats.Length];
            int remaining = pats.Length;
            for (int i = 0; i < len && remaining > 0; i++)
            {
                List<int> candidates = first[hay[i]];
                if (candidates == null) continue;
                for (int c = 0; c < candidates.Count; c++)
                {
                    int pi = candidates[c];
                    if (hit[pi]) continue;
                    byte[] pat = pats[pi];
                    if (i + pat.Length > len) continue;
                    bool ok = true;
                    for (int j = 1; j < pat.Length; j++)
                    {
                        if (hay[i + j] != pat[j]) { ok = false; break; }
                    }
                    if (!ok) continue;
                    hit[pi] = true;
                    remaining--;
                    StringRule r = rules[pi];
                    list.Add(MakeThreat(fullPath, r.Name, "特征串", Sev.Parse(r.Severity), r.Description));
                }
            }
        }

        public Threat MatchHash(string fullPath, string md5)
        {
            if (string.IsNullOrEmpty(md5)) return null;
            HashRule r;
            if (_hashes.TryGetValue(md5, out r))
                return MakeThreat(fullPath, r.Name, "哈希", Sev.Parse(r.Severity), r.Description);
            return null;
        }

        // 用于规则完整性校验：返回小写十六进制 SHA256，失败返回空串。
        public static string Sha256File(string path)
        {
            try
            {
                using (FileStream fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
                {
                    using (System.Security.Cryptography.SHA256 sha = System.Security.Cryptography.SHA256.Create())
                    {
                        byte[] hash = sha.ComputeHash(fs);
                        StringBuilder sb = new StringBuilder(hash.Length * 2);
                        for (int i = 0; i < hash.Length; i++) sb.Append(hash[i].ToString("x2"));
                        return sb.ToString();
                    }
                }
            }
            catch { return ""; }
        }

        public static Threat MakeThreat(string path, string name, string kind, Severity sev, string detail)
        {
            Threat t = new Threat();
            t.Path = path;
            t.Name = name;
            t.Kind = kind;
            t.Sev = sev;
            t.Detail = detail ?? "";
            try { t.Size = new FileInfo(path).Length; } catch { t.Size = 0; }
            return t;
        }

        public static int IndexOf(byte[] hay, int hayLen, byte[] needle)
        {
            if (needle == null || needle.Length == 0) return -1;
            int max = hayLen - needle.Length;
            for (int i = 0; i <= max; i++)
            {
                if (hay[i] != needle[0]) continue;
                bool ok = true;
                for (int j = 1; j < needle.Length; j++)
                {
                    if (hay[i + j] != needle[j]) { ok = false; break; }
                }
                if (ok) return i;
            }
            return -1;
        }
    }
}
