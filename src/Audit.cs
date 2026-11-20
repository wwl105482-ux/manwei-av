using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;
using System.Web.Script.Serialization;
using System.Xml;
using Microsoft.Win32;

namespace GuardScan
{
    public static class Audit
    {
        private static readonly Dictionary<string, KeyValuePair<bool, string>> SigCache =
            new Dictionary<string, KeyValuePair<bool, string>>(StringComparer.OrdinalIgnoreCase);

        public static string Expand(string s)
        {
            if (string.IsNullOrEmpty(s)) return "";
            try { return Environment.ExpandEnvironmentVariables(s); } catch { return s; }
        }

        public static string CommandToPath(string command)
        {
            string c = Expand(command).Trim();
            if (c.Length == 0) return "";
            if (c.StartsWith("\""))
            {
                int end = c.IndexOf('"', 1);
                if (end > 0) return Expand(c.Substring(1, end - 1));
            }
            if (File.Exists(c)) return c;
            int idx = c.ToLowerInvariant().IndexOf(".exe");
            if (idx > 0) return c.Substring(0, idx + 4).Trim('"');
            idx = c.IndexOf(' ');
            if (idx > 0) return c.Substring(0, idx).Trim('"');
            return c.Trim('"');
        }

        private static KeyValuePair<bool, string> SignatureOf(string path)
        {
            if (string.IsNullOrEmpty(path) || !File.Exists(path)) return new KeyValuePair<bool, string>(false, "");
            KeyValuePair<bool, string> cached;
            lock (SigCache)
            {
                if (SigCache.TryGetValue(path, out cached)) return cached;
            }
            string signer;
            bool ok = FileChecks.TrySignature(path, out signer);
            KeyValuePair<bool, string> result = new KeyValuePair<bool, string>(ok, signer ?? "");
            lock (SigCache) SigCache[path] = result;
            return result;
        }

        private static Severity JudgeItem(string command, out string note, out string signerText)
        {
            note = "";
            signerText = "";
            string path = CommandToPath(command);
            if (string.IsNullOrEmpty(path))
            {
                note = "无法解析可执行文件路径";
                return Severity.Medium;
            }
            if (!File.Exists(path))
            {
                note = "引用的文件已不存在（卸载残留）";
                signerText = "-";
                return Severity.Medium;
            }
            KeyValuePair<bool, string> sig = SignatureOf(path);
            signerText = sig.Key ? (string.IsNullOrEmpty(sig.Value) ? "已签名" : sig.Value) : "未签名";
            if (!sig.Key && FileChecks.IsRiskyLocation(path))
            {
                note = "未签名且位于高风险目录";
                return Severity.High;
            }
            if (!sig.Key)
            {
                note = "未签名（来源需确认）";
                return Severity.Medium;
            }
            return Severity.Low;
        }

        public static List<AuditItem> CollectStartup()
        {
            List<AuditItem> list = new List<AuditItem>();
            object[][] keys = new object[][]
            {
                new object[] { RegistryHive.CurrentUser, @"Software\Microsoft\Windows\CurrentVersion\Run", false },
                new object[] { RegistryHive.CurrentUser, @"Software\Microsoft\Windows\CurrentVersion\RunOnce", false },
                new object[] { RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", true },
                new object[] { RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", true },
                new object[] { RegistryHive.LocalMachine, @"SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run", true },
                new object[] { RegistryHive.LocalMachine, @"SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce", true }
            };
            foreach (object[] k in keys)
            {
                RegistryHive hive = (RegistryHive)k[0];
                string sub = (string)k[1];
                bool isMachine = (bool)k[2];
                try
                {
                    using (RegistryKey rk = RegistryKey.OpenBaseKey(hive, RegistryView.Default).OpenSubKey(sub))
                    {
                        if (rk == null) continue;
                        foreach (string name in rk.GetValueNames())
                        {
                            string val = Convert.ToString(rk.GetValue(name, ""), CultureInfo.InvariantCulture);
                            if (string.IsNullOrEmpty(val) || val.StartsWith("*")) continue;
                            string note;
                            string signerText;
                            Severity sev = JudgeItem(val, out note, out signerText);
                            AuditItem it = new AuditItem();
                            it.Category = "自启动";
                            it.Name = name;
                            it.Command = val;
                            it.Location = (isMachine ? "HKLM" : "HKCU") + @"\" + sub;
                            it.SeNote(note, signerText, sev);
                            it.DeleteKind = "registry";
                            it.DeleteRef = it.Location;
                            it.DeleteValue = name;
                            list.Add(it);
                        }
                    }
                }
                catch { }
            }

            TryRegValue(list, RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", "Shell");
            TryRegValue(list, RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", "Userinit");
            TryRegValue(list, RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows", "AppInit_DLLs");
            TryRegValue(list, RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows", "LoadAppInit_DLLs");
            TryRegValue(list, RegistryHive.LocalMachine, @"SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows", "AppInit_DLLs");

            try
            {
                using (RegistryKey ifeo = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Default)
                    .OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"))
                {
                    if (ifeo != null)
                    {
                        foreach (string sub in ifeo.GetSubKeyNames())
                        {
                            using (RegistryKey sk = ifeo.OpenSubKey(sub))
                            {
                                if (sk == null) continue;
                                object dbg = sk.GetValue("Debugger");
                                if (dbg == null) continue;
                                string val = Convert.ToString(dbg, CultureInfo.InvariantCulture);
                                string note;
                                string signerText;
                                Severity sev = JudgeItem(val, out note, out signerText);
                                AuditItem it = new AuditItem();
                                it.Category = "自启动";
                                it.Name = "IFEO 调试器: " + sub;
                                it.Command = val;
                                it.Location = @"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\" + sub;
                                it.SeNote(note, signerText, sev);
                                it.DeleteKind = "registry";
                                it.DeleteRef = it.Location;
                                it.DeleteValue = "Debugger";
                                list.Add(it);
                            }
                        }
                    }
                }
            }
            catch { }

            AddStartupFolder(list, Environment.GetFolderPath(Environment.SpecialFolder.Startup));
            AddStartupFolder(list, Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup));
            return list;
        }

        private static void TryRegValue(List<AuditItem> list, RegistryHive hive, string sub, string valueName)
        {
            try
            {
                using (RegistryKey rk = RegistryKey.OpenBaseKey(hive, RegistryView.Default).OpenSubKey(sub))
                {
                    if (rk == null) return;
                    object v = rk.GetValue(valueName);
                    if (v == null) return;
                    string val = Convert.ToString(v, CultureInfo.InvariantCulture);
                    if (string.IsNullOrEmpty(val)) return;
                    string note;
                    string signerText;
                    Severity sev = JudgeItem(val, out note, out signerText);
                    AuditItem it = new AuditItem();
                    it.Category = "自启动";
                    it.Name = valueName;
                    it.Command = val;
                    it.Location = "HKLM\\" + sub;
                    it.SeNote(note, signerText, sev);
                    it.DeleteKind = "registry";
                    it.DeleteRef = it.Location;
                    it.DeleteValue = valueName;
                    list.Add(it);
                }
            }
            catch { }
        }

        private static void AddStartupFolder(List<AuditItem> list, string folder)
        {
            if (string.IsNullOrEmpty(folder) || !Directory.Exists(folder)) return;
            try
            {
                foreach (string file in Directory.GetFiles(folder))
                {
                    string ext = Path.GetExtension(file).ToLowerInvariant();
                    if (ext != ".lnk" && ext != ".exe" && ext != ".bat" && ext != ".cmd" && ext != ".vbs" && ext != ".url") continue;
                    string target = file;
                    if (ext == ".lnk")
                    {
                        try { target = ShellLinkTarget(file); } catch { }
                    }
                    string note;
                    string signerText;
                    Severity sev = JudgeItem(target, out note, out signerText);
                    AuditItem it = new AuditItem();
                    it.Category = "自启动";
                    it.Name = Path.GetFileName(file);
                    it.Command = target;
                    it.Location = folder;
                    it.SeNote(note, signerText, sev);
                    it.DeleteKind = "file";
                    it.DeleteRef = file;
                    list.Add(it);
                }
            }
            catch { }
        }

        private static string ShellLinkTarget(string lnk)
        {
            try
            {
                Type t = Type.GetTypeFromProgID("WScript.Shell");
                object shell = Activator.CreateInstance(t);
                object shortcut = t.InvokeMember("CreateShortcut", System.Reflection.BindingFlags.InvokeMethod, null, shell, new object[] { lnk });
                object target = shortcut.GetType().InvokeMember("TargetPath", System.Reflection.BindingFlags.GetProperty, null, shortcut, null);
                return Convert.ToString(target, CultureInfo.InvariantCulture);
            }
            catch { return lnk; }
        }

        public static List<AuditItem> CollectServices()
        {
            List<AuditItem> list = new List<AuditItem>();
            try
            {
                using (RegistryKey root = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Default)
                    .OpenSubKey(@"SYSTEM\CurrentControlSet\Services"))
                {
                    if (root == null) return list;
                    foreach (string name in root.GetSubKeyNames())
                    {
                        try
                        {
                            using (RegistryKey sk = root.OpenSubKey(name))
                            {
                                if (sk == null) continue;
                                object typeObj = sk.GetValue("Type");
                                if (typeObj == null) continue;
                                int type = Convert.ToInt32(typeObj, CultureInfo.InvariantCulture);
                                if ((type & 0x30) == 0) continue;
                                string image = Convert.ToString(sk.GetValue("ImagePath", ""), CultureInfo.InvariantCulture);
                                if (string.IsNullOrEmpty(image)) continue;
                                image = image.Trim();
                                string path = CommandToPath(image);
                                string note;
                                string signerText = "";
                                Severity sev;
                                if (!File.Exists(path))
                                {
                                    note = "服务程序文件不存在（卸载残留）";
                                    sev = Severity.Medium;
                                }
                                else
                                {
                                    sev = JudgeItem(image, out note, out signerText);
                                }
                                string display = Convert.ToString(sk.GetValue("DisplayName", name), CultureInfo.InvariantCulture);
                                AuditItem it = new AuditItem();
                                it.Category = "服务";
                                it.Name = display;
                                it.Command = image;
                                it.Location = @"HKLM\SYSTEM\CurrentControlSet\Services\" + name;
                                it.SeNote(note, signerText, sev);
                                list.Add(it);
                            }
                        }
                        catch { }
                    }
                }
            }
            catch { }
            return list;
        }

        public static List<AuditItem> CollectTasks()
        {
            List<AuditItem> list = new List<AuditItem>();
            string root = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "Tasks");
            if (!Directory.Exists(root)) return list;
            List<string> files = new List<string>();
            WalkXml(root, files, 0);
            foreach (string file in files)
            {
                try
                {
                    XmlDocument doc = new XmlDocument();
                    doc.Load(file);
                    XmlNamespaceManager ns = new XmlNamespaceManager(doc.NameTable);
                    ns.AddNamespace("t", "http://schemas.microsoft.com/windows/2004/02/mit/task");
                    XmlNodeList execs = doc.SelectNodes("//t:Actions/t:Exec", ns);
                    if (execs == null || execs.Count == 0) continue;
                    StringBuilder cmds = new StringBuilder();
                    foreach (XmlNode e in execs)
                    {
                        XmlNode cmd = e.SelectSingleNode("t:Command", ns);
                        XmlNode arg = e.SelectSingleNode("t:Arguments", ns);
                        if (cmd == null) continue;
                        if (cmds.Length > 0) cmds.Append(" | ");
                        cmds.Append(cmd.InnerText.Trim());
                        if (arg != null) cmds.Append(" ").Append(arg.InnerText.Trim());
                    }
                    string command = cmds.ToString();
                    if (command.Length == 0) continue;
                    string first = command.Split('|')[0].Trim();
                    string note;
                    string signerText;
                    Severity sev = JudgeItem(first, out note, out signerText);
                    XmlNode enabled = doc.SelectSingleNode("//t:Settings/t:Enabled", ns);
                    string state = (enabled != null && string.Equals(enabled.InnerText.Trim(), "false", StringComparison.OrdinalIgnoreCase)) ? "已禁用" : "已启用";
                    string rel = file.Substring(root.Length).TrimStart('\\');
                    AuditItem it = new AuditItem();
                    it.Category = "计划任务";
                    it.Name = rel.Replace(".xml", "").Replace("\\", " / ");
                    it.Command = command;
                    it.Location = file;
                    it.SeNote(note + "；" + state, signerText, sev);
                    it.DeleteKind = "taskfile";
                    it.DeleteRef = file;
                    list.Add(it);
                }
                catch { }
            }
            return list;
        }

        private static void WalkXml(string dir, List<string> files, int depth)
        {
            if (depth > 8) return;
            try
            {
                foreach (string f in Directory.GetFiles(dir, "*.xml")) files.Add(f);
                foreach (string d in Directory.GetDirectories(dir)) WalkXml(d, files, depth + 1);
            }
            catch { }
        }

        public static List<AuditItem> CollectExtra()
        {
            List<AuditItem> list = new List<AuditItem>();
            string hosts = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), @"drivers\etc\hosts");
            try
            {
                if (File.Exists(hosts))
                {
                    int suspicious = 0;
                    foreach (string raw in File.ReadAllLines(hosts))
                    {
                        string line = raw.Trim();
                        if (line.Length == 0 || line.StartsWith("#")) continue;
                        string[] parts = Regex.Split(line, @"\s+");
                        if (parts.Length < 2) continue;
                        string ip = parts[0];
                        if (ip == "127.0.0.1" || ip == "::1" || ip == "0.0.0.0") continue;
                        AuditItem it = new AuditItem();
                        it.Category = "其他";
                        it.Name = "hosts 映射: " + parts[1];
                        it.Command = line;
                        it.Location = hosts;
                        it.Sev = Severity.Low;
                        it.Note = "非本地回环映射，注意是否为广告拦截/劫持";
                        it.Signer = "-";
                        list.Add(it);
                        suspicious++;
                    }
                    if (suspicious == 0)
                    {
                        AuditItem it = new AuditItem();
                        it.Category = "其他";
                        it.Name = "hosts 文件";
                        it.Command = hosts;
                        it.Location = hosts;
                        it.Sev = Severity.Low;
                        it.Note = "无自定义映射";
                        it.Signer = "-";
                        list.Add(it);
                    }
                }
            }
            catch { }

            AddBrowserExtensions(list, Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), @"Google\Chrome\User Data"), "Chrome");
            AddBrowserExtensions(list, Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), @"Microsoft\Edge\User Data"), "Edge");
            AddBrowserExtensions(list, Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), @"BraveSoftware\Brave-Browser\User Data"), "Brave");
            return list;
        }

        private static void AddBrowserExtensions(List<AuditItem> list, string userData, string browser)
        {
            try
            {
                if (!Directory.Exists(userData)) return;
                foreach (string profile in Directory.GetDirectories(userData))
                {
                    string extDir = Path.Combine(profile, "Extensions");
                    if (!Directory.Exists(extDir)) continue;
                    foreach (string idDir in Directory.GetDirectories(extDir))
                    {
                        foreach (string verDir in Directory.GetDirectories(idDir))
                        {
                            string manifest = Path.Combine(verDir, "manifest.json");
                            if (!File.Exists(manifest)) continue;
                            string name = Path.GetFileName(idDir);
                            int perms = 0;
                            try
                            {
                                JavaScriptSerializer ser = new JavaScriptSerializer();
                                ser.MaxJsonLength = 1024 * 1024;
                                Dictionary<string, object> d = ser.Deserialize<Dictionary<string, object>>(File.ReadAllText(manifest, Encoding.UTF8));
                                object n;
                                if (d != null && d.TryGetValue("name", out n) && n != null) name = Convert.ToString(n, CultureInfo.InvariantCulture);
                                object p;
                                if (d != null && d.TryGetValue("permissions", out p) && p is object[]) perms = ((object[])p).Length;
                            }
                            catch { }
                            AuditItem it = new AuditItem();
                            it.Category = "其他";
                            it.Name = browser + " 扩展: " + name;
                            it.Command = idDir;
                            it.Location = profile;
                            it.Sev = Severity.Low;
                            it.Note = "权限项 " + perms + " 个" + (name.StartsWith("__MSG_") ? "；名称未本地化，来源需确认" : "");
                            it.Signer = "-";
                            list.Add(it);
                        }
                    }
                }
            }
            catch { }
        }
    }

    public static class AuditItemExt
    {
        public static void SeNote(this AuditItem it, string note, string signer, Severity sev)
        {
            it.Note = note;
            it.Signer = signer;
            it.Sev = sev;
        }
    }
}
