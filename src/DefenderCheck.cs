using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Web.Script.Serialization;

namespace GuardScan
{
    // Windows Defender 二次复核：只对本地引擎标为"疑似"的文件调用系统自带的 MpCmdRun.exe，
    // 让它回答"这是不是真的恶意文件"。只报告、不删除（-DisableRemediation）。
    // 为了不拖慢扫描：单文件 15 秒超时、整体 60 秒封顶、4 路并行、结果缓存 7 天。
    public static class DefenderCheck
    {
        public const int MaxFiles = 20;
        public const int TotalSeconds = 60;
        public const int FileTimeoutMs = 15000;
        public const int Workers = 4;

        private static readonly object CacheLock = new object();
        private static Dictionary<string, string> _cache;
        private static string _cacheFile;
        private static string _mpCmdRun;
        private static bool _mpCmdRunSearched;

        public const string VerdictThreat = "threat";
        public const string VerdictClean = "clean";
        public const string VerdictTimeout = "timeout";
        public const string VerdictError = "error";

        public static bool IsAvailable
        {
            get { return MpCmdRunPath != null; }
        }

        public static string MpCmdRunPath
        {
            get
            {
                if (!_mpCmdRunSearched)
                {
                    _mpCmdRunSearched = true;
                    _mpCmdRun = FindMpCmdRun();
                }
                return _mpCmdRun;
            }
        }

        private static string FindMpCmdRun()
        {
            List<string> candidates = new List<string>();
            AddCandidate(candidates, Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles));
            AddCandidate(candidates, Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86));
            AddCandidate(candidates, Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                "Microsoft", "Windows Defender", "Platform"));
            foreach (string c in candidates)
                if (File.Exists(c)) return c;
            return null;
        }

        private static void AddCandidate(List<string> list, string programFiles)
        {
            if (string.IsNullOrEmpty(programFiles)) return;
            string direct = Path.Combine(programFiles, "Windows Defender", "MpCmdRun.exe");
            list.Add(direct);
            // 新版 Defender 的平台文件按版本号放在 Platform\\<版本>\\ 下，取版本号最大的一个。
            string platform = Path.Combine(programFiles, "Microsoft", "Windows Defender", "Platform");
            if (!Directory.Exists(platform)) return;
            string[] dirs = Directory.GetDirectories(platform);
            Array.Sort(dirs, StringComparer.OrdinalIgnoreCase);
            for (int i = dirs.Length - 1; i >= 0; i--)
                list.Add(Path.Combine(dirs[i], "MpCmdRun.exe"));
        }

        // candidates 由调用方排好序并截断到上限；本方法会阻塞到全部完成或总时限到。
        // onResult 可能被多个线程同时调用，GUI 侧需自行 Invoke 回 UI 线程。
        public static void Verify(List<Threat> candidates, Action<Threat, string> onResult, Action<string> log)
        {
            string exe = MpCmdRunPath;
            if (exe == null)
            {
                if (log != null) log("Defender 复核：未找到 MpCmdRun.exe，已跳过。");
                return;
            }
            LoadCache();

            List<Threat> todo = new List<Threat>();
            int cachedThreats = 0;
            int cachedClean = 0;
            foreach (Threat t in candidates)
            {
                string cached = CacheLookup(t);
                if (cached == null)
                {
                    todo.Add(t);
                    continue;
                }
                if (cached == VerdictThreat) cachedThreats++;
                else if (cached == VerdictClean) cachedClean++;
                if (onResult != null) onResult(t, cached);
            }
            if (todo.Count == 0)
            {
                if (log != null) log("Defender 复核：全部命中本地缓存（检出 " + cachedThreats + "，未检出 " + cachedClean + "）。");
                return;
            }

            DateTime deadline = DateTime.UtcNow.AddSeconds(TotalSeconds);
            int next = -1;
            int done = 0;
            int threats = 0;
            int fails = 0;
            DateTime started = DateTime.UtcNow;
            Thread[] workers = new Thread[Math.Min(Workers, todo.Count)];
            for (int w = 0; w < workers.Length; w++)
            {
                workers[w] = new Thread(delegate()
                {
                    while (true)
                    {
                        int i = Interlocked.Increment(ref next);
                        if (i >= todo.Count) break;
                        if (DateTime.UtcNow >= deadline) break;
                        Threat t = todo[i];
                        string verdict = ScanOne(exe, t.Path);
                        if (verdict == VerdictThreat || verdict == VerdictClean) CacheStore(t, verdict);
                        if (verdict == VerdictThreat) Interlocked.Increment(ref threats);
                        else if (verdict == VerdictTimeout || verdict == VerdictError) Interlocked.Increment(ref fails);
                        Interlocked.Increment(ref done);
                        if (onResult != null) onResult(t, verdict);
                    }
                });
                workers[w].IsBackground = true;
                workers[w].Start();
            }
            foreach (Thread th in workers) th.Join();
            SaveCache();
            int seconds = (int)Math.Round((DateTime.UtcNow - started).TotalSeconds);
            if (log != null)
                log("Defender 复核完成：" + done + " 项，检出 " + (threats + cachedThreats) +
                    " 项，失败/超时 " + fails + " 项，用时 " + seconds + " 秒" + (done < todo.Count ? "（达到总时限，其余未复核）" : "") + "。");
        }

        public static string ScanOne(string exe, string file)
        {
            if (string.IsNullOrEmpty(file) || !File.Exists(file)) return VerdictError;
            Process p = null;
            StringBuilder output = new StringBuilder();
            try
            {
                ProcessStartInfo psi = new ProcessStartInfo(exe);
                psi.Arguments = "-Scan -ScanType 3 -File \"" + file + "\" -DisableRemediation";
                psi.UseShellExecute = false;
                psi.CreateNoWindow = true;
                psi.RedirectStandardOutput = true;
                psi.RedirectStandardError = true;
                psi.WindowStyle = ProcessWindowStyle.Hidden;

                p = Process.Start(psi);
                Process proc = p;
                // 必须把输出读空，否则子进程写满管道后会卡住；同时留住文本用于判断结论。
                Thread drainOut = new Thread(delegate()
                {
                    try { string s = proc.StandardOutput.ReadToEnd(); lock (output) output.Append(s); }
                    catch { }
                });
                drainOut.IsBackground = true;
                drainOut.Start();
                Thread drainErr = new Thread(delegate()
                {
                    try { string s = proc.StandardError.ReadToEnd(); lock (output) output.Append(s); }
                    catch { }
                });
                drainErr.IsBackground = true;
                drainErr.Start();

                if (!proc.WaitForExit(FileTimeoutMs))
                {
                    try { proc.Kill(); } catch { }
                    try { proc.WaitForExit(1000); } catch { }
                    return VerdictTimeout;
                }
                try { drainOut.Join(1500); } catch { }
                try { drainErr.Join(1500); } catch { }

                string text;
                lock (output) text = output.ToString();
                string verdict;
                if (TryParseScan(text, out verdict)) return verdict;
                // 退出码 2 在“文件被占用/扫描失败”时也会出现（如 hr=0x80508023），不能单独当检出；
                // 文本里没有明确结论时，只把 0 当未检出，其余一律按复核失败处理。
                if (proc.ExitCode == 0) return VerdictClean;
                return VerdictError;
            }
            catch
            {
                return VerdictError;
            }
            finally
            {
                if (p != null) { try { p.Dispose(); } catch { } }
            }
        }

        private static bool TryParseScan(string text, out string verdict)
        {
            verdict = null;
            if (string.IsNullOrEmpty(text)) return false;
            if (text.IndexOf("Failed with hr", StringComparison.OrdinalIgnoreCase) >= 0)
            {
                verdict = VerdictError;
                return true;
            }
            if (text.IndexOf("found no threats", StringComparison.OrdinalIgnoreCase) >= 0)
            {
                verdict = VerdictClean;
                return true;
            }
            Match m = Regex.Match(text, @"found\s+(\d+)\s+threats?", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
            if (m.Success)
            {
                int n = 0;
                int.TryParse(m.Groups[1].Value, out n);
                verdict = n > 0 ? VerdictThreat : VerdictClean;
                return true;
            }
            return false;
        }

        // ---------------- 结果缓存（路径 + 大小 + 修改时间 → 结论，保留 7 天） ----------------

        private static string CacheFile
        {
            get
            {
                if (_cacheFile == null)
                {
                    string dir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "满唯杀毒");
                    try { Directory.CreateDirectory(dir); } catch { }
                    _cacheFile = Path.Combine(dir, "defender-cache.json");
                }
                return _cacheFile;
            }
        }

        private static string CacheKey(Threat t)
        {
            long ticks = 0;
            try { ticks = File.GetLastWriteTimeUtc(t.Path).Ticks; } catch { }
            return (t.Path == null ? "" : t.Path.ToLowerInvariant()) + "|" + t.Size + "|" + ticks;
        }

        private static void LoadCache()
        {
            lock (CacheLock)
            {
                if (_cache != null) return;
                _cache = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                try
                {
                    if (File.Exists(CacheFile))
                    {
                        JavaScriptSerializer ser = new JavaScriptSerializer();
                        Dictionary<string, string> loaded = ser.Deserialize<Dictionary<string, string>>(File.ReadAllText(CacheFile, Encoding.UTF8));
                        if (loaded != null)
                        {
                            long cutoff = DateTime.UtcNow.AddDays(-7).Ticks;
                            foreach (KeyValuePair<string, string> kv in loaded)
                            {
                                string[] parts = (kv.Value == null ? "" : kv.Value).Split('|');
                                long stamp;
                                if (parts.Length == 2 && long.TryParse(parts[0], out stamp) && stamp >= cutoff)
                                    _cache[kv.Key] = parts[1];
                            }
                        }
                    }
                }
                catch { }
            }
        }

        private static string CacheLookup(Threat t)
        {
            lock (CacheLock)
            {
                if (_cache == null) return null;
                string v;
                return _cache.TryGetValue(CacheKey(t), out v) ? v : null;
            }
        }

        private static void CacheStore(Threat t, string verdict)
        {
            lock (CacheLock)
            {
                if (_cache == null) return;
                _cache[CacheKey(t)] = DateTime.UtcNow.Ticks.ToString() + "|" + verdict;
            }
        }

        private static void SaveCache()
        {
            try
            {
                Dictionary<string, string> copy;
                lock (CacheLock) { copy = new Dictionary<string, string>(_cache, StringComparer.OrdinalIgnoreCase); }
                JavaScriptSerializer ser = new JavaScriptSerializer();
                File.WriteAllText(CacheFile, ser.Serialize(copy), Encoding.UTF8);
            }
            catch { }
        }
    }
}
