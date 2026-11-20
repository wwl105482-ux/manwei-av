using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Threading;

namespace GuardScan
{
    public class ScanOptions
    {
        public List<string> Targets { get; set; }
        public List<string> Exclusions { get; set; }
        public int Threads { get; set; }
        public long MaxBytes { get; set; }
        public long HashLimit { get; set; }
        public bool Heuristics { get; set; }
        public bool HashFiles { get; set; }
        // 彻底扫描：不跳过缓存目录与素材文件，行为规则读全文且不做关键词预筛。
        public bool Thorough { get; set; }

        public ScanOptions()
        {
            Targets = new List<string>();
            Exclusions = new List<string>();
            Threads = 0; // 0 = auto
            MaxBytes = 50L * 1024 * 1024;
            HashLimit = 64L * 1024 * 1024;
            Heuristics = true;
            HashFiles = true;
            Thorough = false;
        }
    }

    public class ScanEngine
    {
        // 特征串扫描窗口：二进制文件读头部 1.5 MB（覆盖 PE 头与常见载荷），
        // 脚本/文本类放大到 4 MB，因为恶意命令常藏在脚本中后段。
        public const int HeadLimit = 1536 * 1024;
        public const int HeadLimitText = 4 * 1024 * 1024;
        // 小于该值的文件一律算 MD5。
        private const long HashSmallFileLimit = 4L * 1024 * 1024;
        // 可执行文件放宽到 8 MB（恶意样本常带大型资源节）。
        private const long PeHashLimit = 8L * 1024 * 1024;
        // 超过该体积的压缩包不再解包检查，避免为巨型安装包耗时。
        private const long ArchiveSizeLimit = 512L * 1024 * 1024;
        // 单个压缩包最多解包检查这么多字节。
        private const long ArchiveBudget = 32L * 1024 * 1024;
        private const int ArchiveMaxEntries = 2000;

        private struct FileEntry
        {
            public string Path;
            public long Size;
        }

        private readonly SignatureStore _sigs;
        private readonly ScanOptions _opt;
        private readonly ConcurrentQueue<FileEntry> _queue = new ConcurrentQueue<FileEntry>();
        private readonly ConcurrentDictionary<string, byte> _seen = new ConcurrentDictionary<string, byte>(StringComparer.OrdinalIgnoreCase);
        // 同一份内容的重复文件（大小 + 修改时间相同）只算一次哈希，避免大量副本重复读盘。
        private readonly ConcurrentDictionary<string, string> _hashCache = new ConcurrentDictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        private readonly HashSet<string> _skipDirs;
        private readonly string _ownDir;
        private int _files;
        private int _threats;
        private int _skipped;
        private volatile bool _cancel;
        private volatile bool _paused;
        private volatile string _currentPath;
        private volatile bool _producerDone;

        public event Action<Threat> ThreatFound;
        public event Action<int, int> ProgressChanged;
        public event Action<string> StatusChanged;
        public event Action ScanFinished;

        public int FilesScanned { get { return _files; } }
        public int SkippedCount { get { return _skipped; } }
        public bool Cancelled { get { return _cancel; } }

        // 无论快速还是彻底都跳过的系统目录：这些目录里的内容不是用户数据，扫描价值低。
        private static readonly string[] BaseSkipDirNames = new string[]
        {
            "$recycle.bin", "system volume information", "winsxs", "driverstore",
            "servicing", "guardscan"
        };

        // 快速扫描额外跳过的浏览器/CEF 缓存：可再生、体积大，内容检测价值低；
        // WPS 的 addons 里仅这类就有近 9000 个文件。彻底扫描时不跳过。
        private static readonly string[] CacheDirNames = new string[]
        {
            "cache", "cache_data", "code cache", "gpucache", "service worker",
            "cachestorage", "shadercache", "grshadercache", "dawncache", "blob_storage", "media cache"
        };

        public ScanEngine(SignatureStore sigs, ScanOptions opt)
        {
            _sigs = sigs;
            _opt = opt;
            List<string> skip = new List<string>(BaseSkipDirNames);
            if (!_opt.Thorough) skip.AddRange(CacheDirNames);
            _skipDirs = new HashSet<string>(skip, StringComparer.OrdinalIgnoreCase);
            try { _ownDir = Path.GetFullPath(AppDomain.CurrentDomain.BaseDirectory).TrimEnd('\\'); }
            catch { _ownDir = null; }
        }

        public void Cancel()
        {
            _cancel = true;
        }

        // 暂停只让消费者线程等待，已入队的文件保留，继续后接着扫。
        public string CurrentPath { get { return _currentPath; } }

        public bool Paused { get { return _paused; } }

        public void SetPaused(bool paused)
        {
            _paused = paused;
        }

        public static int DefaultWorkerCount(ScanOptions opt)
        {
            int requested = opt == null ? 0 : opt.Threads;
            if (requested > 0) return Math.Max(1, Math.Min(32, requested));
            int auto = Environment.ProcessorCount;
            if (auto < 2) auto = 2;
            if (auto > 16) auto = 16;
            return auto;
        }

        public void Run()
        {
            int workers = DefaultWorkerCount(_opt);
            Thread producer = new Thread(Produce);
            producer.IsBackground = true;
            producer.Start();

            Thread[] threads = new Thread[workers];
            for (int i = 0; i < workers; i++)
            {
                threads[i] = new Thread(Consume);
                threads[i].IsBackground = true;
                threads[i].Start();
            }
            foreach (Thread t in threads) t.Join();

            Action done = ScanFinished;
            if (done != null) done();
        }

        private void Produce()
        {
            try
            {
                foreach (string target in _opt.Targets)
                {
                    if (_cancel) break;
                    if (!Directory.Exists(target)) continue;
                    Walk(target);
                }
            }
            finally
            {
                _producerDone = true;
            }
        }

        private void Walk(string root)
        {
            Stack<string> stack = new Stack<string>();
            stack.Push(root);
            while (stack.Count > 0)
            {
                if (_cancel) return;
                string dir = stack.Pop();
                if (IsExcluded(dir)) continue;
                try
                {
                    DirectoryInfo di = new DirectoryInfo(dir);
                    if ((di.Attributes & FileAttributes.ReparsePoint) == FileAttributes.ReparsePoint) continue;
                    if (_skipDirs.Contains(di.Name)) continue;

                    // 单次枚举同时处理文件与子目录，避免对每个目录做两遍系统调用。
                    foreach (FileSystemInfo fsi in di.EnumerateFileSystemInfos())
                    {
                        if (_cancel) return;
                        FileInfo fi = fsi as FileInfo;
                        if (fi != null)
                        {
                            FileEntry e = new FileEntry();
                            e.Path = fi.FullName;
                            try { e.Size = fi.Length; } catch { e.Size = -1; }
                            _queue.Enqueue(e);
                            continue;
                        }
                        DirectoryInfo sub = fsi as DirectoryInfo;
                        if (sub != null)
                        {
                            if ((sub.Attributes & FileAttributes.ReparsePoint) != 0) continue;
                            if (_skipDirs.Contains(sub.Name)) continue;
                            // 跳过本程序自身目录：里面的自检样本会被当成威胁，属于自报家门。
                            if (IsOwnDirectory(sub.FullName)) continue;
                            stack.Push(sub.FullName);
                        }
                    }
                }
                catch { Interlocked.Increment(ref _skipped); }
            }
        }

        private bool IsOwnDirectory(string dir)
        {
            if (string.IsNullOrEmpty(_ownDir)) return false;
            string d = dir.TrimEnd('\\');
            return string.Equals(d, _ownDir, StringComparison.OrdinalIgnoreCase);
        }

        private bool IsExcluded(string dir)
        {
            string d = dir.TrimEnd('\\');
            foreach (string ex in _opt.Exclusions)
            {
                if (string.IsNullOrEmpty(ex)) continue;
                string e = ex.TrimEnd('\\');
                if (d.StartsWith(e, StringComparison.OrdinalIgnoreCase)) return true;
            }
            return false;
        }

        private void Consume()
        {
            byte[] head = new byte[HeadLimit];
            byte[] hashBuf = new byte[128 * 1024];
            while (true)
            {
                if (_cancel) return;
                while (_paused && !_cancel) Thread.Sleep(50);
                FileEntry entry;
                if (!_queue.TryDequeue(out entry))
                {
                    if (_producerDone) return;
                    Thread.Sleep(1);
                    continue;
                }
                // 大于 50 MB 的文件留给"大文件"页，这里既不算扫描数也不报告。
                if (entry.Size > _opt.MaxBytes) continue;
                Interlocked.Increment(ref _files);
                try { Evaluate(entry, head, hashBuf); }
                catch { Interlocked.Increment(ref _skipped); }

                int files = _files;
                if ((files % 32) == 0)
                {
                    Action<int, int> p = ProgressChanged;
                    if (p != null) p(files, _threats);
                }
            }
        }

        private void Evaluate(FileEntry entry, byte[] head, byte[] hashBuf)
        {
            string path = entry.Path;
            long size = entry.Size;

            // 小文件扫描只处理 50 MB 以内的内容，更大的文件交给"大文件"页。
            if (size > _opt.MaxBytes) return;

            List<Threat> found = _sigs.MatchPath(path);

            string ext = Path.GetExtension(path);

            // 图片/字体/样式/媒体：文件名与路径规则已经跑过，内容里没有可执行代码，
            // 不再打开读取（WPS 插件目录里这类素材占文件总数六成以上）。彻底扫描时照常读内容与哈希。
            if (!_opt.Thorough && FileChecks.IsLowValueExtension(ext))
            {
                Report(found, path);
                return;
            }

            bool dataLike = FileChecks.IsDataExtension(ext);
            bool textLike = FileChecks.IsTextExtension(ext);
            bool zipLike = FileChecks.IsArchiveExtension(ext);
            bool risky = FileChecks.IsRiskyLocation(path);

            try
            {
                using (FileStream fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite, 128 * 1024, FileOptions.SequentialScan))
                {
                    long fileLen = size > 0 ? size : fs.Length;
                    int limit = textLike ? HeadLimitText : HeadLimit;
                    int want = (int)Math.Min((long)limit, fileLen);
                    if (want < 0) want = 0;
                    int headLen = 0;
                    while (headLen < want)
                    {
                        if (_cancel) return;
                        int n = fs.Read(head, headLen, want - headLen);
                        if (n <= 0) break;
                        headLen += n;
                    }

                    if (headLen > 0)
                    {
                        if (!dataLike) found.AddRange(_sigs.MatchBody(path, head, headLen));
                        // 脚本类文件再做一层行为组合判定（下载后执行、删卷影、关防护等）。
                        if (!dataLike && FileChecks.IsScriptExtension(ext))
                        {
                            // 快速扫描只检查前面的文本：1 MB 以上的压缩 JS 多为前端库，正则全文扫描会拖慢整体
                            //（实测单个 1 MB 文件约 0.5 秒），而下载/执行类行为通常出现在文件前部。
                            // 彻底扫描读完整头部（脚本 4 MB），且跳过关键词预筛，避免被混淆脚本绕过。
                            int behLen = _opt.Thorough ? headLen : Math.Min(headLen, 64 * 1024);
                            string text = DecodeText(head, behLen);
                            // 先把 -EncodedCommand / base64 载荷解出来，连同原文一起做特征串与行为匹配。
                            string expanded = ScriptDecode.Expand(text);
                            if (expanded.Length > text.Length)
                            {
                                byte[] extra = Encoding.UTF8.GetBytes(expanded.Substring(text.Length));
                                found.AddRange(_sigs.MatchBody(path, extra, extra.Length));
                            }
                            found.AddRange(_sigs.MatchBehavior(path, expanded, !_opt.Thorough));
                        }
                        if (FileChecks.IsPeHeader(head, headLen) && FileChecks.IsHeuristicCandidate(ext))
                        {
                            PeInfo pe = FileChecks.InspectPe(head, headLen);
                            ApplyHeuristics(path, pe, risky, found, true);
                        }
                    }

                    // 哈希策略：小文件全算；可执行文件放宽到 8 MB；高风险位置放宽到配置上限。
                    if (_opt.HashFiles && _sigs.HashRuleCount > 0)
                    {
                        long hashCap = HashSmallFileLimit;
                        if (FileChecks.IsExecutableExtension(ext) && PeHashLimit > hashCap) hashCap = PeHashLimit;
                        if (risky) hashCap = _opt.HashLimit;
                        if (fileLen <= hashCap)
                        {
                            string cacheKey = null;
                            try { cacheKey = fileLen + "|" + File.GetLastWriteTimeUtc(path).Ticks; }
                            catch { }
                            string md5;
                            if (cacheKey != null && _hashCache.TryGetValue(cacheKey, out md5))
                            {
                                // 命中重复文件缓存，直接复用上次的哈希。
                            }
                            else
                            {
                                md5 = Md5FromStream(fs, head, headLen, hashBuf);
                                if (cacheKey != null && md5 != null && _hashCache.Count < 100000)
                                    _hashCache.TryAdd(cacheKey, md5);
                            }
                            if (md5 != null)
                            {
                                Threat ht = _sigs.MatchHash(path, md5);
                                if (ht != null) found.Add(ht);
                            }
                        }
                    }
                }

                if (zipLike && size > 0 && size <= ArchiveSizeLimit) ScanArchive(path, found);
            }
            catch
            {
                // 文件被占用或无权限：仍保留文件名/路径规则的命中结果。
                Interlocked.Increment(ref _skipped);
                Report(found, path);
                return;
            }

            Report(found, path);
        }

        // 解包常见压缩/容器格式，检查内部条目名与小条目内容；超出预算即止，保证整体速度。
        private void ScanArchive(string path, List<Threat> found)
        {
            try
            {
                using (ZipArchive archive = ZipFile.OpenRead(path))
                {
                    long budget = ArchiveBudget;
                    int entries = 0;
                    foreach (ZipArchiveEntry entry in archive.Entries)
                    {
                        if (_cancel) return;
                        if (++entries > ArchiveMaxEntries) break;
                        if (entry.FullName.EndsWith("/")) continue;

                        string vpath = path + "\\" + entry.FullName;
                        found.AddRange(_sigs.MatchArchiveEntry(entry.Name, vpath));
                        // Office 的宏工程固定叫 vbaProject.bin，出现在容器里就说明文档带宏；
                        // 再读宏工程内容，按实际危险调用（自动执行、下载、命令行等）决定严重度。
                        if (string.Equals(entry.Name, "vbaProject.bin", StringComparison.OrdinalIgnoreCase))
                        {
                            byte[] mb = null;
                            int mlen = 0;
                            try
                            {
                                long take = Math.Min(entry.Length, 4L * 1024 * 1024);
                                if (take > 0)
                                {
                                    mb = new byte[(int)take];
                                    using (Stream ms = entry.Open())
                                    {
                                        int got = 0;
                                        while (got < mb.Length)
                                        {
                                            int n = ms.Read(mb, got, mb.Length - got);
                                            if (n <= 0) break;
                                            got += n;
                                        }
                                        mlen = got;
                                    }
                                }
                            }
                            catch { }
                            Threat mt = MacroCheck.Analyze(vpath, mb, mlen);
                            if (mt == null)
                                mt = SignatureStore.MakeThreat(vpath, "Doc.VbaMacro", "宏文档", Severity.Medium,
                                    "Office 文档内嵌 VBA 宏工程，宏可执行任意命令，打开前请确认来源");
                            found.Add(mt);
                        }

                        if (budget <= 0) continue;
                        if (entry.Length <= 0 || entry.Length > 8L * 1024 * 1024) continue;
                        try
                        {
                            byte[] buf = new byte[(int)Math.Min(262144L, entry.Length)];
                            using (Stream s = entry.Open())
                            {
                                int total = 0;
                                while (total < buf.Length)
                                {
                                    if (_cancel) return;
                                    int n = s.Read(buf, total, buf.Length - total);
                                    if (n <= 0) break;
                                    total += n;
                                }
                                if (total > 0)
                                {
                                    budget -= total;
                                    found.AddRange(_sigs.MatchBody(vpath, buf, total));
                                }
                            }
                        }
                        catch { }
                    }
                }
            }
            catch { }
        }

        private static void ApplyHeuristics(string path, PeInfo pe, bool risky, List<Threat> found, bool peLike)
        {
            string fn = Path.GetFileName(path).ToLowerInvariant();
            if (!peLike) return;
            if (FileChecks.HasDoubleExtension(fn))
            {
                found.Add(SignatureStore.MakeThreat(path, "Heur.DoubleExtension", "启发式", Severity.High,
                    "伪装扩展名（如 .pdf.exe），常见于钓鱼与投毒"));
            }
            if (!risky) return;
            string signer;
            bool signed = FileChecks.TrySignature(path, out signer);
            pe.Signed = signed;
            pe.Signer = signer;
            if (!signed)
            {
                found.Add(SignatureStore.MakeThreat(path, "Heur.UnsignedInRiskPath", "启发式", Severity.Medium,
                    "未签名的可执行文件位于临时/启动/根目录等高风险位置"));
            }
            if (pe.Packed)
            {
                found.Add(SignatureStore.MakeThreat(path, "Heur.PackedBinary", "启发式", Severity.Medium,
                    "疑似加壳/高熵程序" + (string.IsNullOrEmpty(pe.PackerName) ? "" : "（" + pe.PackerName + "）")));
            }
            if (FileChecks.IsHidden(path))
            {
                found.Add(SignatureStore.MakeThreat(path, "Heur.HiddenExecutable", "启发式", Severity.High,
                    "隐藏属性的可执行文件，常见于挖矿/后门持久化"));
            }
        }

        private void Report(List<Threat> found, string path)
        {
            if (found.Count > 0)
            {
                foreach (Threat t in found)
                {
                    string key = t.Path.ToLowerInvariant() + "|" + t.Name;
                    if (!_seen.TryAdd(key, 0)) continue;
                    Interlocked.Increment(ref _threats);
                    Action<Threat> th = ThreatFound;
                    if (th != null) th(t);
                }
            }
            _currentPath = path;
            Action<string> st = StatusChanged;
            if (st != null && (_files % 16) == 0) st(path);
        }

        private string Md5FromStream(FileStream fs, byte[] head, int headLen, byte[] buf)
        {
            using (MD5 md5 = MD5.Create())
            {
                if (_cancel) return null;
                if (headLen > 0) md5.TransformBlock(head, 0, headLen, null, 0);
                int n;
                while ((n = fs.Read(buf, 0, buf.Length)) > 0)
                {
                    if (_cancel) return null;
                    md5.TransformBlock(buf, 0, n, null, 0);
                }
                md5.TransformFinalBlock(buf, 0, 0);
                byte[] hash = md5.Hash;
                char[] hex = new char[32];
                const string digits = "0123456789abcdef";
                for (int i = 0; i < 16; i++)
                {
                    hex[i * 2] = digits[hash[i] >> 4];
                    hex[i * 2 + 1] = digits[hash[i] & 0xF];
                }
                return new string(hex);
            }
        }

        // 脚本可能是 UTF-8、带 BOM 的 UTF-16，或 PowerShell 5 默认的无 BOM UTF-16LE。
        // 按 BOM 与“隔一个字节一个 0”的特征选择解码方式，避免行为规则在 UTF-16 脚本上失效。
        private static string DecodeText(byte[] b, int len)
        {
            if (len >= 2 && b[0] == 0xFF && b[1] == 0xFE) return Encoding.Unicode.GetString(b, 2, (len - 2) & ~1);
            if (len >= 2 && b[0] == 0xFE && b[1] == 0xFF) return Encoding.BigEndianUnicode.GetString(b, 2, (len - 2) & ~1);
            int probe = Math.Min(len, 512);
            int zeros = 0;
            for (int i = 1; i < probe; i += 2) if (b[i] == 0) zeros++;
            if (probe >= 16 && zeros > probe / 4) return Encoding.Unicode.GetString(b, 0, len & ~1);
            return Encoding.UTF8.GetString(b, 0, len);
        }

        public static byte[] ReadHead(string path, int limit, out int length)
        {
            length = 0;
            try
            {
                using (FileStream fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite, 64 * 1024))
                {
                    int toRead = (int)Math.Min(limit, fs.Length);
                    if (toRead <= 0) return null;
                    byte[] buf = new byte[toRead];
                    int total = 0;
                    while (total < toRead)
                    {
                        int n = fs.Read(buf, total, toRead - total);
                        if (n <= 0) break;
                        total += n;
                    }
                    length = total;
                    return buf;
                }
            }
            catch { return null; }
        }
    }
}
