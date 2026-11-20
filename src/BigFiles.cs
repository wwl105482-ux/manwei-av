using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;

namespace GuardScan
{
    public class BigFileItem
    {
        public string Path { get; set; }
        public long Size { get; set; }
        public DateTime Modified { get; set; }
        public string Category { get; set; }
        public string Reason { get; set; }
        // true = 放心删（可再生成/可再下载），false = 疑似垃圾（删除前确认）。
        public bool Safe { get; set; }
        // 严重度：放心删=高（优先清理），疑似垃圾=中（需确认）。
        public Severity Sev { get; set; }
    }

    public class BigFileOptions
    {
        public List<string> Targets { get; set; }
        public long MinSize { get; set; }
        public bool JunkOnly { get; set; }

        public BigFileOptions()
        {
            Targets = new List<string>();
            MinSize = 50L * 1024 * 1024;
            JunkOnly = true;
        }
    }

    public static class BigFileClassifier
    {
        private static readonly string[] TempSegments = new string[]
        {
            "\\temp\\", "\\tmp\\", "\\cache\\", "\\caches\\", "\\crashdumps\\",
            "\\minidump\\", "\\livekernelreports\\", "\\dumpstack.log.tmp\\"
        };

        private static readonly HashSet<string> InstallerExt = new HashSet<string>(new string[]
        {
            ".exe", ".msi", ".msix", ".appx", ".zip", ".rar", ".7z", ".iso", ".img",
            ".cab", ".msu", ".tar", ".gz"
        }, StringComparer.OrdinalIgnoreCase);

        private static readonly HashSet<string> DiskImageExt = new HashSet<string>(new string[]
        {
            ".iso", ".img", ".vhd", ".vhdx", ".wim", ".esd"
        }, StringComparer.OrdinalIgnoreCase);

        private static readonly HashSet<string> DumpExt = new HashSet<string>(new string[]
        {
            ".dmp", ".mdmp", ".hdmp"
        }, StringComparer.OrdinalIgnoreCase);

        private static readonly HashSet<string> BackupExt = new HashSet<string>(new string[]
        {
            ".bak", ".old", ".tmp", ".temp", ".orig", ".copy"
        }, StringComparer.OrdinalIgnoreCase);

        // 返回 true 表示属于疑似垃圾；junkOnly=false 时所有大文件都返回 true。
        public static bool Classify(string path, long size, DateTime modified, bool junkOnly, out string category, out string reason)
        {
            string lower = path.ToLowerInvariant();
            string ext = Path.GetExtension(path);
            string dirName = Path.GetFileName(Path.GetDirectoryName(path));
            if (dirName == null) dirName = "";

            if (DumpExt.Contains(ext))
            {
                category = "崩溃转储";
                reason = "系统或程序崩溃转储，正常使用不需要保留";
                return true;
            }

            if (lower.Contains("\\softwaredistribution\\download\\"))
            {
                category = "系统更新缓存";
                reason = "Windows 更新下载缓存，安装完成后可清理";
                return true;
            }

            foreach (string seg in TempSegments)
            {
                if (lower.Contains(seg))
                {
                    if (lower.Contains("crashdumps") || lower.Contains("minidump") || lower.Contains("livekernelreports"))
                    {
                        category = "崩溃转储";
                        reason = "崩溃转储目录中的大文件";
                    }
                    else
                    {
                        category = "临时/缓存文件";
                        reason = "位于临时或缓存目录，通常可安全删除";
                    }
                    return true;
                }
            }

            if (lower.Contains("\\downloads\\") && InstallerExt.Contains(ext))
            {
                category = "旧安装包";
                reason = "下载目录中的安装包，安装完成后一般不再需要";
                return true;
            }

            if (DiskImageExt.Contains(ext) && (DateTime.Now - modified).TotalDays > 180)
            {
                category = "旧镜像文件";
                reason = "超过 180 天未修改的磁盘/系统镜像";
                return true;
            }

            if (BackupExt.Contains(ext))
            {
                category = "备份/临时残留";
                reason = "备份或临时后缀的残留文件";
                return true;
            }

            if (string.Equals(ext, ".log", StringComparison.OrdinalIgnoreCase) && size >= 200L * 1024 * 1024)
            {
                category = "超大日志";
                reason = "体积超过 200 MB 的日志文件";
                return true;
            }

            if (string.Equals(ext, ".pdb", StringComparison.OrdinalIgnoreCase))
            {
                category = "调试符号";
                reason = "调试符号文件，普通使用不需要";
                return true;
            }

            if (string.Equals(ext, ".etl", StringComparison.OrdinalIgnoreCase) || string.Equals(ext, ".evtx", StringComparison.OrdinalIgnoreCase))
            {
                // 系统事件日志不能删（删了会破坏审计/事件记录），只在"所有大文件"模式下展示。
                if (lower.Contains("\\winevt\\logs\\"))
                {
                    if (!junkOnly)
                    {
                        category = "大文件";
                        reason = "系统事件日志（不建议删除）";
                        return true;
                    }
                    category = "";
                    reason = "";
                    return false;
                }
                category = "跟踪/事件日志";
                reason = "系统跟踪或事件日志，可清理";
                return true;
            }

            if (!junkOnly)
            {
                category = "大文件";
                reason = "体积较大（未判定为垃圾，请自行确认）";
                return true;
            }

            category = "";
            reason = "";
            return false;
        }

        // 分类结果是否属于"放心删"：这些都能重新生成或重新下载，删掉不影响系统。
        public static bool IsSafeToDelete(string category)
        {
            if (category == null) return false;
            switch (category)
            {
                case "崩溃转储":
                case "系统更新缓存":
                case "临时/缓存文件":
                case "超大日志":
                    return true;
                default:
                    return false;
            }
        }
    }

    public class BigFileScanner
    {
        private static readonly string[] SkipDirNames = new string[]
        {
            "$recycle.bin", "system volume information", "winsxs", "driverstore",
            "servicing", "guardscan"
        };

        private readonly BigFileOptions _opt;
        private readonly HashSet<string> _skipDirs;
        private string _ownDir;
        private volatile bool _cancel;
        private int _scanned;
        private int _foundCount;
        private long _foundBytes;

        public event Action<BigFileItem> ItemFound;
        public event Action<int, int, long> ProgressChanged;
        public event Action ScanFinished;

        public int FoundCount { get { return _foundCount; } }
        public long FoundBytes { get { return _foundBytes; } }

        public BigFileScanner(BigFileOptions opt)
        {
            _opt = opt;
            _skipDirs = new HashSet<string>(SkipDirNames, StringComparer.OrdinalIgnoreCase);
            try { _ownDir = Path.GetFullPath(AppDomain.CurrentDomain.BaseDirectory).TrimEnd('\\'); }
            catch { _ownDir = null; }
        }

        public void Cancel()
        {
            _cancel = true;
        }

        public void Run()
        {
            foreach (string target in _opt.Targets)
            {
                if (_cancel) break;
                if (!Directory.Exists(target)) continue;
                Walk(target);
            }
            Action done = ScanFinished;
            if (done != null) done();
        }

        private void Walk(string root)
        {
            Stack<string> stack = new Stack<string>();
            stack.Push(root);
            while (stack.Count > 0)
            {
                if (_cancel) return;
                string dir = stack.Pop();
                DirectoryInfo di;
                try
                {
                    di = new DirectoryInfo(dir);
                    if ((di.Attributes & FileAttributes.ReparsePoint) == FileAttributes.ReparsePoint) continue;
                    if (_skipDirs.Contains(di.Name)) continue;
                    if (IsOwnDirectory(dir)) continue;
                }
                catch { continue; }

                try
                {
                    foreach (FileSystemInfo fsi in di.EnumerateFileSystemInfos())
                    {
                        if (_cancel) return;
                        FileInfo fi = fsi as FileInfo;
                        if (fi != null)
                        {
                            _scanned++;
                            long len = 0;
                            try { len = fi.Length; } catch { continue; }
                            if (len < _opt.MinSize) continue;

                            string category;
                            string reason;
                            if (!BigFileClassifier.Classify(fi.FullName, len, fi.LastWriteTime, _opt.JunkOnly, out category, out reason)) continue;

                            BigFileItem item = new BigFileItem();
                            item.Path = fi.FullName;
                            item.Size = len;
                            item.Modified = fi.LastWriteTime;
                            item.Category = category;
                            item.Reason = reason;
                            item.Safe = BigFileClassifier.IsSafeToDelete(category);
                            item.Sev = item.Safe ? Severity.High : Severity.Medium;

                            _foundCount++;
                            _foundBytes += len;
                            Action<BigFileItem> handler = ItemFound;
                            if (handler != null) handler(item);
                            continue;
                        }

                        DirectoryInfo sub = fsi as DirectoryInfo;
                        if (sub != null)
                        {
                            if ((sub.Attributes & FileAttributes.ReparsePoint) != 0) continue;
                            if (_skipDirs.Contains(sub.Name)) continue;
                            stack.Push(sub.FullName);
                        }
                    }
                }
                catch { }

                if ((_scanned % 500) == 0)
                {
                    Action<int, int, long> p = ProgressChanged;
                    if (p != null) p(_scanned, _foundCount, _foundBytes);
                }
            }
        }

        private bool IsOwnDirectory(string dir)
        {
            if (string.IsNullOrEmpty(_ownDir)) return false;
            return string.Equals(dir.TrimEnd('\\'), _ownDir, StringComparison.OrdinalIgnoreCase);
        }
    }
}
