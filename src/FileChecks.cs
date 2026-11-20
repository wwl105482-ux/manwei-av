using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace GuardScan
{
    public class PeInfo
    {
        public bool IsPe;
        public bool IsDotNet;
        public List<string> SectionNames = new List<string>();
        public double MaxSectionEntropy;
        public bool Packed;
        public string PackerName = "";
        public bool Signed;
        public string Signer = "";
    }

    public static class FileChecks
    {
        private static readonly HashSet<string> ExecExtensions = new HashSet<string>(new string[]
        {
            ".exe", ".dll", ".sys", ".scr", ".ocx", ".cpl", ".com", ".drv", ".efi", ".mui"
        }, StringComparer.OrdinalIgnoreCase);

        private static readonly HashSet<string> TextExtensions = new HashSet<string>(new string[]
        {
            ".ps1", ".psm1", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh",
            ".hta", ".py", ".pyw", ".sh", ".pl", ".rb", ".txt", ".xml", ".json", ".reg", ".inf",
            ".ini", ".log", ".csv", ".php", ".asp", ".aspx", ".jsp", ".html", ".htm", ".shtml"
        }, StringComparer.OrdinalIgnoreCase);

        private static readonly HashSet<string> ArchiveExtensions = new HashSet<string>(new string[]
        {
            ".zip", ".jar", ".apk", ".whl", ".nupkg", ".vsix", ".xpi", ".crx", ".docx", ".xlsx", ".pptx", ".epub",
            ".docm", ".xlsm", ".pptm", ".dotm", ".xlam", ".xlsb"
        }, StringComparer.OrdinalIgnoreCase);

        // 数据/日志类文件：里面的字符串多半是"记录"而不是"可执行内容"，做特征串匹配只会制造噪音
        //（比如清理日志里出现了病毒名）。这类文件仍参与文件名/路径规则与哈希检查。
        private static readonly HashSet<string> DataExtensions = new HashSet<string>(new string[]
        {
            ".log", ".txt", ".json", ".xml", ".ini", ".cfg", ".dat", ".db", ".csv", ".md",
            ".html", ".htm", ".chm", ".idx", ".sqlite", ".evtx", ".etl", ".pdb",
            ".db-wal", ".db-shm", ".sqlite-wal", ".sqlite-shm"
        }, StringComparer.OrdinalIgnoreCase);

        // 启发式只针对用户可能双击运行的二进制，避免对系统目录里海量的 DLL/.mui 误报。
        private static readonly HashSet<string> HeuristicExtensions = new HashSet<string>(new string[]
        {
            ".exe", ".scr", ".com", ".cpl"
        }, StringComparer.OrdinalIgnoreCase);

        // 图片/字体/样式/媒体这类素材文件：内容里几乎不会有可执行代码，但目录里数量极大。
        // 文件名与路径规则仍会生效；这里只跳过"打开读头部 + 算哈希"的开销。
        private static readonly HashSet<string> LowValueExtensions = new HashSet<string>(new string[]
        {
            ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".webp", ".tif", ".tiff", ".psd", ".icns",
            ".svg", ".css", ".ttf", ".otf", ".woff", ".woff2", ".eot", ".fon",
            ".mp3", ".mp4", ".wav", ".avi", ".mkv", ".flac", ".ogg", ".webm", ".mov", ".wmv",
            ".m4a", ".m4v", ".aac", ".wma", ".flv", ".map"
        }, StringComparer.OrdinalIgnoreCase);

        public static bool IsLowValueExtension(string ext)
        {
            return !string.IsNullOrEmpty(ext) && LowValueExtensions.Contains(ext);
        }

        public static bool IsDataExtension(string ext)
        {
            return !string.IsNullOrEmpty(ext) && DataExtensions.Contains(ext);
        }

        public static bool IsHeuristicCandidate(string ext)
        {
            return !string.IsNullOrEmpty(ext) && HeuristicExtensions.Contains(ext);
        }

        public static bool IsExecutableExtension(string ext)
        {
            return !string.IsNullOrEmpty(ext) && ExecExtensions.Contains(ext);
        }

        // 会被 Windows 直接执行、内容通常是明文命令的脚本（不含 .txt/.log 这类记录文件）。
        private static readonly HashSet<string> ScriptExtensions = new HashSet<string>(new string[]
        {
            ".ps1", ".psm1", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh", ".hta"
        }, StringComparer.OrdinalIgnoreCase);

        public static bool IsScriptExtension(string ext)
        {
            return !string.IsNullOrEmpty(ext) && ScriptExtensions.Contains(ext);
        }

        public static bool IsTextExtension(string ext)
        {
            return !string.IsNullOrEmpty(ext) && TextExtensions.Contains(ext);
        }

        public static bool IsArchiveExtension(string ext)
        {
            return !string.IsNullOrEmpty(ext) && ArchiveExtensions.Contains(ext);
        }

        private static readonly string[] PackerMarks = new string[]
        {
            "UPX0", "UPX1", "UPX2", ".aspack", ".adata", "MPRESS1", "MPRESS2",
            ".themida", ".vmp0", ".vmp1", ".enigma1", ".enigma2", ".petite", ".nsp0", ".nsp1"
        };

        public static bool IsPeHeader(byte[] b, int len)
        {
            if (b == null || len < 0x40) return false;
            if (b[0] != 'M' || b[1] != 'Z') return false;
            int lfanew = BitConverter.ToInt32(b, 0x3C);
            if (lfanew <= 0 || lfanew + 24 > len) return false;
            return b[lfanew] == 'P' && b[lfanew + 1] == 'E' && b[lfanew + 2] == 0 && b[lfanew + 3] == 0;
        }

        public static PeInfo InspectPe(byte[] b, int len)
        {
            PeInfo info = new PeInfo();
            if (!IsPeHeader(b, len)) return info;
            info.IsPe = true;
            try
            {
                int lfanew = BitConverter.ToInt32(b, 0x3C);
                int coff = lfanew + 4;
                int numSections = BitConverter.ToUInt16(b, coff + 2);
                int sizeOptional = BitConverter.ToUInt16(b, coff + 16);
                int opt = coff + 20;
                if (opt + 2 > len) return info;
                ushort magic = BitConverter.ToUInt16(b, opt);
                bool pe32Plus = magic == 0x20B;
                int dirOffset = opt + (pe32Plus ? 112 : 96);
                if (dirOffset + 8 * 15 <= len)
                {
                    uint comRva = BitConverter.ToUInt32(b, dirOffset + 8 * 14);
                    uint comSize = BitConverter.ToUInt32(b, dirOffset + 8 * 14 + 4);
                    if (comRva != 0 && comSize != 0) info.IsDotNet = true;
                }
                int secTable = opt + sizeOptional;
                for (int i = 0; i < numSections; i++)
                {
                    int s = secTable + i * 40;
                    if (s + 40 > len) break;
                    string name = Encoding.ASCII.GetString(b, s, 8).TrimEnd('\0').Trim();
                    info.SectionNames.Add(name);
                    uint rawSize = BitConverter.ToUInt32(b, s + 16);
                    uint rawPtr = BitConverter.ToUInt32(b, s + 20);
                    int cap = (int)Math.Min(rawSize, 1024 * 1024);
                    if (rawPtr < (uint)len && cap > 0)
                    {
                        int avail = len - (int)rawPtr;
                        if (cap > avail) cap = avail;
                        if (cap > 64)
                        {
                            double e = Entropy(b, (int)rawPtr, cap);
                            if (e > info.MaxSectionEntropy) info.MaxSectionEntropy = e;
                        }
                    }
                    foreach (string mark in PackerMarks)
                    {
                        if (string.Equals(name, mark, StringComparison.OrdinalIgnoreCase))
                        {
                            info.Packed = true;
                            info.PackerName = mark;
                        }
                    }
                }
                if (info.MaxSectionEntropy > 7.2) info.Packed = true;
            }
            catch { }
            return info;
        }

        public static double Entropy(byte[] data, int offset, int count)
        {
            if (count <= 0) return 0;
            long[] counts = new long[256];
            for (int i = 0; i < count; i++) counts[data[offset + i]]++;
            double total = 0;
            for (int i = 0; i < 256; i++)
            {
                if (counts[i] == 0) continue;
                double p = (double)counts[i] / count;
                total -= p * Math.Log(p, 2);
            }
            return total;
        }

        public static bool TrySignature(string path, out string signer)
        {
            signer = "";
            try
            {
                X509Certificate cert = X509Certificate.CreateFromSignedFile(path);
                if (cert == null) return false;
                try
                {
                    X509Certificate2 cert2 = new X509Certificate2(cert);
                    signer = cert2.GetNameInfo(X509NameType.SimpleName, false);
                    if (string.IsNullOrEmpty(signer)) signer = cert2.Subject;
                }
                catch { signer = cert.Subject; }
                return true;
            }
            catch { return false; }
        }

        public static string Md5File(string path)
        {
            try
            {
                using (FileStream fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite, 1024 * 1024))
                {
                    using (MD5 md5 = MD5.Create())
                    {
                        byte[] hash = md5.ComputeHash(fs);
                        StringBuilder sb = new StringBuilder(32);
                        foreach (byte x in hash) sb.Append(x.ToString("x2"));
                        return sb.ToString();
                    }
                }
            }
            catch { return ""; }
        }

        public static bool IsRiskyLocation(string fullPath)
        {
            string p = fullPath.ToLowerInvariant();
            if (p.IndexOf("\\temp\\") >= 0) return true;
            if (p.IndexOf("\\windows\\temp\\") >= 0) return true;
            if (p.IndexOf("\\startup\\") >= 0) return true;
            if (p.IndexOf("\\start menu\\programs\\startup\\") >= 0) return true;
            if (p.IndexOf("\\appdata\\local\\temp") >= 0) return true;
            if (p.IndexOf("\\users\\public\\") >= 0) return true;
            string root = Path.GetPathRoot(fullPath);
            if (!string.IsNullOrEmpty(root))
            {
                string dir = Path.GetDirectoryName(fullPath);
                if (dir != null && string.Equals(dir.TrimEnd('\\'), root.TrimEnd('\\'), StringComparison.OrdinalIgnoreCase)) return true;
            }
            return false;
        }

        public static bool HasDoubleExtension(string fileName)
        {
            string[] docs = new string[] { "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "jpg", "jpeg", "png", "gif", "txt", "zip", "rar", "7z", "mp4", "mp3", "csv", "rtf" };
            string[] execs = new string[] { "exe", "scr", "pif", "com", "bat", "cmd", "js", "vbs", "ps1", "hta" };
            string lower = fileName.ToLowerInvariant();
            int lastDot = lower.LastIndexOf('.');
            if (lastDot <= 0) return false;
            string lastExt = lower.Substring(lastDot + 1);
            if (Array.IndexOf(execs, lastExt) < 0) return false;
            string before = lower.Substring(0, lastDot);
            int prevDot = before.LastIndexOf('.');
            if (prevDot <= 0) return false;
            string prevExt = before.Substring(prevDot + 1);
            return Array.IndexOf(docs, prevExt) >= 0;
        }

        public static bool IsHidden(string fullPath)
        {
            try
            {
                FileAttributes a = File.GetAttributes(fullPath);
                return (a & FileAttributes.Hidden) == FileAttributes.Hidden;
            }
            catch { return false; }
        }
    }
}
