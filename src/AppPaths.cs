using System;
using System.IO;

namespace GuardScan
{
    // 配置与报告的落地位置：优先 exe 同目录（绿色便携），不可写时退回 %LOCALAPPDATA%\满唯杀毒，
    // 避免程序被放到 Program Files 或只读目录后设置保存失败、报告导不出来。
    public static class AppPaths
    {
        private static string _dataDir;

        public static string BaseDir
        {
            get
            {
                try { return Path.GetFullPath(AppDomain.CurrentDomain.BaseDirectory).TrimEnd('\\'); }
                catch { return AppDomain.CurrentDomain.BaseDirectory; }
            }
        }

        public static string DataDir
        {
            get
            {
                if (_dataDir != null) return _dataDir;
                string baseDir = BaseDir;
                if (CanWrite(baseDir))
                {
                    _dataDir = baseDir;
                    return _dataDir;
                }
                string local = null;
                try
                {
                    local = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "满唯杀毒");
                    Directory.CreateDirectory(local);
                }
                catch { }
                _dataDir = (local != null && CanWrite(local)) ? local : baseDir;
                return _dataDir;
            }
        }

        public static string SettingsFile { get { return Path.Combine(DataDir, "满唯杀毒.settings.json"); } }

        public static string ReportsDir { get { return Path.Combine(DataDir, "Reports"); } }

        public static bool IsPortable
        {
            get { return string.Equals(DataDir, BaseDir, StringComparison.OrdinalIgnoreCase); }
        }

        private static bool CanWrite(string dir)
        {
            try
            {
                Directory.CreateDirectory(dir);
                string probe = Path.Combine(dir, ".mw-write-test");
                File.WriteAllText(probe, "x");
                File.Delete(probe);
                return true;
            }
            catch { return false; }
        }
    }
}
