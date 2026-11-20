using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Web.Script.Serialization;
using System.Windows.Forms;

namespace GuardScan
{
    static class Program
    {
        // 程序版本：与 src\AssemblyInfo.cs 里的 AssemblyVersion 保持一致。
        public const string AppVersion = "1.0.0";
        [DllImport("user32.dll", CharSet = CharSet.Unicode)]
        private static extern IntPtr FindWindow(string cls, string title);

        [DllImport("user32.dll")]
        private static extern bool ShowWindow(IntPtr h, int cmd);

        [DllImport("user32.dll")]
        private static extern bool SetForegroundWindow(IntPtr h);

        [STAThread]
        static int Main(string[] args)
        {
            try { Console.OutputEncoding = System.Text.Encoding.UTF8; } catch { }

            if (args.Length > 0 && string.Equals(args[0], "--selftest", StringComparison.OrdinalIgnoreCase))
                return SelfTest.Run();

            if (args.Length > 1 && string.Equals(args[0], "--check-rules", StringComparison.OrdinalIgnoreCase))
            {
                RuleSet crs; string cerr;
                bool cok = RulePack.Validate(args[1], out crs, out cerr);
                Console.WriteLine("CHECK|" + (cok ? "ok" : "fail") + "|" + cerr);
                return cok ? 0 : 1;
            }

            if (args.Length > 1 && string.Equals(args[0], "--import-rules", StringComparison.OrdinalIgnoreCase))
            {
                string imsg;
                bool iok = RulePack.Import(args[1], out imsg);
                Console.WriteLine("IMPORT|" + (iok ? "ok" : "fail") + "|" + imsg);
                return iok ? 0 : 1;
            }

            if (args.Length > 0 && string.Equals(args[0], "--diag", StringComparison.OrdinalIgnoreCase))
            {
                // 排障用：输出诊断信息；带路径时同时写入文件。
                SignatureStore dsigs = new SignatureStore();
                dsigs.Load(SignatureStore.DefaultRulePath);
                string dtext = Diagnostics.Build(dsigs, Diagnostics.LoadSettings(), "");
                Console.WriteLine(dtext);
                if (args.Length > 1)
                {
                    try
                    {
                        File.WriteAllText(args[1], dtext, Encoding.UTF8);
                        Console.WriteLine("DIAG_FILE|" + args[1]);
                    }
                    catch (Exception dex) { Console.WriteLine("DIAG_ERROR|" + dex.Message); return 1; }
                }
                return 0;
            }

            if (args.Length > 1 && string.Equals(args[0], "--defender-check", StringComparison.OrdinalIgnoreCase))
            {
                // 调试用：直接看 MpCmdRun 对单个文件的结论（只报告，不删除）。
                string mp = DefenderCheck.MpCmdRunPath;
                Console.WriteLine("MPCMDRUN|" + (mp == null ? "not-found" : mp));
                Console.WriteLine("VERDICT|" + DefenderCheck.ScanOne(mp, args[1]));
                return 0;
            }

            if (args.Length > 1 && string.Equals(args[0], "--defender-batch", StringComparison.OrdinalIgnoreCase))
            {
                // 调试用：扫描目录，把“疑似”项交给 Defender 批量复核，打印逐项结论与耗时。
                SignatureStore bsigs = new SignatureStore();
                bsigs.Load(SignatureStore.DefaultRulePath);
                ScanOptions bopt2 = new ScanOptions();
                bopt2.Targets.Add(args[1]);
                ScanEngine beng = new ScanEngine(bsigs, bopt2);
                System.Collections.Generic.List<Threat> bfound = new System.Collections.Generic.List<Threat>();
                beng.ThreatFound += delegate(Threat t) { lock (bfound) bfound.Add(t); };
                beng.Run();
                System.Collections.Generic.List<Threat> bsus = new System.Collections.Generic.List<Threat>();
                foreach (Threat t in bfound)
                    if (!ThreatSafety.IsSafeToDelete(t)) bsus.Add(t);
                Console.WriteLine("SUSPECTS|" + bsus.Count);
                Stopwatch bsw = Stopwatch.StartNew();
                object block = new object();
                DefenderCheck.Verify(bsus,
                    delegate(Threat t, string v)
                    {
                        lock (block) Console.WriteLine("VERDICT|" + v + "|" + t.Name + "|" + t.Path + "|" + bsw.ElapsedMilliseconds + "ms");
                    },
                    delegate(string m) { lock (block) Console.WriteLine("LOG|" + m); });
                Console.WriteLine("DONE|" + bsw.ElapsedMilliseconds + "ms");
                return 0;
            }

            if (args.Length > 0 && string.Equals(args[0], "--info", StringComparison.OrdinalIgnoreCase))
                return PrintInfo();

            if (args.Length > 0 && string.Equals(args[0], "--scan", StringComparison.OrdinalIgnoreCase))
                return HeadlessScan(args);

            if (args.Length > 0 && string.Equals(args[0], "--bigfiles", StringComparison.OrdinalIgnoreCase))
            {
                BigFileOptions bopt = new BigFileOptions();
                if (args.Length > 1) bopt.Targets.Add(args[1]);
                else bopt.Targets.Add("C:\\");
                int minMb = 100;
                if (args.Length > 2) { try { minMb = int.Parse(args[2]); } catch { minMb = 100; } }
                bopt.MinSize = (long)minMb * 1024 * 1024;
                bopt.JunkOnly = !(args.Length > 3 && string.Equals(args[3], "all", StringComparison.OrdinalIgnoreCase));

                BigFileScanner scanner = new BigFileScanner(bopt);
                bool header = true;
                scanner.ItemFound += delegate(BigFileItem it)
                {
                    if (header) { Console.WriteLine("BIGHDR|minMB=" + minMb + "|target=" + bopt.Targets[0]); header = false; }
                    Console.WriteLine("BIG|" + (it.Size / (1024 * 1024)) + "|" + it.Category + "|" + it.Reason + "|" + it.Path);
                };
                scanner.Run();
                Console.WriteLine("BIGSUM|" + scanner.FoundCount + "|" + (scanner.FoundBytes / (1024 * 1024)));
                return 0;
            }

            if (args.Length > 0 && string.Equals(args[0], "--quick-targets", StringComparison.OrdinalIgnoreCase))
            {
                // print quick-scan coverage only, no UI
                System.Collections.Generic.List<string> quick = MainForm.BuildQuickTargets();
                for (int i = 0; i < quick.Count; i++) Console.WriteLine("TARGET|" + quick[i]);
                Console.WriteLine("COUNT|" + quick.Count);
                return 0;
            }

            string guiScan = null;
            bool guiAudit = false;
            bool guiBig = false;
            for (int i = 0; i < args.Length; i++)
            {
                if (string.Equals(args[i], "--gui-scan", StringComparison.OrdinalIgnoreCase) && i + 1 < args.Length)
                    guiScan = args[i + 1];
                else if (string.Equals(args[i], "--gui-audit", StringComparison.OrdinalIgnoreCase))
                    guiAudit = true;
                else if (string.Equals(args[i], "--gui-big", StringComparison.OrdinalIgnoreCase))
                    guiBig = true;
            }
            MainForm.PendingBigScan = guiBig;

            if (!IsAdmin())
            {
                string choice = LoadElevationChoice();
                if (choice == "always")
                {
                    if (TryRelaunchAdmin(args)) return 0;
                }
                else if (choice == "never")
                {
                    // 用户选择始终以普通用户运行：继续受限启动，不再询问。
                }
                else
                {
                    using (ElevationDialog dlg = new ElevationDialog())
                    {
                        DialogResult r = dlg.ShowDialog();
                        if (dlg.Remember)
                            SaveElevationChoice(r == DialogResult.Yes ? "always" : "never");
                        if (r == DialogResult.Yes && TryRelaunchAdmin(args)) return 0;
                    }
                }
            }

            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            Application.SetUnhandledExceptionMode(UnhandledExceptionMode.CatchException);
            Application.ApplicationExit += delegate { MainForm.CleanupTray(); };
            Application.ThreadException += delegate(object sender, ThreadExceptionEventArgs e)
            {
                MainForm.CleanupTray();
                try
                {
                    MessageBox.Show("程序遇到错误，即将退出：\r\n" + e.Exception.Message, "满唯杀毒", MessageBoxButtons.OK, MessageBoxIcon.Error);
                }
                catch { }
                Environment.Exit(1);
            };
            AppDomain.CurrentDomain.UnhandledException += delegate(object sender, UnhandledExceptionEventArgs e)
            {
                MainForm.CleanupTray();
            };

            bool created;
            using (Mutex mutex = new Mutex(true, "ManweiAV_SingleInstance", out created))
            {
                if (!created)
                {
                    IntPtr existing = FindWindow(null, "满唯杀毒 - 本地查杀与启动项审计");
                    if (existing != IntPtr.Zero)
                    {
                        ShowWindow(existing, 9);
                        SetForegroundWindow(existing);
                    }
                    return 0;
                }
                Application.Run(new MainForm(guiScan, guiAudit));
            }
            return 0;
        }

        private static bool TryRelaunchAdmin(string[] args)
        {
            try
            {
                ProcessStartInfo psi = new ProcessStartInfo(Application.ExecutablePath);
                psi.UseShellExecute = true;
                psi.Verb = "runas";
                psi.Arguments = JoinArgs(args);
                Process.Start(psi);
                return true;
            }
            catch (Exception ex)
            {
                MessageBox.Show("提权失败，将以普通用户权限运行（部分审计项不可见）：\n" + ex.Message,
                    "满唯杀毒", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return false;
            }
        }

        // "ask" = 每次询问；"always" = 自动提权；"never" = 直接普通用户运行。
        public static string LoadElevationChoice()
        {
            try
            {
                string file = AppPaths.SettingsFile;
                if (!File.Exists(file)) return "ask";
                JavaScriptSerializer ser = new JavaScriptSerializer();
                AppSettings st = ser.Deserialize<AppSettings>(File.ReadAllText(file, Encoding.UTF8));
                if (st == null || string.IsNullOrEmpty(st.Elevation)) return "ask";
                return st.Elevation;
            }
            catch { return "ask"; }
        }

        private static void SaveElevationChoice(string value)
        {
            try
            {
                string file = AppPaths.SettingsFile;
                JavaScriptSerializer ser = new JavaScriptSerializer();
                AppSettings st = null;
                if (File.Exists(file))
                    st = ser.Deserialize<AppSettings>(File.ReadAllText(file, Encoding.UTF8));
                if (st == null) st = new AppSettings();
                st.Elevation = value;
                File.WriteAllText(file, ser.Serialize(st), Encoding.UTF8);
            }
            catch { }
        }

        private static string JoinArgs(string[] args)
        {
            if (args == null || args.Length == 0) return "";
            string[] quoted = new string[args.Length];
            for (int i = 0; i < args.Length; i++)
            {
                string a = args[i] == null ? "" : args[i];
                quoted[i] = a.IndexOf(' ') >= 0 ? ("\"" + a + "\"") : a;
            }
            return string.Join(" ", quoted);
        }

        public static bool IsAdmin()
        {
            try
            {
                using (WindowsIdentity id = WindowsIdentity.GetCurrent())
                {
                    return new WindowsPrincipal(id).IsInRole(WindowsBuiltInRole.Administrator);
                }
            }
            catch { return false; }
        }

        // 排障用：打印运行环境、规则、目录、Defender 可用性。让对方在别的电脑上跑这个，把输出发回来。
        private static int PrintInfo()
        {
            SignatureStore sigs = new SignatureStore();
            sigs.Load(SignatureStore.DefaultRulePath);
            Console.WriteLine("APP|满唯杀毒|ver=" + AppVersion + "|clr=" + typeof(object).Assembly.GetName().Version +
                "|os=" + Environment.OSVersion.VersionString +
                "|64bit=" + Environment.Is64BitOperatingSystem +
                "|admin=" + IsAdmin());
            Console.WriteLine("SHA|" + SignatureStore.Sha256File(System.Windows.Forms.Application.ExecutablePath));
            try
            {
                AppSettings st = Diagnostics.LoadSettings();
                StringBuilder drives = new StringBuilder();
                foreach (DriveInfo d in DriveInfo.GetDrives())
                {
                    if (d.DriveType != DriveType.Fixed && d.DriveType != DriveType.Removable) continue;
                    if (drives.Length > 0) drives.Append(",");
                    drives.Append(d.Name.Substring(0, 2) + "=" + d.DriveType);
                }
                Console.WriteLine("DRIVES|" + drives + "|includeRemovable=" + st.IncludeRemovable);
            }
            catch { }
            string net = "";
            try
            {
                using (Microsoft.Win32.RegistryKey k = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(
                    @"SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full"))
                {
                    if (k != null) net = Convert.ToString(k.GetValue("Release", ""));
                }
            }
            catch { }
            Console.WriteLine("NETFX|" + net);
            Console.WriteLine("RULES|" + SignatureStore.DefaultRulePath + "|" + sigs.Rules.Version +
                "|hash=" + sigs.Rules.Hashes.Count + "|strings=" + sigs.Rules.Strings.Count +
                "|names=" + sigs.Rules.Names.Count + "|paths=" + sigs.Rules.Paths.Count +
                "|behaviors=" + sigs.Rules.Behaviors.Count +
                "|error=" + (sigs.LoadError == null ? "" : sigs.LoadError));
            Console.WriteLine("DATA|" + AppPaths.DataDir + "|portable=" + AppPaths.IsPortable);
            Console.WriteLine("DEFENDER|" + (DefenderCheck.MpCmdRunPath == null ? "not-found" : DefenderCheck.MpCmdRunPath));
            try
            {
                System.Drawing.Rectangle wa = Screen.PrimaryScreen.WorkingArea;
                Console.WriteLine("SCREEN|" + wa.Width + "x" + wa.Height + "|dpi=" + (int)System.Drawing.Graphics.FromHwnd(IntPtr.Zero).DpiX);
            }
            catch { }
            return 0;
        }

        private static int HeadlessScan(string[] args)
        {
            SignatureStore sigs = new SignatureStore();
            sigs.Load(SignatureStore.DefaultRulePath);
            ScanOptions opt = new ScanOptions();
            for (int i = 1; i < args.Length; i++)
            {
                if (string.Equals(args[i], "--thorough", StringComparison.OrdinalIgnoreCase))
                {
                    opt.Thorough = true;
                    continue;
                }
                opt.Targets.Add(args[i]);
            }
            if (opt.Targets.Count == 0)
            {
                opt.Targets.Add(System.IO.Path.GetTempPath());
            }
            opt.Threads = 0; // 自动（按 CPU 核心数）
            ScanEngine eng = new ScanEngine(sigs, opt);
            int threats = 0;
            eng.ThreatFound += delegate (Threat t)
            {
                threats++;
                Console.WriteLine("THREAT|" + Sev.Text(t.Sev) + "|" + t.Name + "|" + t.Path);
            };
            eng.Run();
            Console.WriteLine("SUMMARY|files=" + eng.FilesScanned + "|threats=" + threats + "|skipped=" + eng.SkippedCount);
            return 0;
        }
    }

    // 首次以普通用户启动时询问是否提权；可勾选“记住我的选择”。
    internal class ElevationDialog : Form
    {
        private CheckBox chkRemember;

        public bool Remember { get { return chkRemember.Checked; } }

        public ElevationDialog()
        {
            Text = "满唯杀毒";
            Width = 430;
            Height = 214;
            FormBorderStyle = FormBorderStyle.FixedDialog;
            MaximizeBox = false;
            MinimizeBox = false;
            ShowInTaskbar = false;
            StartPosition = FormStartPosition.CenterScreen;
            Font = new Font("Microsoft YaHei UI", 9F);
            try { Icon = Icon.ExtractAssociatedIcon(Application.ExecutablePath); } catch { }

            Label tip = new Label();
            tip.AutoSize = false;
            tip.Text = "满唯杀毒 需要管理员权限才能完整审计启动项与服务。\n是否以管理员身份重新启动？";
            tip.SetBounds(16, 14, 390, 46);
            Controls.Add(tip);

            chkRemember = new CheckBox();
            chkRemember.Text = "记住我的选择（以后不再询问）";
            chkRemember.SetBounds(16, 70, 300, 22);
            Controls.Add(chkRemember);

            Label note = new Label();
            note.AutoSize = false;
            note.ForeColor = Color.DimGray;
            note.Text = "以普通用户运行也能扫描和清理，但 HKLM 启动项/服务审计会不全。";
            note.SetBounds(16, 96, 390, 30);
            Controls.Add(note);

            Button yes = new Button();
            yes.Text = "是，以管理员重启";
            yes.DialogResult = DialogResult.Yes;
            yes.SetBounds(110, 138, 150, 32);
            Controls.Add(yes);

            Button no = new Button();
            no.Text = "否，直接运行";
            no.DialogResult = DialogResult.No;
            no.SetBounds(272, 138, 130, 32);
            Controls.Add(no);

            AcceptButton = yes;
            CancelButton = no;
        }
    }
}
