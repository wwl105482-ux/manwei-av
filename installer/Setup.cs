using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.IO.Compression;
using System.Reflection;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Windows.Forms;
using Microsoft.Win32;

namespace ManweiSetup
{
    internal static class Program
    {
        public const string AppName = "满唯杀毒";
        public const string AppVersion = "1.0.0";
        public const string RegPath = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\满唯杀毒";

        public static bool IsAdmin
        {
            get
            {
                try
                {
                    using (WindowsIdentity id = WindowsIdentity.GetCurrent())
                        return new WindowsPrincipal(id).IsInRole(WindowsBuiltInRole.Administrator);
                }
                catch { return false; }
            }
        }

        public static bool IsAdminGroupMember
        {
            get
            {
                try
                {
                    using (WindowsIdentity id = WindowsIdentity.GetCurrent())
                    {
                        WindowsPrincipal p = new WindowsPrincipal(id);
                        SecurityIdentifier sid = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
                        return p.IsInRole(sid);
                    }
                }
                catch { return false; }
            }
        }

        public static void Log(string msg)
        {
            string line = DateTime.Now.ToString("HH:mm:ss.fff") + " " + msg + "\r\n";
            try { File.AppendAllText(Path.Combine(Path.GetTempPath(), "mwsetup.log"), line, Encoding.UTF8); } catch { }
        }

        private static string JoinArgs(string[] args)
        {
            StringBuilder sb = new StringBuilder();
            foreach (string a in args)
            {
                if (sb.Length > 0) sb.Append(' ');
                if (a != null && a.IndexOf(' ') >= 0) sb.Append('"').Append(a).Append('"');
                else sb.Append(a);
            }
            return sb.ToString();
        }

        [STAThread]
        private static int Main(string[] args)
        {
            bool silent = false;
            bool uninstall = false;
            string dir = null;
            for (int i = 0; i < args.Length; i++)
            {
                string a = args[i] ?? "";
                if (string.Equals(a, "/S", StringComparison.OrdinalIgnoreCase)) silent = true;
                else if (string.Equals(a, "/uninstall", StringComparison.OrdinalIgnoreCase)) uninstall = true;
                else if (a.StartsWith("/D=", StringComparison.OrdinalIgnoreCase)) dir = a.Substring(3).Trim('"');
                else if (a.StartsWith("/dir=", StringComparison.OrdinalIgnoreCase)) dir = a.Substring(5).Trim('"');
            }

            if (!silent && !uninstall && !IsAdmin && IsAdminGroupMember)
            {
                try
                {
                    ProcessStartInfo psi2 = new ProcessStartInfo(Application.ExecutablePath, JoinArgs(args));
                    psi2.UseShellExecute = true;
                    psi2.Verb = "runas";
                    Process.Start(psi2);
                    return 0;
                }
                catch { }
            }

            string exeName = Path.GetFileName(Application.ExecutablePath);
            if (uninstall || string.Equals(exeName, "Uninstall.exe", StringComparison.OrdinalIgnoreCase))
                return Uninstaller.Run(silent);

            if (silent)
            {
                try
                {
                    Installer.Install(dir ?? Installer.DefaultDir, true, true, false, true);
                    return 0;
                }
                catch (Exception ex)
                {
                    Log("silent install failed: " + ex);
                    Console.Error.WriteLine("INSTALL_FAILED: " + ex.Message);
                    return 1;
                }
            }

            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            Application.Run(new SetupForm());
            return 0;
        }
    }

    internal static class Installer
    {
        public static string DefaultDir
        {
            get
            {
                if (Program.IsAdmin)
                {
                    string pf = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
                    return Path.Combine(pf, Program.AppName);
                }
                string local = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
                return Path.Combine(Path.Combine(local, "Programs"), Program.AppName);
            }
        }

        // Program Files / ProgramData 这类“所有用户”位置需要管理员权限才能写。
        public static bool MachineScope(string dir)
        {
            try
            {
                string d = Path.GetFullPath(dir).TrimEnd('\\') + "\\";
                Environment.SpecialFolder[] roots = new Environment.SpecialFolder[] {
                    Environment.SpecialFolder.ProgramFiles,
                    Environment.SpecialFolder.CommonProgramFiles,
                    Environment.SpecialFolder.CommonApplicationData
                };
                foreach (Environment.SpecialFolder sf in roots)
                {
                    string r;
                    try { r = Environment.GetFolderPath(sf); } catch { r = ""; }
                    if (string.IsNullOrEmpty(r)) continue;
                    string rr = Path.GetFullPath(r).TrimEnd('\\') + "\\";
                    if (d.StartsWith(rr, StringComparison.OrdinalIgnoreCase)) return true;
                }
            }
            catch { }
            return false;
        }

        public static bool UseMachineScope(string dir)
        {
            return Program.IsAdmin && MachineScope(dir);
        }

        public static void EnsureWritable(string dir)
        {
            try
            {
                Directory.CreateDirectory(dir);
                string probe = Path.Combine(dir, ".mw-write-test");
                File.WriteAllText(probe, "x");
                try { File.Delete(probe); } catch { }
            }
            catch (Exception ex)
            {
                throw new InvalidOperationException(
                    "没有权限写入“" + dir + "”。\r\n\r\n" +
                    "请改选一个可写目录（默认是 " + DefaultDir + "），或以管理员身份运行安装包。\r\n" +
                    "（" + ex.Message + "）");
            }
        }

        public static string ExistingDir
        {
            get
            {
                RegistryKey[] roots = new RegistryKey[] { Registry.LocalMachine, Registry.CurrentUser };
                foreach (RegistryKey root in roots)
                {
                    try
                    {
                        using (RegistryKey k = root.OpenSubKey(Program.RegPath))
                        {
                            if (k == null) continue;
                            string loc = Convert.ToString(k.GetValue("InstallLocation", ""));
                            if (!string.IsNullOrEmpty(loc) && Directory.Exists(loc)) return loc;
                        }
                    }
                    catch { }
                }
                return null;
            }
        }

        public static void Install(string dir, bool desktopShortcut, bool startMenuShortcut, bool launch, bool silent)
        {
            try
            {
                InstallCore(dir, desktopShortcut, startMenuShortcut, launch, silent);
            }
            catch (Exception ex)
            {
                Program.Log("install failed: " + ex);
                throw;
            }
        }

        private static void InstallCore(string dir, bool desktopShortcut, bool startMenuShortcut, bool launch, bool silent)
        {
            if (string.IsNullOrEmpty(dir)) dir = DefaultDir;
            dir = Path.GetFullPath(dir).TrimEnd('\\');

            if (dir.Length > 180)
                throw new InvalidOperationException("安装目录过长（" + dir.Length + " 个字符），请选择更短的路径（建议不超过 180 个字符）。");
            if (Environment.OSVersion.Version.Major < 10)
                throw new InvalidOperationException("满唯杀毒 需要 Windows 10 或 Windows 11。");

            bool machine = UseMachineScope(dir);
            if (!machine)
            {
                bool machineExists = false;
                try
                {
                    using (RegistryKey k = Registry.LocalMachine.OpenSubKey(Program.RegPath)) machineExists = k != null;
                }
                catch { }
                string machineDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), Program.AppName);
                if (machineExists || Directory.Exists(machineDir))
                    throw new InvalidOperationException(
                        "检测到已安装“所有用户”版本（" + machineDir + "）。" + Environment.NewLine +
                        "请先用管理员权限卸载它（设置 → 应用 → 满唯杀毒 → 卸载），再安装当前用户版本。");
            }

            KillRunning();
            EnsureWritable(dir);
            try
            {
                DriveInfo di = new DriveInfo(Path.GetPathRoot(dir));
                if (di.AvailableFreeSpace < 50L * 1024 * 1024)
                    throw new InvalidOperationException("安装盘剩余空间不足 50 MB，请清理后重试。");
            }
            catch (InvalidOperationException) { throw; }
            catch { }
            Directory.CreateDirectory(dir);
            string rulesDir = Path.Combine(dir, "rules");
            Directory.CreateDirectory(rulesDir);

            try
            {
                Extract("app.exe", Path.Combine(dir, Program.AppName + ".exe"));
                ExtractGz("rules.json.gz", Path.Combine(rulesDir, "signatures.json"));
                Extract("readme.txt", Path.Combine(dir, "使用说明.txt"));
            }
            catch (Exception ex)
            {
                throw new InvalidOperationException(
                    "写入安装文件失败：" + ex.Message + Environment.NewLine + Environment.NewLine +
                    "如果安全软件刚刚弹过拦截提示，请把“" + dir + "”加入白名单，或临时关闭实时防护后重试。");
            }
            string appPath = Path.Combine(dir, Program.AppName + ".exe");
            if (!File.Exists(appPath) || new FileInfo(appPath).Length < 50 * 1024)
                throw new InvalidOperationException(
                    "安装文件没有成功写入“" + appPath + "”。" + Environment.NewLine + Environment.NewLine +
                    "常见原因是安全软件把释放出来的程序删除了：请把安装目录加入白名单，或临时关闭实时防护后重试。");

            // 卸载程序就是安装程序自身的一份拷贝，靠文件名进入卸载模式。
            string self = Application.ExecutablePath;
            string uninst = Path.Combine(dir, "Uninstall.exe");
            if (!string.Equals(Path.GetFullPath(self), Path.GetFullPath(uninst), StringComparison.OrdinalIgnoreCase))
                File.Copy(self, uninst, true);

            if (machine)
            {
                try { Registry.CurrentUser.DeleteSubKeyTree(Program.RegPath, false); } catch { }
                try { Uninstaller.RemoveShortcutsIn(false); } catch { }
            }
            else
            {
                try { Uninstaller.RemoveShortcutsIn(true); } catch { }
            }

            // 覆盖另一作用域的默认安装目录，避免用户级/机器级两份共存、卸载入口对不上。
            string otherDir = machine
                ? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Programs")
                : Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
            otherDir = Path.Combine(otherDir, Program.AppName);
            try
            {
                if (Directory.Exists(otherDir) &&
                    !string.Equals(Path.GetFullPath(otherDir).TrimEnd('\\'), dir, StringComparison.OrdinalIgnoreCase))
                    Directory.Delete(otherDir, true);
            }
            catch { }

            string exe = Path.Combine(dir, Program.AppName + ".exe");
            if (startMenuShortcut)
            {
                try { CreateShortcuts(dir, exe, machine); } catch { }
            }
            if (desktopShortcut)
            {
                try { CreateDesktopShortcut(exe, machine); } catch { }
            }
            WriteUninstallEntry(dir, exe, machine);

            if (launch)
            {
                try
                {
                    ProcessStartInfo psi = new ProcessStartInfo(exe);
                    psi.UseShellExecute = true;
                    psi.WorkingDirectory = dir;
                    Process.Start(psi);
                }
                catch { }
            }
            if (silent) Console.WriteLine("INSTALL_OK|" + dir);
        }

        public static void Extract(string res, string file)
        {
            using (Stream s = Assembly.GetExecutingAssembly().GetManifestResourceStream(res))
            {
                if (s == null) throw new Exception("安装包缺少资源: " + res);
                using (FileStream fs = new FileStream(file, FileMode.Create, FileAccess.Write))
                {
                    byte[] buf = new byte[81920];
                    int n;
                    while ((n = s.Read(buf, 0, buf.Length)) > 0) fs.Write(buf, 0, n);
                }
            }
        }

        public static void ExtractGz(string res, string file)
        {
            using (Stream s = Assembly.GetExecutingAssembly().GetManifestResourceStream(res))
            {
                if (s == null) throw new Exception("安装包缺少资源: " + res);
                using (GZipStream gz = new GZipStream(s, CompressionMode.Decompress))
                using (FileStream fs = new FileStream(file, FileMode.Create, FileAccess.Write))
                {
                    byte[] buf = new byte[81920];
                    int n;
                    while ((n = gz.Read(buf, 0, buf.Length)) > 0) fs.Write(buf, 0, n);
                }
            }
        }

        public static void KillRunning()
        {
            try
            {
                foreach (Process p in Process.GetProcessesByName(Program.AppName))
                {
                    try { p.Kill(); p.WaitForExit(3000); } catch { }
                }
            }
            catch { }
        }

        private static void CreateDesktopShortcut(string exe, bool machine)
        {
            string desktop = Environment.GetFolderPath(machine
                ? Environment.SpecialFolder.CommonDesktopDirectory
                : Environment.SpecialFolder.DesktopDirectory);
            CreateShortcut(Path.Combine(desktop, Program.AppName + ".lnk"), exe, exe);
        }

        private static void CreateShortcuts(string dir, string exe, bool machine)
        {
            string programs = Environment.GetFolderPath(machine
                ? Environment.SpecialFolder.CommonPrograms
                : Environment.SpecialFolder.Programs);
            string folder = Path.Combine(programs, Program.AppName);
            Directory.CreateDirectory(folder);
            CreateShortcut(Path.Combine(folder, Program.AppName + ".lnk"), exe, exe);
            CreateShortcut(Path.Combine(folder, "卸载 " + Program.AppName + ".lnk"),
                Path.Combine(dir, "Uninstall.exe"), exe);
        }

        private static void CreateShortcut(string lnkPath, string target, string iconSource)
        {
            try
            {
                Type t = Type.GetTypeFromProgID("WScript.Shell");
                object shell = Activator.CreateInstance(t);
                object lnk = t.InvokeMember("CreateShortcut", BindingFlags.InvokeMethod, null, shell, new object[] { lnkPath });
                Type lt = lnk.GetType();
                lt.InvokeMember("TargetPath", BindingFlags.SetProperty, null, lnk, new object[] { target });
                lt.InvokeMember("WorkingDirectory", BindingFlags.SetProperty, null, lnk, new object[] { Path.GetDirectoryName(target) });
                lt.InvokeMember("IconLocation", BindingFlags.SetProperty, null, lnk, new object[] { iconSource + ",0" });
                lt.InvokeMember("Description", BindingFlags.SetProperty, null, lnk, new object[] { Program.AppName });
                lt.InvokeMember("Save", BindingFlags.InvokeMethod, null, lnk, null);
            }
            catch { }
        }

        private static void WriteUninstallEntry(string dir, string exe, bool machine)
        {
            long size = 0;
            try
            {
                foreach (string f in Directory.GetFiles(dir, "*", SearchOption.AllDirectories))
                    size += new FileInfo(f).Length;
            }
            catch { }

            RegistryKey root = machine ? Registry.LocalMachine : Registry.CurrentUser;
            using (RegistryKey k = root.CreateSubKey(Program.RegPath))
            {
                k.SetValue("DisplayName", Program.AppName + " - 本地查杀与启动项审计");
                k.SetValue("DisplayVersion", Program.AppVersion);
                k.SetValue("Publisher", Program.AppName);
                k.SetValue("InstallLocation", dir);
                k.SetValue("DisplayIcon", exe + ",0");
                k.SetValue("UninstallString", "\"" + Path.Combine(dir, "Uninstall.exe") + "\"");
                k.SetValue("QuietUninstallString", "\"" + Path.Combine(dir, "Uninstall.exe") + "\" /S");
                k.SetValue("InstallDate", DateTime.Now.ToString("yyyyMMdd"));
                k.SetValue("EstimatedSize", (int)Math.Max(1, size / 1024), RegistryValueKind.DWord);
                k.SetValue("NoModify", 1, RegistryValueKind.DWord);
                k.SetValue("NoRepair", 1, RegistryValueKind.DWord);
            }
        }
    }

    internal static class Uninstaller
    {
        public static int Run(bool silent)
        {
            string dir = Path.GetDirectoryName(Application.ExecutablePath);

            if (!silent && !Program.IsAdmin && Program.IsAdminGroupMember)
            {
                try
                {
                    ProcessStartInfo psi = new ProcessStartInfo(Application.ExecutablePath, "/uninstall");
                    psi.UseShellExecute = true;
                    psi.Verb = "runas";
                    Process.Start(psi);
                    return 0;
                }
                catch { }
            }

            bool keepData = false;
            if (!silent)
            {
                DialogResult r = MessageBox.Show(
                    "确定要卸载 " + Program.AppName + " 吗？\r\n\r\n点“是”卸载，点“否”取消。",
                    Program.AppName + " 卸载", MessageBoxButtons.YesNo, MessageBoxIcon.Question);
                if (r != DialogResult.Yes) return 1;

                DialogResult r2 = MessageBox.Show(
                    "是否同时删除配置（满唯杀毒.settings.json）和历史报告（Reports 目录）？\r\n\r\n" +
                    "选“是”全部删除；选“否”保留配置与报告。",
                    Program.AppName + " 卸载", MessageBoxButtons.YesNo, MessageBoxIcon.Question);
                keepData = r2 == DialogResult.No;
            }

            Installer.KillRunning();
            try { RemoveShortcuts(); } catch { }
            try { DeleteRegistry(); } catch { }

            if (keepData) DeleteFiles(dir, true);
            else
            {
                ScheduleDelete(dir);
                try
                {
                    string local = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), Program.AppName);
                    if (!string.Equals(Path.GetFullPath(local), Path.GetFullPath(dir), StringComparison.OrdinalIgnoreCase))
                        TryDeleteDirectory(local);
                }
                catch { }
            }

            if (!silent)
                MessageBox.Show("卸载完成。", Program.AppName, MessageBoxButtons.OK, MessageBoxIcon.Information);
            else
                Console.WriteLine("UNINSTALL_OK|" + dir);
            return 0;
        }

        private static void RemoveShortcuts()
        {
            RemoveShortcutsIn(false);
            RemoveShortcutsIn(true);
        }

        internal static void RemoveShortcutsIn(bool machine)
        {
            string desktop = Environment.GetFolderPath(machine
                ? Environment.SpecialFolder.CommonDesktopDirectory
                : Environment.SpecialFolder.DesktopDirectory);
            TryDelete(Path.Combine(desktop, Program.AppName + ".lnk"));
            string folder = Path.Combine(Environment.GetFolderPath(machine
                ? Environment.SpecialFolder.CommonPrograms
                : Environment.SpecialFolder.Programs), Program.AppName);
            TryDeleteDirectory(folder);
        }

        private static void DeleteRegistry()
        {
            try { Registry.LocalMachine.DeleteSubKeyTree(Program.RegPath, false); } catch { }
            try { Registry.CurrentUser.DeleteSubKeyTree(Program.RegPath, false); } catch { }
        }

        private static void DeleteFiles(string dir, bool keepData)
        {
            foreach (string f in Directory.GetFiles(dir))
            {
                string name = Path.GetFileName(f);
                if (keepData && string.Equals(name, Program.AppName + ".settings.json", StringComparison.OrdinalIgnoreCase)) continue;
                if (string.Equals(name, "Uninstall.exe", StringComparison.OrdinalIgnoreCase)) continue;
                TryDelete(f);
            }
            foreach (string d in Directory.GetDirectories(dir))
            {
                string name = Path.GetFileName(d);
                if (keepData && string.Equals(name, "Reports", StringComparison.OrdinalIgnoreCase)) continue;
                TryDeleteDirectory(d);
            }
            if (!keepData) TryDeleteDirectory(dir);
        }

        // Uninstall.exe 自己正在运行，删不掉自己；交给一个延迟的 cmd 在进程退出后收尾。
        private static void ScheduleDelete(string dir)
        {
            try
            {
                ProcessStartInfo psi = new ProcessStartInfo("cmd.exe",
                    "/c ping -n 3 127.0.0.1 >nul & rmdir /s /q \"" + dir + "\"");
                psi.CreateNoWindow = true;
                psi.UseShellExecute = false;
                psi.WindowStyle = ProcessWindowStyle.Hidden;
                Process.Start(psi);
            }
            catch
            {
                DeleteFiles(dir, false);
            }
        }

        private static void TryDelete(string file)
        {
            try { if (File.Exists(file)) File.Delete(file); } catch { }
        }

        private static void TryDeleteDirectory(string dir)
        {
            try { if (Directory.Exists(dir)) Directory.Delete(dir, true); } catch { }
        }
    }

    internal class SetupForm : Form
    {
        private TextBox txtDir;
        private CheckBox chkDesktop;
        private CheckBox chkStart;
        private CheckBox chkLaunch;
        private Button btnInstall;
        private Button btnCancel;
        private Label lblStatus;

        public SetupForm()
        {
            Text = Program.AppName + " 安装程序";
            Width = 560;
            Height = 312;
            FormBorderStyle = FormBorderStyle.FixedDialog;
            MaximizeBox = false;
            MinimizeBox = false;
            StartPosition = FormStartPosition.CenterScreen;
            Font = new Font("Microsoft YaHei UI", 9F);
            try { Icon = Icon.ExtractAssociatedIcon(Application.ExecutablePath); } catch { }

            Label title = new Label();
            title.Text = "将 " + Program.AppName + " 安装到本机";
            title.Font = new Font("Microsoft YaHei UI", 12F, FontStyle.Bold);
            title.SetBounds(18, 16, 500, 28);
            Controls.Add(title);

            Label tip = new Label();
            tip.AutoSize = false;
            tip.Text = Program.IsAdmin
                ? "安装到 Program Files 会写入所有用户；\n配置/报告不可写时自动改存用户目录。"
                : "当前没有管理员权限，默认装到当前用户目录；\n装到 Program Files 需要以管理员身份运行。";
            tip.ForeColor = Color.DimGray;
            tip.SetBounds(18, 44, 510, 40);
            Controls.Add(tip);

            Label l1 = new Label();
            l1.Text = "安装位置：";
            l1.SetBounds(18, 92, 80, 22);
            Controls.Add(l1);

            txtDir = new TextBox();
            txtDir.SetBounds(100, 90, 340, 24);
            txtDir.Text = Installer.ExistingDir ?? Installer.DefaultDir;
            Controls.Add(txtDir);

            Button browse = new Button();
            browse.Text = "浏览...";
            browse.SetBounds(448, 88, 80, 28);
            browse.Click += delegate
            {
                using (FolderBrowserDialog d = new FolderBrowserDialog())
                {
                    d.Description = "选择安装目录";
                    if (Directory.Exists(txtDir.Text)) d.SelectedPath = txtDir.Text;
                    if (d.ShowDialog(this) == DialogResult.OK) txtDir.Text = d.SelectedPath;
                }
            };
            Controls.Add(browse);

            chkDesktop = new CheckBox();
            chkDesktop.Text = "创建桌面快捷方式";
            chkDesktop.Checked = true;
            chkDesktop.SetBounds(100, 126, 200, 22);
            Controls.Add(chkDesktop);

            chkStart = new CheckBox();
            chkStart.Text = "创建开始菜单项";
            chkStart.Checked = true;
            chkStart.SetBounds(300, 126, 200, 22);
            Controls.Add(chkStart);

            chkLaunch = new CheckBox();
            chkLaunch.Text = "安装完成后立即运行";
            chkLaunch.Checked = true;
            chkLaunch.SetBounds(100, 154, 250, 22);
            Controls.Add(chkLaunch);

            lblStatus = new Label();
            lblStatus.Text = "准备就绪。";
            lblStatus.SetBounds(18, 190, 510, 22);
            Controls.Add(lblStatus);

            btnInstall = new Button();
            btnInstall.Text = "安装";
            btnInstall.SetBounds(300, 224, 110, 34);
            btnInstall.Click += delegate { DoInstall(); };
            Controls.Add(btnInstall);

            btnCancel = new Button();
            btnCancel.Text = "取消";
            btnCancel.SetBounds(418, 224, 110, 34);
            btnCancel.Click += delegate { Close(); };
            Controls.Add(btnCancel);
        }

        private void DoInstall()
        {
            string dir = txtDir.Text.Trim();
            if (dir.Length == 0) { MessageBox.Show(this, "请填写安装目录。", Program.AppName); return; }
            try { dir = Path.GetFullPath(dir); }
            catch { MessageBox.Show(this, "安装目录不合法。", Program.AppName); return; }

            if (Directory.Exists(dir) && File.Exists(Path.Combine(dir, Program.AppName + ".exe")))
            {
                if (MessageBox.Show(this, "该目录下已有 " + Program.AppName + "，是否覆盖安装？", Program.AppName,
                    MessageBoxButtons.YesNo, MessageBoxIcon.Question) != DialogResult.Yes) return;
            }

            btnInstall.Enabled = false;
            btnCancel.Enabled = false;
            txtDir.Enabled = false;
            lblStatus.Text = "正在安装...";

            bool ok = false;
            string err = null;
            Thread t = new Thread(delegate()
            {
                try
                {
                    Installer.Install(dir, chkDesktop.Checked, chkStart.Checked, false, false);
                    ok = true;
                }
                catch (Exception ex) { err = ex.Message; }
            });
            t.IsBackground = true;
            t.Start();
            while (t.IsAlive) { Application.DoEvents(); Thread.Sleep(50); }

            if (!ok)
            {
                lblStatus.Text = "安装失败。";
                MessageBox.Show(this, "安装失败：\r\n" + err, Program.AppName, MessageBoxButtons.OK, MessageBoxIcon.Error);
                btnInstall.Enabled = true;
                btnCancel.Enabled = true;
                txtDir.Enabled = true;
                return;
            }

            lblStatus.Text = "安装完成。";
            if (chkLaunch.Checked)
            {
                try
                {
                    ProcessStartInfo psi = new ProcessStartInfo(Path.Combine(dir, Program.AppName + ".exe"));
                    psi.UseShellExecute = true;
                    psi.WorkingDirectory = dir;
                    Process.Start(psi);
                }
                catch { }
            }
            MessageBox.Show(this, Program.AppName + " 已安装到：\r\n" + dir +
                "\r\n\r\n可在“设置 → 应用 → 已安装的应用”里卸载。",
                Program.AppName, MessageBoxButtons.OK, MessageBoxIcon.Information);
            Close();
        }
    }
}
