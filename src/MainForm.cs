using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.Globalization;
using System.IO;
using System.Text;
using System.Threading;
using System.Web.Script.Serialization;
using System.Windows.Forms;
using Microsoft.Win32;

namespace GuardScan
{
    public class MainForm : Form
    {
        private SignatureStore _sigs = new SignatureStore();
        private AppSettings _settings = new AppSettings();
        private ScanEngine _engine;
        private Thread _scanThread;
        private int _scanGen;
        private DateTime _scanStarted;
        private TextBox txtThreatFilter;
        private int _sortColumn = -1;
        private bool _sortAsc = true;
        private CheckBox chkRemovable;
        private CheckBox chkRemovableBig;
        private ToolStripMenuItem _removableItem;
        private bool _syncingRemovable;
        private ToolStripMenuItem _pauseItem;
        private readonly List<Threat> _threats = new List<Threat>();
        private readonly List<AuditItem> _audit = new List<AuditItem>();
        private DateTime _lastStatus = DateTime.MinValue;
        private bool _scanning;
        private bool _stopRequested;
        private bool _bigStopRequested;
        private float _uiScale = 1f;

        private TabControl tabs;
        private ComboBox cboTarget;
        private Button btnBrowse;
        private Button btnStart;
        private Button btnStop;
        private CheckBox chkThorough;
        private Label lblStatus;
        private Label lblCounts;
        private Label lblThreatSummary;
        private Label lblThreatMaybe;
        private CheckBox chkSumSafe;
        private CheckBox chkSumMaybe;
        private Label lblBigMaybe;
        private CheckBox chkBigSumSafe;
        private CheckBox chkBigSumMaybe;
        private bool _syncingSummary;
        private ListView lvThreats;
        private Button btnDelete;
        private Button btnLocate;
        private Button btnExport;
        private Button btnSelectAll;

        private Button btnAudit;
        private Button btnAuditDelete;
        private ComboBox cboCategory;
        private ListView lvAudit;
        private Label lblAuditStatus;
        private ContextMenuStrip auditMenu;

        private RichTextBox rtbLog;
        private NotifyIcon tray;
        private static NotifyIcon _trayRef;
        public static bool PendingBigScan;

        private ComboBox cboBigScope;
        private Button btnBigBrowse;
        private Button btnBigStart;
        private Button btnBigStop;
        private ListView lvBig;
        private ListViewGroup grpSafe;
        private ListViewGroup grpMaybe;
        private ListViewGroup grpThreatSafe;
        private ListViewGroup grpThreatMaybe;
        private Button btnBigSelectAll;
        private TextBox txtBigDetail;
        private string _customDir;
        // 当前系统上的固定磁盘（"C:"、"D:"…）：下拉框与扫描都以此为准，插新盘后自动更新。
        private readonly List<string> _scopes = new List<string>();
        private TextBox txtThreatDetail;
        private Button btnBigDelete;
        private Button btnBigLocate;
        private Button btnBigExport;
        private Label lblBigStatus;
        private Label lblBigSummary;
        private BigFileScanner _bigScanner;
        private Thread _bigThread;
        private string _bigCustomDir;
        private bool _bigScanning;
        private readonly List<BigFileItem> _bigItems = new List<BigFileItem>();

        public MainForm()
        {
            InitUi(null, false);
        }

        public MainForm(string startupScan)
        {
            InitUi(startupScan, false);
        }

        public MainForm(string startupScan, bool startupAudit)
        {
            InitUi(startupScan, startupAudit);
        }

        private void InitUi(string startupScan, bool startupAudit)
        {
            Text = "满唯杀毒 - 本地查杀与启动项审计";
            Width = 1120;
            Height = 720;
            MinimumSize = new Size(900, 600);
            StartPosition = FormStartPosition.CenterScreen;
            Font = new Font("Microsoft YaHei UI", 9F);

            try { Icon = Icon.ExtractAssociatedIcon(Application.ExecutablePath); }
            catch { }

            try
            {
                using (Graphics g = CreateGraphics())
                {
                    float dpi = g.DpiX;
                    if (dpi > 0) _uiScale = Math.Max(1f, dpi / 96f);
                }
            }
            catch
            {
                _uiScale = 1f;
            }

            // 小屏笔记本（1366x768）或高缩放（125%/150%）下窗口可能比工作区还大，按工作区收缩一次。
            try
            {
                Rectangle wa = Screen.PrimaryScreen.WorkingArea;
                int w = Math.Min(Width, wa.Width - 24);
                int h = Math.Min(Height, wa.Height - 56); // 预留标题栏
                if (w < Width || h < Height)
                {
                    int minW = Math.Min(900, Math.Max(640, w));
                    int minH = Math.Min(600, Math.Max(420, h));
                    MinimumSize = new Size(minW, minH);
                    Width = Math.Max(minW, w);
                    Height = Math.Max(minH, h);
                }
            }
            catch { }

            LoadSettings();
            _sigs.Load(SignatureStore.DefaultRulePath);

            BuildUi();
            BuildTray();
            AppendLog("满唯杀毒 已启动，程序构建时间 " + BuildStamp() + "，规则库版本 " + _sigs.Rules.Version + "（哈希 " + _sigs.Rules.Hashes.Count + " / 特征串 " + _sigs.Rules.Strings.Count + " / 文件名 " + _sigs.Rules.Names.Count + " / 路径 " + _sigs.Rules.Paths.Count + " / 行为 " + _sigs.Rules.Behaviors.Count + "）");
            if (!string.IsNullOrEmpty(_sigs.LoadError)) AppendLog("规则库提示: " + _sigs.LoadError);
            try
            {
                string ruleHash = SignatureStore.Sha256File(SignatureStore.DefaultRulePath);
                if (!string.IsNullOrEmpty(ruleHash) && !string.Equals(ruleHash, RulesHash.Sha256, StringComparison.OrdinalIgnoreCase))
                    AppendLog("规则库校验：当前规则文件与随程序发布的版本不同（可能导入过规则包或被外部修改），请确认来源。");
            }
            catch { }
            AppendLog("当前权限: " + (Program.IsAdmin() ? "管理员" : "普通用户（部分审计项不可见）"));
            AppendLog("配置与报告目录: " + AppPaths.DataDir + (AppPaths.IsPortable ? "（便携模式）" : "（程序目录不可写，已改用用户目录）"));

            if (startupAudit)
            {
                tabs.SelectedIndex = 2;
                Shown += delegate { RunAudit(); };
            }
            RefreshScopes();

            if (PendingBigScan)
            {
                tabs.SelectedIndex = 1;
                Shown += delegate
                {
                    cboBigScope.SelectedIndex = 0;
                    StartBigScan();
                };
            }
            if (!string.IsNullOrEmpty(startupScan))
            {
                _customDir = startupScan;
                RefreshScopes();
                cboTarget.SelectedIndex = cboTarget.Items.Count - 1;
                Shown += delegate { StartScan(); };
            }
        }

        private int Px(int v)
        {
            return (int)Math.Round(v * _uiScale);
        }

        private void BuildUi()
        {
            tabs = new TabControl();
            tabs.Dock = DockStyle.Fill;
            Controls.Add(tabs);

            TabPage scanPage = new TabPage("小文件");
            TabPage bigPage = new TabPage("大文件");
            TabPage auditPage = new TabPage("启动项审计");
            TabPage logPage = new TabPage("日志");
            tabs.TabPages.Add(scanPage);
            tabs.TabPages.Add(bigPage);
            tabs.TabPages.Add(auditPage);
            tabs.TabPages.Add(logPage);

            BuildScanPage(scanPage);
            BuildBigPage(bigPage);
            BuildAuditPage(auditPage);
            rtbLog = new RichTextBox();
            rtbLog.Dock = DockStyle.Fill;
            rtbLog.ReadOnly = true;
            rtbLog.BackColor = Color.FromArgb(30, 30, 30);
            rtbLog.ForeColor = Color.Gainsboro;
            rtbLog.Font = new Font("Consolas", 9F);
            rtbLog.HideSelection = false;
            logPage.Controls.Add(rtbLog);

            StatusStrip ss = new StatusStrip();
            ToolStripStatusLabel tip = new ToolStripStatusLabel("提示：扫描只读；删除操作均需二次确认。");
            ss.Items.Add(tip);
            Controls.Add(ss);
        }

        private void BuildScanPage(TabPage page)
        {
            Panel top = new Panel();
            top.Dock = DockStyle.Top;
            top.Height = Px(128);
            page.Controls.Add(top);

            Label l1 = new Label();
            l1.Text = "扫描范围";
            l1.Location = new Point(12, Px(16));
            l1.AutoSize = true;
            top.Controls.Add(l1);

            cboTarget = new ComboBox();
            cboTarget.DropDownStyle = ComboBoxStyle.DropDownList;
            cboTarget.Location = new Point(80, Px(12));
            cboTarget.Width = 250;
            cboTarget.DropDown += delegate { RefreshScopes(); };
            top.Controls.Add(cboTarget);

            btnBrowse = new Button();
            btnBrowse.Text = "选择目录";
            btnBrowse.Location = new Point(340, Px(10));
            btnBrowse.Width = 90;
            btnBrowse.Height = Px(30);
            btnBrowse.Click += delegate { BrowseFolder(); };
            top.Controls.Add(btnBrowse);

            btnStart = new Button();
            btnStart.Text = "开始扫描";
            btnStart.Location = new Point(445, Px(10));
            btnStart.Width = 100;
            btnStart.Height = Px(30);
            btnStart.Click += delegate { StartScan(); };
            top.Controls.Add(btnStart);

            btnStop = new Button();
            btnStop.Text = "停止";
            btnStop.Location = new Point(553, Px(10));
            btnStop.Width = 80;
            btnStop.Height = Px(30);
            btnStop.Enabled = false;
            btnStop.Click += delegate { StopScan(); };
            top.Controls.Add(btnStop);

            chkThorough = new CheckBox();
            chkThorough.Text = "彻底扫描（扫描大量文件可能耗时较长，请耐心等待）";
            chkThorough.Location = new Point(645, Px(14));
            chkThorough.AutoSize = true;
            chkThorough.Checked = _settings.ThoroughScan;
            chkThorough.CheckedChanged += delegate
            {
                _settings.ThoroughScan = chkThorough.Checked;
                SaveSettings();
            };
            top.Controls.Add(chkThorough);

            lblStatus = new Label();
            lblStatus.Text = "就绪";
            lblStatus.Location = new Point(12, Px(76));
            lblStatus.AutoSize = false;
            lblStatus.Width = 570;
            lblStatus.Height = Px(22);
            lblStatus.AutoEllipsis = true;
            top.Controls.Add(lblStatus);

            lblCounts = new Label();
            lblCounts.Text = "";
            lblCounts.Location = new Point(600, Px(76));
            lblCounts.AutoSize = true;
            top.Controls.Add(lblCounts);

            lblThreatSummary = new Label();
            lblThreatSummary.Text = "";
            lblThreatSummary.Location = new Point(12, Px(104));
            lblThreatSummary.AutoSize = true;
            lblThreatSummary.ForeColor = Color.DimGray;
            lblThreatSummary.Font = new Font("SimHei", 9F);
            top.Controls.Add(lblThreatSummary);

            chkSumSafe = new CheckBox();
            chkSumSafe.Width = Px(18);
            chkSumSafe.Height = Px(20);
            chkSumSafe.Location = new Point(Px(200), Px(104));
            chkSumSafe.Visible = false;
            chkSumSafe.CheckedChanged += delegate { if (!_syncingSummary) SelectGroupThreats(grpThreatSafe, chkSumSafe.Checked); };
            top.Controls.Add(chkSumSafe);

            lblThreatMaybe = new Label();
            lblThreatMaybe.Text = "";
            lblThreatMaybe.AutoSize = true;
            lblThreatMaybe.ForeColor = Color.DimGray;
            lblThreatMaybe.Font = new Font("SimHei", 9F);
            lblThreatMaybe.Location = new Point(Px(240), Px(76));
            top.Controls.Add(lblThreatMaybe);

            chkSumMaybe = new CheckBox();
            chkSumMaybe.Width = Px(18);
            chkSumMaybe.Height = Px(20);
            chkSumMaybe.Location = new Point(Px(400), Px(104));
            chkSumMaybe.Visible = false;
            chkSumMaybe.CheckedChanged += delegate { if (!_syncingSummary) SelectGroupThreats(grpThreatMaybe, chkSumMaybe.Checked); };
            top.Controls.Add(chkSumMaybe);

            Label lblFilter = new Label();
            lblFilter.Text = "筛选：";
            lblFilter.Location = new Point(556, Px(104));
            lblFilter.Width = 66;
            top.Controls.Add(lblFilter);

            txtThreatFilter = new TextBox();
            txtThreatFilter.Location = new Point(624, Px(102));
            txtThreatFilter.Width = 200;
            txtThreatFilter.Anchor = AnchorStyles.Top | AnchorStyles.Left;
            txtThreatFilter.TextChanged += delegate { RebuildThreatList(); };
            top.Controls.Add(txtThreatFilter);

            chkRemovable = new CheckBox();
            chkRemovable.Text = RemovableText;
            chkRemovable.AutoSize = true;
            chkRemovable.Location = new Point(12, Px(46));
            chkRemovable.Checked = _settings.IncludeRemovable;
            chkRemovable.CheckedChanged += delegate
            {
                if (_syncingRemovable) return;
                SetIncludeRemovable(chkRemovable.Checked);
            };
            top.Controls.Add(chkRemovable);

            Panel bottom = new Panel();
            bottom.Dock = DockStyle.Bottom;
            bottom.Height = Px(112);
            page.Controls.Add(bottom);

            // 选中某一项时完整显示说明与路径，避免列宽省略号看不全。
            txtThreatDetail = new TextBox();
            txtThreatDetail.Multiline = true;
            txtThreatDetail.ReadOnly = true;
            txtThreatDetail.BorderStyle = BorderStyle.FixedSingle;
            txtThreatDetail.ScrollBars = ScrollBars.Vertical;
            txtThreatDetail.Location = new Point(12, Px(8));
            txtThreatDetail.Width = 1060;
            txtThreatDetail.Height = Px(56);
            txtThreatDetail.Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right;
            bottom.Controls.Add(txtThreatDetail);

            btnDelete = new Button();
            btnDelete.Text = "删除选中（永久）";
            btnDelete.Location = new Point(12, Px(70));
            btnDelete.Width = 140;
            btnDelete.Height = Px(30);
            btnDelete.Click += delegate { DeleteSelectedThreats(); };
            bottom.Controls.Add(btnDelete);

            btnLocate = new Button();
            btnLocate.Text = "定位文件";
            btnLocate.Location = new Point(160, Px(70));
            btnLocate.Width = 100;
            btnLocate.Height = Px(30);
            btnLocate.Click += delegate { OpenThreatLocation(); };
            bottom.Controls.Add(btnLocate);

            btnExport = new Button();
            btnExport.Text = "导出 HTML 报告";
            btnExport.Location = new Point(270, Px(70));
            btnExport.Width = 130;
            btnExport.Height = Px(30);
            btnExport.Click += delegate { ExportReport(); };
            bottom.Controls.Add(btnExport);

            btnSelectAll = new Button();
            btnSelectAll.Text = "全选";
            btnSelectAll.Location = new Point(930, Px(62));
            btnSelectAll.Width = 100;
            btnSelectAll.Height = Px(28);
            top.Resize += delegate { btnSelectAll.Left = top.ClientSize.Width - btnSelectAll.Width - Px(12); };
            btnSelectAll.Click += delegate { ToggleSelectAllThreats(); BeginInvoke((MethodInvoker)delegate { lvThreats.Focus(); }); };
            top.Controls.Add(btnSelectAll);
            btnSelectAll.Visible = false;

            lvThreats = new ListView();
            lvThreats.Dock = DockStyle.Fill;
            lvThreats.View = View.Details;
            lvThreats.FullRowSelect = true;
            lvThreats.GridLines = true;
            lvThreats.MultiSelect = true;
            lvThreats.HideSelection = false;
            lvThreats.Columns.Add("严重度", 60);
            lvThreats.Columns.Add("名称", 165);
            lvThreats.Columns.Add("大小", 125, HorizontalAlignment.Left);
            lvThreats.Columns.Add("类型", 125);
            lvThreats.Columns.Add("说明", 250);
            lvThreats.Columns.Add("磁盘", 50);
            lvThreats.Columns.Add("路径", 310);
            lvThreats.ShowItemToolTips = true;
            lvThreats.ContextMenuStrip = BuildListMenu(lvThreats, delegate { OpenThreatLocation(); });
            lvThreats.SelectedIndexChanged += delegate { UpdateThreatDetail(); };
            lvThreats.ShowGroups = true;
            grpThreatSafe = new ListViewGroup("放心删", HorizontalAlignment.Left);
            grpThreatMaybe = new ListViewGroup("疑似垃圾", HorizontalAlignment.Left);
            lvThreats.Groups.Add(grpThreatSafe);
            lvThreats.Groups.Add(grpThreatMaybe);
            lvThreats.ColumnClick += delegate (object sender, ColumnClickEventArgs e)
            {
                if (_sortColumn == e.Column) _sortAsc = !_sortAsc;
                else { _sortColumn = e.Column; _sortAsc = true; }
                lvThreats.ListViewItemSorter = new ThreatItemComparer(_sortColumn, _sortAsc);
                lvThreats.Sort();
            };
            lvThreats.DoubleClick += delegate { OpenThreatLocation(); };
            lvThreats.KeyDown += delegate (object sender, KeyEventArgs e)
            {
                if (e.Control && e.KeyCode == Keys.A)
                {
                    SelectAllThreats(true);

                    e.Handled = true;
                    e.SuppressKeyPress = true;
                }
            };
            page.Controls.Add(lvThreats);
            lvThreats.BringToFront();
        }

        private void BuildBigPage(TabPage page)
        {
            Panel top = new Panel();
            top.Dock = DockStyle.Top;
            top.Height = Px(128);
            page.Controls.Add(top);

            Label l1 = new Label();
            l1.Text = "扫描范围";
            l1.Location = new Point(12, Px(16));
            l1.AutoSize = true;
            top.Controls.Add(l1);

            cboBigScope = new ComboBox();
            cboBigScope.DropDownStyle = ComboBoxStyle.DropDownList;
            cboBigScope.Location = new Point(80, Px(12));
            cboBigScope.Width = 250;
            cboBigScope.DropDown += delegate { RefreshScopes(); };
            cboBigScope.SelectedIndexChanged += delegate
            {
                if (IsCustomIndex(cboBigScope) && string.IsNullOrEmpty(_bigCustomDir)) BrowseBigFolder();
            };
            top.Controls.Add(cboBigScope);

            btnBigBrowse = new Button();
            btnBigBrowse.Text = "选择目录";
            btnBigBrowse.Location = new Point(340, Px(10));
            btnBigBrowse.Width = 90;
            btnBigBrowse.Height = Px(30);
            btnBigBrowse.Click += delegate { BrowseBigFolder(); };
            top.Controls.Add(btnBigBrowse);

            btnBigStart = new Button();
            btnBigStart.Text = "开始扫描";
            btnBigStart.Location = new Point(445, Px(10));
            btnBigStart.Width = 100;
            btnBigStart.Height = Px(30);
            btnBigStart.Click += delegate { StartBigScan(); };
            top.Controls.Add(btnBigStart);

            btnBigStop = new Button();
            btnBigStop.Text = "停止";
            btnBigStop.Location = new Point(553, Px(10));
            btnBigStop.Width = 80;
            btnBigStop.Height = Px(30);
            btnBigStop.Enabled = false;
            btnBigStop.Click += delegate { StopBigScan(); };
            top.Controls.Add(btnBigStop);

            chkRemovableBig = new CheckBox();
            chkRemovableBig.Text = RemovableText;
            chkRemovableBig.AutoSize = true;
            chkRemovableBig.Location = new Point(12, Px(46));
            chkRemovableBig.Checked = _settings.IncludeRemovable;
            chkRemovableBig.CheckedChanged += delegate
            {
                if (_syncingRemovable) return;
                SetIncludeRemovable(chkRemovableBig.Checked);
            };
            top.Controls.Add(chkRemovableBig);

            lblBigStatus = new Label();
            lblBigStatus.Text = "就绪";
            lblBigStatus.Location = new Point(12, Px(76));
            lblBigStatus.AutoSize = false;
            lblBigStatus.Width = 570;
            lblBigStatus.Height = Px(22);
            lblBigStatus.AutoEllipsis = true;
            top.Controls.Add(lblBigStatus);

            lblBigSummary = new Label();
            lblBigSummary.Text = "";
            lblBigSummary.Location = new Point(12, Px(104));
            lblBigSummary.AutoSize = true;
            lblBigSummary.ForeColor = Color.DimGray;
            lblBigSummary.Font = new Font("SimHei", 9F);
            top.Controls.Add(lblBigSummary);

            chkBigSumSafe = new CheckBox();
            chkBigSumSafe.Width = Px(18);
            chkBigSumSafe.Height = Px(20);
            chkBigSumSafe.Location = new Point(Px(200), Px(104));
            chkBigSumSafe.Visible = false;
            chkBigSumSafe.CheckedChanged += delegate { if (!_syncingSummary) SelectGroupBig(grpSafe, chkBigSumSafe.Checked); };
            top.Controls.Add(chkBigSumSafe);

            lblBigMaybe = new Label();
            lblBigMaybe.Text = "";
            lblBigMaybe.AutoSize = true;
            lblBigMaybe.ForeColor = Color.DimGray;
            lblBigMaybe.Font = new Font("SimHei", 9F);
            lblBigMaybe.Location = new Point(Px(240), Px(104));
            top.Controls.Add(lblBigMaybe);

            chkBigSumMaybe = new CheckBox();
            chkBigSumMaybe.Width = Px(18);
            chkBigSumMaybe.Height = Px(20);
            chkBigSumMaybe.Location = new Point(Px(400), Px(104));
            chkBigSumMaybe.Visible = false;
            chkBigSumMaybe.CheckedChanged += delegate { if (!_syncingSummary) SelectGroupBig(grpMaybe, chkBigSumMaybe.Checked); };
            top.Controls.Add(chkBigSumMaybe);

            Panel bottom = new Panel();
            bottom.Dock = DockStyle.Bottom;
            bottom.Height = Px(112);
            page.Controls.Add(bottom);

            // 选中某一项时，在这里完整显示类别/原因/路径，不受列宽省略号影响。
            txtBigDetail = new TextBox();
            txtBigDetail.Multiline = true;
            txtBigDetail.ReadOnly = true;
            txtBigDetail.BorderStyle = BorderStyle.FixedSingle;
            txtBigDetail.ScrollBars = ScrollBars.Vertical;
            txtBigDetail.Location = new Point(12, Px(8));
            txtBigDetail.Width = 1060;
            txtBigDetail.Height = Px(56);
            txtBigDetail.Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right;
            txtBigDetail.Text = "";
            bottom.Controls.Add(txtBigDetail);

            btnBigDelete = new Button();
            btnBigDelete.Text = "删除选中（永久）";
            btnBigDelete.Location = new Point(12, Px(70));
            btnBigDelete.Width = 140;
            btnBigDelete.Height = Px(30);
            btnBigDelete.Click += delegate { DeleteSelectedBigFiles(); };
            bottom.Controls.Add(btnBigDelete);

            btnBigLocate = new Button();
            btnBigLocate.Text = "定位文件";
            btnBigLocate.Location = new Point(160, Px(70));
            btnBigLocate.Width = 100;
            btnBigLocate.Height = Px(30);
            btnBigLocate.Click += delegate { LocateSelectedBigFile(); };
            bottom.Controls.Add(btnBigLocate);

            btnBigExport = new Button();
            btnBigExport.Text = "导出 HTML 报告";
            btnBigExport.Location = new Point(270, Px(70));
            btnBigExport.Width = 130;
            btnBigExport.Height = Px(30);
            btnBigExport.Click += delegate { ExportBigReport(); };
            bottom.Controls.Add(btnBigExport);

            btnBigSelectAll = new Button();
            btnBigSelectAll.Text = "全选";
            btnBigSelectAll.Location = new Point(930, Px(62));
            btnBigSelectAll.Width = 100;
            btnBigSelectAll.Height = Px(28);
            top.Resize += delegate { btnBigSelectAll.Left = top.ClientSize.Width - btnBigSelectAll.Width - Px(12); };
            btnBigSelectAll.Click += delegate { ToggleSelectAllBig(); BeginInvoke((MethodInvoker)delegate { lvBig.Focus(); }); };
            top.Controls.Add(btnBigSelectAll);
            btnBigSelectAll.Visible = false;

            lvBig = new ListView();
            lvBig.Dock = DockStyle.Fill;
            lvBig.View = View.Details;
            lvBig.FullRowSelect = true;
            lvBig.GridLines = true;
            lvBig.MultiSelect = true;
            lvBig.HideSelection = false;
            lvBig.ShowGroups = true;
            grpSafe = new ListViewGroup("放心删");
            grpMaybe = new ListViewGroup("疑似垃圾");
            lvBig.Groups.Add(grpSafe);
            lvBig.Groups.Add(grpMaybe);
            lvBig.Columns.Add("严重度", 60);
            lvBig.Columns.Add("名称", 165);
            lvBig.Columns.Add("大小", 125, HorizontalAlignment.Left);
            lvBig.Columns.Add("类别", 125);
            lvBig.Columns.Add("原因", 125);
            lvBig.Columns.Add("最后修改", 125);
            lvBig.Columns.Add("磁盘", 50);
            lvBig.Columns.Add("路径", 310);
            lvBig.ShowItemToolTips = true;
            lvBig.DoubleClick += delegate { LocateSelectedBigFile(); };
            lvBig.SelectedIndexChanged += delegate { UpdateBigDetail(); };
            lvBig.ContextMenuStrip = BuildListMenu(lvBig, delegate { LocateSelectedBigFile(); });
            lvBig.KeyDown += delegate (object sender, KeyEventArgs e)
            {
                if (e.Control && e.KeyCode == Keys.A)
                {
                    SetAllBigSelected(true);

                    e.Handled = true;
                    e.SuppressKeyPress = true;
                }
            };
            page.Controls.Add(lvBig);
            lvBig.BringToFront();
        }

        private void BrowseBigFolder()
        {
            using (FolderBrowserDialog dlg = new FolderBrowserDialog())
            {
                dlg.Description = "选择要扫描大文件的目录";
                if (dlg.ShowDialog(this) == DialogResult.OK)
                {
                    _bigCustomDir = dlg.SelectedPath;
                    RefreshScopes();
                    cboBigScope.SelectedIndex = cboBigScope.Items.Count - 1;
                }
            }
        }

        private void StartBigScan()
        {
            if (_bigScanning) return;

            List<string> targets = new List<string>();
            int idx = cboBigScope.SelectedIndex;
            int driveCount = _scopes.Count;
            if (idx == 0) targets.AddRange(BuildQuickTargets());
            else if (idx >= 1 && idx <= driveCount) targets.Add(_scopes[idx - 1] + "\\");
            else if (idx == driveCount + 1)
            {
                foreach (DriveInfo d in DriveInfo.GetDrives())
                {
                    if (IsScanDrive(d)) targets.Add(d.RootDirectory.FullName);
                }
            }
            else
            {
                if (string.IsNullOrEmpty(_bigCustomDir))
                {
                    MessageBox.Show(this, "请先选择要扫描的目录。", "大文件扫描", MessageBoxButtons.OK, MessageBoxIcon.Information);
                    return;
                }
                targets.Add(_bigCustomDir);
            }

            _bigItems.Clear();
            lvBig.Items.Clear();
            SetAllBigSelected(false);

            BigFileOptions opt = new BigFileOptions();
            opt.Targets = targets;
            opt.MinSize = 50L * 1024 * 1024;
            // 固定只看疑似垃圾：列表里出现的每一条都有明确清理理由。
            opt.JunkOnly = true;

            _bigScanner = new BigFileScanner(opt);
            _bigScanner.ItemFound += delegate(BigFileItem item)
            {
                if (_bigStopRequested) return;
                BeginInvoke((Action)delegate { if (!_bigStopRequested) AddBigRow(item); });
            };
            _bigScanner.ProgressChanged += delegate(int scanned, int found, long bytes)
            {
                if (_bigStopRequested) return;
                BeginInvoke((Action)delegate
                {
                    if (_bigStopRequested) return;
                    lblBigStatus.Text = "已检查 " + scanned + " 个文件，发现 " + found + " 个";
                    lblBigSummary.Text = "合计约 " + FormatSize(bytes);
                });
            };
            _bigScanner.ScanFinished += delegate
            {
                BeginInvoke((Action)delegate { FinishBigScan(); });
            };

            _bigScanning = true;
            _bigStopRequested = false;
            btnBigStart.Enabled = false;
            btnBigStop.Enabled = true;
            lblBigStatus.Text = "正在扫描…";
            lblBigSummary.Text = "";
            AppendLog("大文件扫描开始：最小体积 " + FormatSize(opt.MinSize) + "，范围 " + targets.Count + " 个目录" + (opt.JunkOnly ? "，只看疑似垃圾" : "，列出所有大文件"));

            _bigThread = new Thread(delegate()
            {
                try { _bigScanner.Run(); }
                catch { }
            });
            _bigThread.IsBackground = true;
            _bigThread.Start();
        }

        private void StopBigScan()
        {
            if (_bigScanner != null && _bigScanning)
            {
                _bigStopRequested = true;
                _bigScanner.Cancel();
                btnBigStop.Enabled = false;
                lblBigStatus.Text = "正在停止…";
            }
        }

        private void AddBigRow(BigFileItem item)
        {
            _bigItems.Add(item);
            lvBig.Items.Add(MakeBigRow(item));
            UpdateBigGroupHeaders();
        }

        private ListViewItem MakeBigRow(BigFileItem item)
        {
            ListViewItem li = new ListViewItem(Sev.Text(item.Sev));
            li.SubItems.Add(Path.GetFileName(item.Path));
            li.SubItems.Add(FormatSize(item.Size));
            li.SubItems.Add(item.Category);
            li.SubItems.Add(item.Reason);
            li.SubItems.Add(item.Modified.ToString("yyyy-MM-dd HH:mm"));
            li.SubItems.Add(DriveOf(item.Path));
            li.SubItems.Add(item.Path);
            li.Tag = item;
            li.Group = item.Safe ? grpSafe : grpMaybe;
            li.ToolTipText = item.Category + "｜" + item.Reason + "\n" + item.Path;
            if (item.Sev == Severity.High) li.ForeColor = Color.Firebrick;
            else if (item.Sev == Severity.Medium) li.ForeColor = Color.DarkOrange;
            return li;
        }

        // 底部详情框：把选中行的完整信息显示出来（列宽再窄也不影响查看）。
        private void UpdateThreatDetail()
        {
            if (txtThreatDetail == null) return;
            if (lvThreats.SelectedItems.Count != 1)
            {
                txtThreatDetail.Text = "";
                return;
            }
            Threat t = lvThreats.SelectedItems[0].Tag as Threat;
            if (t == null)
            {
                txtThreatDetail.Text = "";
                return;
            }
            txtThreatDetail.Text = "路径：" + t.Path
                + Environment.NewLine + "类型：" + t.Kind + "　严重度：" + Sev.Text(t.Sev) + "　大小：" + FormatSize(t.Size)
                + Environment.NewLine + "说明：" + t.Detail;
        }

        // 底部详情框：把选中行的完整信息显示出来（列宽再窄也不影响查看）。
        private void UpdateBigDetail()
        {
            if (txtBigDetail == null) return;
            if (lvBig.SelectedItems.Count != 1)
            {
                txtBigDetail.Text = "";
                return;
            }
            BigFileItem item = lvBig.SelectedItems[0].Tag as BigFileItem;
            if (item == null)
            {
                txtBigDetail.Text = "";
                return;
            }
            txtBigDetail.Text = "类别：" + item.Category + "　原因：" + item.Reason + "　最后修改：" + item.Modified.ToString("yyyy-MM-dd HH:mm")
                + Environment.NewLine + "路径：" + item.Path + "（" + FormatSize(item.Size) + "）";
        }

        // 两个分组标题上直接显示条数与体积，扫完一眼能看出哪堆更值得清。
        private void UpdateBigGroupHeaders()
        {
            int safeCount = 0, maybeCount = 0;
            long safeBytes = 0, maybeBytes = 0;
            foreach (BigFileItem it in _bigItems)
            {
                if (it.Safe) { safeCount++; safeBytes += it.Size; }
                else { maybeCount++; maybeBytes += it.Size; }
            }
            grpSafe.Header = "放心删（" + safeCount + " 个 · " + FormatSize(safeBytes) + "）";
            grpMaybe.Header = "疑似垃圾（" + maybeCount + " 个 · " + FormatSize(maybeBytes) + "）";
        }

        private void FinishBigScan()
        {
            _bigScanning = false;
            btnBigStart.Enabled = true;
            btnBigStop.Enabled = false;

            _bigItems.Sort(delegate(BigFileItem a, BigFileItem b) { return b.Size.CompareTo(a.Size); });
            lvBig.BeginUpdate();
            lvBig.Items.Clear();
            long total = 0;
            foreach (BigFileItem it in _bigItems)
            {
                lvBig.Items.Add(MakeBigRow(it));
                total += it.Size;
            }
            lvBig.EndUpdate();
            UpdateBigGroupHeaders();

            if (_bigStopRequested)
            {
                lblBigStatus.Text = "已停止，共 " + _bigItems.Count + " 个";
                AppendLog("大文件扫描已停止：" + _bigItems.Count + " 个，合计 " + FormatSize(total));
                _bigStopRequested = false;
                return;
            }
            int safen = 0, mayben = 0;
            long safeB = 0, maybeB = 0;
            foreach (BigFileItem it in _bigItems)
            {
                if (it.Safe) { safen++; safeB += it.Size; }
                else { mayben++; maybeB += it.Size; }
            }
            lblBigStatus.Text = "扫描完成，共 " + _bigItems.Count + " 个";
            lblBigSummary.Text = "放心删 " + safen + " 个（" + FormatSize(safeB) + "）";
            lblBigMaybe.Text = "疑似垃圾 " + mayben + " 个（" + FormatSize(maybeB) + "）";
            _syncingSummary = true;
            chkBigSumSafe.Checked = false;
            chkBigSumMaybe.Checked = false;
            _syncingSummary = false;
            LayoutSummaryRow(lblBigSummary, chkBigSumSafe, lblBigMaybe, chkBigSumMaybe);
            bool bigShow = (safen + mayben) > 0;
            lblBigSummary.Visible = bigShow;
            lblBigMaybe.Visible = bigShow;
            chkBigSumSafe.Visible = bigShow;
            chkBigSumMaybe.Visible = bigShow;
            if (btnBigSelectAll != null) btnBigSelectAll.Visible = bigShow;
            AppendLog("大文件扫描完成：放心删 " + safen + " 个（" + FormatSize(safeB) + "），疑似垃圾 " + mayben + " 个（" + FormatSize(maybeB) + "）。");
            UpdateBigGroupHeaders();
            lvBig.SelectedItems.Clear();
        }

        private void SetAllBigSelected(bool select)
        {
            lvBig.BeginUpdate();
            foreach (ListViewItem li in lvBig.Items) li.Selected = select;
            lvBig.EndUpdate();
            lvBig.Invalidate();
            if (btnBigSelectAll != null) btnBigSelectAll.Text = select ? "取消全选" : "全选";
            if (select && lvBig.Items.Count > 0) lvBig.Focus();
        }

        private void LocateSelectedBigFile()
        {
            if (lvBig.SelectedItems.Count == 0) return;
            BigFileItem it = lvBig.SelectedItems[0].Tag as BigFileItem;
            if (it == null) return;
            try { Process.Start("explorer.exe", "/select,\"" + it.Path + "\""); }
            catch { }
        }

        private void DeleteSelectedBigFiles()
        {
            if (lvBig.SelectedItems.Count == 0)
            {
                MessageBox.Show(this, "请先选中要删除的文件。", "大文件清理", MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }

            List<ListViewItem> selected = new List<ListViewItem>();
            foreach (ListViewItem li in lvBig.SelectedItems) selected.Add(li);

            long total = 0;
            foreach (ListViewItem li in selected)
            {
                BigFileItem it = li.Tag as BigFileItem;
                if (it != null) total += it.Size;
            }

            string msg = "即将永久删除 " + selected.Count + " 个文件，合计 " + FormatSize(total) + "。\r\n\r\n删掉后不进回收站，无法恢复。确定继续？";
            if (MessageBox.Show(this, msg, "确认删除", MessageBoxButtons.YesNo, MessageBoxIcon.Warning) != DialogResult.Yes) return;

            int ok = 0;
            long freed = 0;
            int failed = 0;
            foreach (ListViewItem li in selected)
            {
                BigFileItem it = li.Tag as BigFileItem;
                if (it == null) continue;
                try
                {
                    File.Delete(it.Path);
                    lvBig.Items.Remove(li);
                    _bigItems.Remove(it);
                    ok++;
                    freed += it.Size;
                }
                catch
                {
                    failed++;
                }
            }

            string text = "已删除 " + ok + " 个，释放约 " + FormatSize(freed);
            if (failed > 0) text += "；" + failed + " 个删除失败（可能被占用或权限不足）";
            lblBigSummary.Text = text;
            AppendLog(text);
            UpdateBigGroupHeaders();
        }

        private void BuildAuditPage(TabPage page)
        {
            Panel top = new Panel();
            top.Dock = DockStyle.Top;
            top.Height = Px(52);
            page.Controls.Add(top);

            btnAudit = new Button();
            btnAudit.Text = "开始审计";
            btnAudit.Location = new Point(12, Px(10));
            btnAudit.Width = 100;
            btnAudit.Height = Px(30);
            btnAudit.Click += delegate { RunAudit(); };
            top.Controls.Add(btnAudit);

            btnAuditDelete = new Button();
            btnAuditDelete.Text = "删除选中";
            btnAuditDelete.Location = new Point(330, Px(10));
            btnAuditDelete.Width = 110;
            btnAuditDelete.Height = Px(30);
            btnAuditDelete.Click += delegate { AuditDelete(); };
            top.Controls.Add(btnAuditDelete);

            Label l = new Label();
            l.Text = "筛选";
            l.Location = new Point(130, Px(16));
            l.AutoSize = true;
            top.Controls.Add(l);

            cboCategory = new ComboBox();
            cboCategory.DropDownStyle = ComboBoxStyle.DropDownList;
            cboCategory.Location = new Point(170, Px(12));
            cboCategory.Width = 140;
            cboCategory.Items.Add("全部");
            cboCategory.Items.Add("自启动");
            cboCategory.Items.Add("服务");
            cboCategory.Items.Add("计划任务");
            cboCategory.Items.Add("其他");
            cboCategory.SelectedIndex = 0;
            cboCategory.SelectedIndexChanged += delegate { RefreshAuditView(); };
            top.Controls.Add(cboCategory);

            lblAuditStatus = new Label();
            lblAuditStatus.Text = "尚未审计";
            lblAuditStatus.Location = new Point(452, Px(16));
            lblAuditStatus.AutoSize = true;
            top.Controls.Add(lblAuditStatus);

            lvAudit = new ListView();
            lvAudit.Dock = DockStyle.Fill;
            lvAudit.View = View.Details;
            lvAudit.FullRowSelect = true;
            lvAudit.GridLines = true;
            lvAudit.MultiSelect = false;
            lvAudit.Columns.Add("类别", 80);
            lvAudit.Columns.Add("名称", 240);
            lvAudit.Columns.Add("命令 / 路径", 400);
            lvAudit.Columns.Add("签名", 130);
            lvAudit.Columns.Add("严重度", 60);
            lvAudit.Columns.Add("说明", 220);
            lvAudit.DoubleClick += delegate { AuditOpenLocation(); };
            lvAudit.KeyDown += delegate(object sender, KeyEventArgs e)
            {
                if (e.KeyCode == Keys.Delete)
                {
                    AuditDelete();
                    e.Handled = true;
                }
            };
            page.Controls.Add(lvAudit);
            lvAudit.BringToFront();

            auditMenu = new ContextMenuStrip();
            auditMenu.Items.Add("定位文件", null, delegate { AuditOpenLocation(); });
            auditMenu.Items.Add("复制命令", null, delegate { AuditCopyCommand(); });
            auditMenu.Items.Add(new ToolStripSeparator());
            auditMenu.Items.Add("删除该项（需确认）", null, delegate { AuditDelete(); });
            lvAudit.ContextMenuStrip = auditMenu;
        }

        private void BuildTray()
        {
            tray = new NotifyIcon();
            _trayRef = tray;
            try { tray.Icon = Icon.ExtractAssociatedIcon(Application.ExecutablePath); }
            catch { tray.Icon = SystemIcons.Shield; }
            tray.Text = "满唯杀毒";
            tray.Visible = true;
            ContextMenuStrip menu = new ContextMenuStrip();
            menu.Items.Add("打开主界面", null, delegate { ShowFromTray(); });
            menu.Items.Add("快速扫描", null, delegate { ShowFromTray(); cboTarget.SelectedIndex = 0; StartScan(); });
            _pauseItem = new ToolStripMenuItem("暂停扫描");
            _pauseItem.Enabled = false;
            _pauseItem.Click += delegate
            {
                if (!_scanning || _engine == null) return;
                bool paused = !_engine.Paused;
                _engine.SetPaused(paused);
                _pauseItem.Text = paused ? "继续扫描" : "暂停扫描";
                SetStatus(paused ? "已暂停" : "正在扫描: " + (_engine.CurrentPath ?? ""));
                AppendLog(paused ? "扫描已暂停。" : "继续扫描。");
            };
            menu.Items.Add(_pauseItem);
            menu.Items.Add(new ToolStripSeparator());
            ToolStripMenuItem notifyItem = new ToolStripMenuItem("显示桌面通知");
            notifyItem.Checked = _settings.Notifications;
            notifyItem.Click += delegate
            {
                _settings.Notifications = notifyItem.Checked;
                SaveSettings();
            };
            menu.Items.Add(notifyItem);
            ToolStripMenuItem defenderItem = new ToolStripMenuItem("Defender 二次复核");
            defenderItem.Checked = _settings.DefenderCheck;
            defenderItem.Click += delegate
            {
                _settings.DefenderCheck = defenderItem.Checked;
                SaveSettings();
                AppendLog("Defender 二次复核已" + (defenderItem.Checked ? "开启" : "关闭") + "（下次扫描生效）。");
            };
            menu.Items.Add(defenderItem);
            ToolStripMenuItem removableItem = new ToolStripMenuItem("包含可移动磁盘");
            removableItem.Checked = _settings.IncludeRemovable;
            _removableItem = removableItem;
            removableItem.Click += delegate
            {
                if (_syncingRemovable) return;
                SetIncludeRemovable(removableItem.Checked);
            };
            menu.Items.Add(removableItem);
            menu.Items.Add(new ToolStripSeparator());
            menu.Items.Add("关于 满唯杀毒", null, delegate { ShowFromTray(); ShowAbout(); });
            menu.Items.Add("导入规则包...", null, delegate { ShowFromTray(); ImportRulePack(); });
            menu.Items.Add("导出诊断信息...", null, delegate { ExportDiagnostics(); });
            menu.Items.Add(new ToolStripSeparator());
            menu.Items.Add("退出", null, delegate { tray.Visible = false; Application.Exit(); });
            tray.ContextMenuStrip = menu;
            tray.DoubleClick += delegate { ShowFromTray(); };
            FormClosing += delegate { CleanupTray(); };
        }

        public static void CleanupTray()
        {
            try
            {
                NotifyIcon t = _trayRef;
                _trayRef = null;
                if (t != null)
                {
                    t.Visible = false;
                    t.Dispose();
                }
            }
            catch { }
        }

        private void ShowFromTray()
        {
            Show();
            WindowState = FormWindowState.Normal;
            Activate();
        }

        private void BrowseFolder()
        {
            using (FolderBrowserDialog dlg = new FolderBrowserDialog())
            {
                dlg.Description = "选择要扫描的目录";
                if (dlg.ShowDialog(this) == DialogResult.OK)
                {
                    _customDir = dlg.SelectedPath;
                    RefreshScopes();
                    cboTarget.SelectedIndex = cboTarget.Items.Count - 1;
                }
            }
        }

        public static List<string> BuildQuickTargets()
        {
            List<string> list = new List<string>();
            AddQuickTarget(list, Path.GetTempPath());
            AddQuickTarget(list, Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Temp"));
            AddQuickTarget(list, Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"));
            AddQuickTarget(list, Environment.GetFolderPath(Environment.SpecialFolder.Desktop));
            AddQuickTarget(list, Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData));
            AddQuickTarget(list, Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData));
            AddQuickTarget(list, Environment.GetFolderPath(Environment.SpecialFolder.Startup));
            AddQuickTarget(list, Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup));
            AddQuickTarget(list, Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Public"));
            AddQuickTarget(list, Environment.GetEnvironmentVariable("PUBLIC"));
            AddOtherDriveQuickTargets(list);
            return list;
        }

        private static void AddQuickTarget(List<string> targets, string dir)
        {
            if (string.IsNullOrEmpty(dir)) return;
            string d = dir.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
            if (d.Length == 0) d = dir;
            if (!Directory.Exists(d)) return;
            for (int i = 0; i < targets.Count; i++)
            {
                string t = targets[i].TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
                if (string.Equals(t, d, StringComparison.OrdinalIgnoreCase)) return;
            }
            targets.Add(d);
        }

        // quick scan also covers common junk locations on other fixed drives
        public static void AddOtherDriveQuickTargets(List<string> targets)
        {
            string systemRoot = Path.GetPathRoot(Environment.SystemDirectory);
            try
            {
                foreach (DriveInfo di in DriveInfo.GetDrives())
                {
                    if (di.DriveType != DriveType.Fixed || !di.IsReady) continue;
                    string root = di.RootDirectory.FullName;
                    if (string.Equals(root, systemRoot, StringComparison.OrdinalIgnoreCase)) continue;
                    string[] subs = new string[] { "Temp", "tmp", "Downloads", "Desktop", "ProgramData" };
                    for (int i = 0; i < subs.Length; i++) AddQuickTarget(targets, Path.Combine(root, subs[i]));
                    AddQuickTarget(targets, Path.Combine(root, "Windows", "Temp"));
                    AddQuickTarget(targets, Path.Combine(root, "Users", "Public"));
                    AddQuickTarget(targets, Path.Combine(root, "Backup", "Downloads"));

                    // 其它盘常见垃圾目录名（Cache / QMDownload / QLDownload / qycache 之类），按关键字识别，避免漏扫。
                    try
                    {
                        string[] rootDirs = Directory.GetDirectories(root);
                        for (int i = 0; i < rootDirs.Length; i++)
                        {
                            string nm = Path.GetFileName(rootDirs[i]).ToLowerInvariant();
                            if (nm.IndexOf("temp") >= 0 || nm.IndexOf("tmp") >= 0 ||
                                nm.IndexOf("cache") >= 0 || nm.IndexOf("download") >= 0)
                            {
                                AddQuickTarget(targets, rootDirs[i]);
                            }
                        }
                    }
                    catch { }

                    string users = Path.Combine(root, "Users");
                    if (!Directory.Exists(users)) continue;
                    string[] userDirs = Directory.GetDirectories(users);
                    for (int i = 0; i < userDirs.Length; i++)
                    {
                        AddQuickTarget(targets, Path.Combine(userDirs[i], "Downloads"));
                        AddQuickTarget(targets, Path.Combine(userDirs[i], "Desktop"));
                        AddQuickTarget(targets, Path.Combine(userDirs[i], "AppData", "Local", "Temp"));
                    }
                }
            }
            catch { }
        }

        // 扫描范围里要不要列出这块盘：固定盘总是列；可移动盘仅在设置开启时列出。
        private bool IsScanDrive(DriveInfo d)
        {
            if (!d.IsReady) return false;
            if (d.DriveType == DriveType.Fixed) return true;
            return _settings.IncludeRemovable && d.DriveType == DriveType.Removable;
        }

        private const string RemovableText = "含可移动磁盘（U 盘/移动硬盘）";

        // 两个页面 + 托盘的开关都走这里，保证状态一致、扫描范围立即刷新。
        private void SetIncludeRemovable(bool value)
        {
            _settings.IncludeRemovable = value;
            SaveSettings();
            _syncingRemovable = true;
            if (chkRemovable != null) chkRemovable.Checked = value;
            if (chkRemovableBig != null) chkRemovableBig.Checked = value;
            if (_removableItem != null) _removableItem.Checked = value;
            _syncingRemovable = false;
            RefreshScopes();
            AppendLog("扫描范围" + (value ? "已包含" : "已排除") + "可移动磁盘（U 盘/移动硬盘）。");
        }

        private void RefreshScopes()
        {
            List<string> drives = new List<string>();
            try
            {
                foreach (DriveInfo d in DriveInfo.GetDrives())
                {
                    if (IsScanDrive(d) && d.Name.Length >= 2)
                    {
                        drives.Add(d.Name.Substring(0, 2).ToUpperInvariant());
                    }
                }
            }
            catch { }
            drives.Sort(StringComparer.Ordinal);
            _scopes.Clear();
            _scopes.AddRange(drives);
            FillScopeCombo(cboTarget, _customDir);
            FillScopeCombo(cboBigScope, _bigCustomDir);
        }

        private void FillScopeCombo(ComboBox cbo, string customDir)
        {
            if (cbo == null) return;
            int sel = cbo.SelectedIndex;
            string prev = (sel >= 0 && sel < cbo.Items.Count) ? cbo.Items[sel].ToString() : null;
            cbo.BeginUpdate();
            cbo.Items.Clear();
            cbo.Items.Add("快速扫描（推荐）");
            foreach (string s in _scopes) cbo.Items.Add("全盘扫描 " + s);
            cbo.Items.Add("全盘扫描（所有磁盘）");
            cbo.Items.Add(string.IsNullOrEmpty(customDir) ? "自定义目录..." : "自定义：" + customDir);
            cbo.EndUpdate();
            // 尽量保持用户原来选的那一项；那一项若已不存在（例如对应磁盘被移除），退回第一项。
            int idx = prev == null ? -1 : cbo.Items.IndexOf(prev);
            if (idx < 0) idx = (sel >= 0 && sel < cbo.Items.Count) ? sel : 0;
            cbo.SelectedIndex = idx;
        }

        private bool IsCustomIndex(ComboBox cbo)
        {
            if (cbo == null || cbo.Items.Count == 0) return false;
            return cbo.SelectedIndex == cbo.Items.Count - 1;
        }

        private void StartScan()
        {
            if (_scanning) return;
            List<string> targets = new List<string>();
            int idx = cboTarget.SelectedIndex;
            int driveCount = _scopes.Count;
            if (idx == 0)
            {
                targets.AddRange(BuildQuickTargets());
            }
            else if (idx >= 1 && idx <= driveCount)
            {
                targets.Add(_scopes[idx - 1] + "\\");
            }
            else if (idx == driveCount + 1)
            {
                foreach (DriveInfo di in DriveInfo.GetDrives())
                {
                    if (di.DriveType == DriveType.Fixed && di.IsReady) targets.Add(di.RootDirectory.FullName);
                }
            }
            else if (idx == driveCount + 2)
            {
                if (string.IsNullOrEmpty(_customDir)) BrowseFolder();
                if (!string.IsNullOrEmpty(_customDir)) targets.Add(_customDir);
            }

            ScanOptions opt = new ScanOptions();
            opt.Targets = targets;
            opt.Exclusions = _settings.Exclusions;
            opt.Threads = _settings.Threads;
            opt.MaxBytes = 50L * 1024 * 1024;
            opt.HashLimit = Math.Min(opt.MaxBytes, 64L * 1024 * 1024);
            opt.HashFiles = true;
            opt.Heuristics = true;
            opt.Thorough = chkThorough != null && chkThorough.Checked;

            _threats.Clear();
            lvThreats.Items.Clear();
            if (txtThreatDetail != null) txtThreatDetail.Text = "";
            UpdateThreatGroupHeaders();
            SelectAllThreats(false);
            AppendLog("扫描位置共 " + targets.Count + " 个：");
            for (int i = 0; i < targets.Count; i++) AppendLog("  " + targets[i]);
            _scanning = true;
            _stopRequested = false;
            _scanGen++;
            _scanStarted = DateTime.Now;
            if (_pauseItem != null)
            {
                _pauseItem.Text = "暂停扫描";
                _pauseItem.Enabled = true;
            }
            btnStart.Enabled = false;
            btnStop.Enabled = true;
            if (chkThorough != null) chkThorough.Enabled = false;
            // 扫描过程中也允许删除/忽略已发现的项目，不必等整盘扫完。
            btnDelete.Enabled = true;
            SetStatus("正在扫描...");
            lblCounts.Text = "已扫描 0 个文件，发现 0 项";
            AppendLog("开始扫描，目标: " + string.Join("; ", targets.ToArray()));
            AppendLog(opt.Thorough
                ? "扫描模式：彻底（不跳过缓存与素材，行为规则读全文）"
                : "扫描模式：快速（跳过缓存目录与素材内容，行为规则看前 64 KB）");

            _engine = new ScanEngine(_sigs, opt);
            _engine.ThreatFound += OnThreatFound;
            _engine.ProgressChanged += OnProgress;
            _engine.StatusChanged += OnStatus;
            _engine.ScanFinished += OnScanFinished;

            _scanThread = new Thread(delegate () { _engine.Run(); });
            _scanThread.IsBackground = true;
            _scanThread.Start();
        }

        private void OnThreatFound(Threat t)
        {
            if (IsDisposed || _stopRequested) return;
            BeginInvoke((MethodInvoker)delegate
            {
                _threats.Add(t);
                if (MatchesFilter(t)) AddThreatRow(t);
                UpdateThreatGroupHeaders();
                lblCounts.Text = "已扫描 " + _engine.FilesScanned + " 个文件，发现 " + _threats.Count + " 项";
                if (_settings.Notifications && _threats.Count == 1) tray.ShowBalloonTip(2000, "满唯杀毒 发现威胁", t.Name + "：" + t.Path, ToolTipIcon.Warning);
            });
        }

        private bool MatchesFilter(Threat t)
        {
            if (txtThreatFilter == null) return true;
            string q = txtThreatFilter.Text.Trim();
            if (q.Length == 0) return true;
            string hay = t.Name + " " + t.Kind + " " + t.Detail + " " + t.Path;
            return hay.IndexOf(q, StringComparison.OrdinalIgnoreCase) >= 0;
        }

        private void AddThreatRow(Threat t)
        {
            ListViewItem li = new ListViewItem(new string[]
            {
                Sev.Text(t.Sev), t.Name, FormatSize(t.Size), t.Kind, t.Detail, DriveOf(t.Path), t.Path
            });
            li.Tag = t;
            li.ToolTipText = t.Kind + "｜" + t.Detail + "\n" + t.Path;
            li.Group = ThreatSafety.IsSafeToDelete(t) ? grpThreatSafe : grpThreatMaybe;
            if (t.Sev == Severity.High) li.ForeColor = Color.Firebrick;
            else if (t.Sev == Severity.Medium) li.ForeColor = Color.DarkOrange;
            lvThreats.Items.Add(li);
        }

        // 筛选条件变化或切换排序时，按 _threats 重建列表，保证分组与计数一致。
        private void RebuildThreatList()
        {
            if (lvThreats == null) return;
            lvThreats.BeginUpdate();
            try
            {
                lvThreats.Items.Clear();
                for (int i = 0; i < _threats.Count; i++)
                {
                    if (MatchesFilter(_threats[i])) AddThreatRow(_threats[i]);
                }
                if (_sortColumn >= 0) lvThreats.Sort();
            }
            finally { lvThreats.EndUpdate(); }
            UpdateThreatGroupHeaders();
        }

        private void OnProgress(int files, int threats)
        {
            if (IsDisposed || _stopRequested) return;
            if ((DateTime.Now - _lastStatus).TotalMilliseconds < 120) return;
            _lastStatus = DateTime.Now;
            BeginInvoke((MethodInvoker)delegate
            {
                lblCounts.Text = "已扫描 " + files + " 个文件，发现 " + threats + " 项";
            });
        }

        private void OnStatus(string path)
        {
            if (IsDisposed || _stopRequested) return;
            if ((DateTime.Now - _lastStatus).TotalMilliseconds < 120) return;
            _lastStatus = DateTime.Now;
            BeginInvoke((MethodInvoker)delegate { SetStatus("正在扫描: " + path); });
        }

        private string ScanSummary(int scanned)
        {
            try
            {
                TimeSpan el = DateTime.Now - _scanStarted;
                double sec = el.TotalSeconds;
                if (sec < 0.05) sec = 0.05;
                return "用时 " + sec.ToString("0.0") + " 秒（" + (scanned / sec).ToString("0") + " 文件/秒）";
            }
            catch { return "用时不详"; }
        }

        private void OnScanFinished()
        {
            if (IsDisposed) return;
            BeginInvoke((MethodInvoker)delegate
            {
                _scanning = false;
                btnStart.Enabled = true;
                btnStop.Enabled = false;
                if (chkThorough != null) chkThorough.Enabled = true;
                if (_pauseItem != null)
                {
                    _pauseItem.Text = "暂停扫描";
                    _pauseItem.Enabled = false;
                }
                btnDelete.Enabled = _threats.Count > 0;
                int scanned = _engine == null ? 0 : _engine.FilesScanned;
                if (_stopRequested)
                {
                    SetStatus("已停止");
                    lblCounts.Text = "已扫描 " + scanned + " 个文件，发现 " + _threats.Count + " 项（已停止）";
                    AppendLog("扫描已停止：扫描 " + scanned + " 个文件，发现 " + _threats.Count + " 项威胁，" + ScanSummary(scanned) + "。");
                    _stopRequested = false;
                    return;
                }
                SetStatus("扫描完成");
                lblCounts.Text = "已扫描 " + scanned + " 个文件，发现 " + _threats.Count + " 项";
                UpdateThreatGroupHeaders();
                AppendLog("扫描完成：扫描 " + scanned + " 个文件，发现 " + _threats.Count + " 项威胁，跳过/异常 " + (_engine == null ? 0 : _engine.SkippedCount) + " 项，" + ScanSummary(scanned) + "。");
                BeginDefenderReview();
                if (_threats.Count == 0) MessageBox.Show(this, "扫描完成，未发现匹配的威胁。", "满唯杀毒", MessageBoxButtons.OK, MessageBoxIcon.Information);
            });
        }

        // 扫描结束后把"疑似垃圾"交给 Windows Defender 复核：只报告、不删除，异步进行，不阻塞界面。
        private void BeginDefenderReview()
        {
            if (!_settings.DefenderCheck)
            {
                AppendLog("Defender 复核：已在托盘菜单「Defender 二次复核」里关闭。");
                return;
            }
            if (!DefenderCheck.IsAvailable)
            {
                AppendLog("Defender 复核：未找到 MpCmdRun.exe（Defender 可能被移除或禁用），已跳过。");
                return;
            }
            List<Threat> suspicious = new List<Threat>();
            int inContainer = 0;
            foreach (Threat t in _threats)
            {
                if (t.Removed || ThreatSafety.IsSafeToDelete(t)) continue;
                // 压缩包内部条目是虚拟路径，MpCmdRun 不能单独扫；文件已不在的也跳过。
                if (!System.IO.File.Exists(t.Path)) { inContainer++; continue; }
                suspicious.Add(t);
            }
            if (inContainer > 0)
                AppendLog("Defender 复核：跳过 " + inContainer + " 项（位于压缩包内或文件已不存在，无法单独提交）。");
            if (suspicious.Count == 0) return;
            // 严重度高的优先，其次体积大的；只提交上限以内的一批。
            suspicious.Sort(delegate(Threat a, Threat b)
            {
                int c = b.Sev.CompareTo(a.Sev);
                return c != 0 ? c : b.Size.CompareTo(a.Size);
            });
            if (suspicious.Count > DefenderCheck.MaxFiles)
                suspicious = suspicious.GetRange(0, DefenderCheck.MaxFiles);
            int gen = _scanGen;
            SetStatus("Defender 复核中...");
            AppendLog("Defender 复核：提交 " + suspicious.Count + " 项疑似文件（最多 " + DefenderCheck.MaxFiles +
                " 项，单文件 15 秒，总时限 60 秒；只报告、不删除）。");
            Thread th = new Thread(delegate()
            {
                DefenderCheck.Verify(suspicious,
                    delegate(Threat t, string v) { OnDefenderResult(gen, t, v); },
                    delegate(string msg) { AppendLogSafe(msg); });
                try
                {
                    BeginInvoke((MethodInvoker)delegate
                    {
                        if (gen == _scanGen && !_scanning) SetStatus("扫描完成");
                    });
                }
                catch { }
            });
            th.IsBackground = true;
            th.Start();
        }

        private void OnDefenderResult(int gen, Threat t, string verdict)
        {
            if (IsDisposed) return;
            try
            {
                BeginInvoke((MethodInvoker)delegate
                {
                    if (gen != _scanGen) return;
                    t.Defender = verdict;
                    ListViewItem li = FindThreatItem(t);
                    if (li != null)
                    {
                        string detail = DetailWithDefender(t);
                        li.SubItems[4].Text = detail;
                        li.ToolTipText = t.Kind + "｜" + detail + "\n" + t.Path;
                        if (verdict == DefenderCheck.VerdictThreat)
                        {
                            t.Sev = Severity.High;
                            li.SubItems[0].Text = Sev.Text(t.Sev);
                            li.ForeColor = Color.Firebrick;
                        }
                        li.Group = ThreatSafety.IsSafeToDelete(t) ? grpThreatSafe : grpThreatMaybe;
                    }
                    UpdateThreatGroupHeaders();
                    RefreshThreatCount();
                });
            }
            catch { }
        }

        private ListViewItem FindThreatItem(Threat t)
        {
            foreach (ListViewItem li in lvThreats.Items)
                if (ReferenceEquals(li.Tag, t)) return li;
            return null;
        }

        private static string DetailWithDefender(Threat t)
        {
            string extra = "";
            switch (t.Defender)
            {
                case DefenderCheck.VerdictThreat: extra = "Defender 检出威胁"; break;
                case DefenderCheck.VerdictClean: extra = "Defender 未检出"; break;
                case DefenderCheck.VerdictTimeout: extra = "Defender 复核超时"; break;
                case DefenderCheck.VerdictError: extra = "Defender 复核失败"; break;
            }
            if (extra.Length == 0) return t.Detail;
            return (t.Detail == null ? "" : t.Detail) + " ｜ " + extra;
        }

        private void AppendLogSafe(string msg)
        {
            try
            {
                if (!IsDisposed) BeginInvoke((MethodInvoker)delegate { AppendLog(msg); });
            }
            catch { }
        }

        private void StopScan()
        {
            if (_engine != null && _scanning)
            {
                _stopRequested = true;
                _engine.Cancel();
                btnStop.Enabled = false;
                AppendLog("用户请求停止扫描。");
                SetStatus("正在停止...");
            }
        }

        private void DeleteSelectedThreats()
        {
            if (lvThreats.SelectedItems.Count == 0) return;
            DialogResult r = MessageBox.Show(this,
                "将永久删除 " + lvThreats.SelectedItems.Count + " 个文件，删除后无法恢复。\n\n请确认这些文件确实可疑（可先双击定位查看）。是否继续？",
                "确认删除", MessageBoxButtons.YesNo, MessageBoxIcon.Warning, MessageBoxDefaultButton.Button2);
            if (r != DialogResult.Yes) return;
            int ok = 0;
            int fail = 0;
            foreach (ListViewItem li in lvThreats.SelectedItems)
            {
                Threat t = li.Tag as Threat;
                if (t == null) continue;
                try
                {
                    File.SetAttributes(t.Path, FileAttributes.Normal);
                    File.Delete(t.Path);
                    ok++;
                    _threats.Remove(t);
                    li.SubItems[5].Text = "已删除";
                    li.ForeColor = Color.Gray;
                    AppendLog("已删除: " + t.Path);
                }
                catch (Exception ex)
                {
                    fail++;
                    li.SubItems[5].Text = "删除失败: " + ex.Message;
                    AppendLog("删除失败: " + t.Path + " -> " + ex.Message);
                }
            }
            RefreshThreatCount();
            MessageBox.Show(this, "删除完成：成功 " + ok + " 个，失败 " + fail + " 个。", "满唯杀毒", MessageBoxButtons.OK, MessageBoxIcon.Information);
        }

        // 删除/忽略后同步"已扫描…发现 n 项"和按钮状态（扫描进行中也能安全调用）。
        private void RefreshThreatCount()
        {
            int scanned = _engine == null ? 0 : _engine.FilesScanned;
            lblCounts.Text = "已扫描 " + scanned + " 个文件，发现 " + _threats.Count + " 项";
            if (!_scanning) btnDelete.Enabled = _threats.Count > 0;
            UpdateThreatGroupHeaders();
        }

        // 威胁列表按"放心删/疑似垃圾"分组，标题带条数与体积。
        private void UpdateThreatGroupHeaders()
        {
            if (grpThreatSafe == null || grpThreatMaybe == null) return;
            int safen = 0, mayben = 0;
            long safeB = 0, maybeB = 0;
            // 按当前列表里可见的行统计，筛选时分组标题与列表保持一致。
            if (lvThreats != null)
            {
                foreach (ListViewItem li in lvThreats.Items)
                {
                    Threat t = li.Tag as Threat;
                    if (t == null) continue;
                    if (li.Group == grpThreatSafe) { safen++; safeB += t.Size; }
                    else { mayben++; maybeB += t.Size; }
                }
            }
            grpThreatSafe.Header = "放心删（" + safen + " 个 · " + FormatSize(safeB) + "）";
            grpThreatMaybe.Header = "疑似垃圾（" + mayben + " 个 · " + FormatSize(maybeB) + "）";
            if (lblThreatSummary != null)
            {
                lblThreatSummary.Text = "放心删 " + safen + " 个（" + FormatSize(safeB) + "）";
                lblThreatMaybe.Text = "疑似垃圾 " + mayben + " 个（" + FormatSize(maybeB) + "）";
                _syncingSummary = true;
                chkSumSafe.Checked = false;
                chkSumMaybe.Checked = false;
                _syncingSummary = false;
                LayoutSummaryRow(lblThreatSummary, chkSumSafe, lblThreatMaybe, chkSumMaybe);
                bool show = (safen + mayben) > 0;
                lblThreatSummary.Visible = show;
                lblThreatMaybe.Visible = show;
                chkSumSafe.Visible = show;
                chkSumMaybe.Visible = show;
                if (btnSelectAll != null) btnSelectAll.Visible = show;
            }
        }

        // 汇总行上的两个小方框分别紧跟在"放心删""疑似垃圾"文字右边。
        private void LayoutSummaryRow(Label safeText, CheckBox safeBox, Label maybeText, CheckBox maybeBox)
        {
            if (safeText == null || safeBox == null || maybeText == null || maybeBox == null) return;
            safeBox.Left = safeText.Right + Px(4);
            safeBox.Top = safeText.Top + (safeText.Height - safeBox.Height) / 2 + Px(1);
            maybeText.Left = safeBox.Right + Px(18);
            maybeText.Top = safeText.Top;
            maybeBox.Left = maybeText.Right + Px(4);
            maybeBox.Top = maybeText.Top + (maybeText.Height - maybeBox.Height) / 2 + Px(1);
        }

        // 只选中某一组（放心删或疑似垃圾）里的行。
        private void SelectGroupThreats(ListViewGroup group, bool select)
        {
            if (group == null) return;
            lvThreats.BeginUpdate();
            foreach (ListViewItem li in lvThreats.Items)
            {
                if (li.Group == group) li.Selected = select;
            }
            lvThreats.EndUpdate();
            lvThreats.Invalidate();
            if (select && lvThreats.Items.Count > 0) lvThreats.Focus();
        }

        private void SelectGroupBig(ListViewGroup group, bool select)
        {
            if (group == null) return;
            lvBig.BeginUpdate();
            foreach (ListViewItem li in lvBig.Items)
            {
                if (li.Group == group) li.Selected = select;
            }
            lvBig.EndUpdate();
            lvBig.Invalidate();
            if (select && lvBig.Items.Count > 0) lvBig.Focus();
        }

        private void OpenThreatLocation()
        {
            if (lvThreats.SelectedItems.Count == 0) return;
            Threat t = lvThreats.SelectedItems[0].Tag as Threat;
            if (t == null) return;
            OpenInExplorer(t.Path);
        }

        private static void OpenInExplorer(string path)
        {
            try
            {
                if (File.Exists(path)) Process.Start("explorer.exe", "/select,\"" + path + "\"");
                else
                {
                    string dir = Path.GetDirectoryName(path);
                    if (!string.IsNullOrEmpty(dir) && Directory.Exists(dir)) Process.Start("explorer.exe", "\"" + dir + "\"");
                }
            }
            catch { }
        }

        // 列表右键菜单：复制完整路径、按内容自动调整列宽（把省略号展开）、定位文件。
        private ContextMenuStrip BuildListMenu(ListView lv, Action locate)
        {
            ContextMenuStrip menu = new ContextMenuStrip();
            menu.Items.Add("复制完整路径", null, delegate { CopySelectedPath(lv); });
            menu.Items.Add("自动调整列宽", null, delegate { AutoFitColumns(lv); });
            menu.Items.Add("定位文件", null, delegate { locate(); });
            return menu;
        }

        private static void CopySelectedPath(ListView lv)
        {
            if (lv.SelectedItems.Count == 0) return;
            ListViewItem li = lv.SelectedItems[0];
            string path = null;
            BigFileItem bf = li.Tag as BigFileItem;
            if (bf != null) path = bf.Path;
            if (path == null)
            {
                Threat th = li.Tag as Threat;
                if (th != null) path = th.Path;
            }
            if (path == null && li.SubItems.Count > 0) path = li.SubItems[li.SubItems.Count - 1].Text;
            if (string.IsNullOrEmpty(path)) return;
            try { Clipboard.SetText(path); }
            catch { }
        }

        // Width = -2 让每一列按"表头 + 内容"里最宽的那个自适应，长路径/长说明一次展开。
        private static void AutoFitColumns(ListView lv)
        {
            for (int i = 0; i < lv.Columns.Count; i++) lv.Columns[i].Width = -2;
        }

        private void RunAudit()
        {
            btnAudit.Enabled = false;
            lblAuditStatus.Text = "正在审计...";
            AppendLog("开始启动项/服务/计划任务审计...");
            Thread th = new Thread(delegate ()
            {
                List<AuditItem> all = new List<AuditItem>();
                try { all.AddRange(Audit.CollectStartup()); } catch (Exception ex) { SafeLog("自启动审计异常: " + ex.Message); }
                try { all.AddRange(Audit.CollectServices()); } catch (Exception ex) { SafeLog("服务审计异常: " + ex.Message); }
                try { all.AddRange(Audit.CollectTasks()); } catch (Exception ex) { SafeLog("计划任务审计异常: " + ex.Message); }
                try { all.AddRange(Audit.CollectExtra()); } catch (Exception ex) { SafeLog("其他审计异常: " + ex.Message); }
                if (IsDisposed) return;
                BeginInvoke((MethodInvoker)delegate
                {
                    _audit.Clear();
                    _audit.AddRange(all);
                    RefreshAuditView();
                    btnAudit.Enabled = true;
                    int high = 0;
                    foreach (AuditItem it in all) { if (it.Sev == Severity.High) high++; }
                    lblAuditStatus.Text = "审计完成：共 " + all.Count + " 项，高风险 " + high + " 项";
                    AppendLog("审计完成：共 " + all.Count + " 项，其中高风险 " + high + " 项。");
                });
            });
            th.IsBackground = true;
            th.Start();
        }

        private void SafeLog(string msg)
        {
            if (IsDisposed) return;
            try { BeginInvoke((MethodInvoker)delegate { AppendLog(msg); }); } catch { }
        }

        private void RefreshAuditView()
        {
            if (lvAudit == null) return;
            string filter = cboCategory.SelectedItem == null ? "全部" : cboCategory.SelectedItem.ToString();
            lvAudit.BeginUpdate();
            lvAudit.Items.Clear();
            foreach (AuditItem it in _audit)
            {
                if (filter != "全部" && it.Category != filter) continue;
                ListViewItem li = new ListViewItem(new string[]
                {
                    it.Category, it.Name, it.Command, it.Signer, Sev.Text(it.Sev), it.Note
                });
                li.Tag = it;
                if (it.Sev == Severity.High) li.ForeColor = Color.Firebrick;
                else if (it.Sev == Severity.Medium) li.ForeColor = Color.DarkOrange;
                lvAudit.Items.Add(li);
            }
            lvAudit.EndUpdate();
        }

        private void AuditOpenLocation()
        {
            if (lvAudit.SelectedItems.Count == 0) return;
            AuditItem it = lvAudit.SelectedItems[0].Tag as AuditItem;
            if (it == null) return;
            string path = Audit.CommandToPath(it.Command);
            if (File.Exists(path)) OpenInExplorer(path);
            else if (File.Exists(it.Location)) OpenInExplorer(it.Location);
            else if (Directory.Exists(it.Location)) Process.Start("explorer.exe", "\"" + it.Location + "\"");
        }

        private void AuditCopyCommand()
        {
            if (lvAudit.SelectedItems.Count == 0) return;
            AuditItem it = lvAudit.SelectedItems[0].Tag as AuditItem;
            if (it == null) return;
            try { Clipboard.SetText(it.Command); } catch { }
        }

        private void AuditDelete()
        {
            if (lvAudit.SelectedItems.Count == 0) return;
            AuditItem it = lvAudit.SelectedItems[0].Tag as AuditItem;
            if (it == null) return;
            if (string.IsNullOrEmpty(it.DeleteKind))
            {
                MessageBox.Show(this, "该项为只读信息，无法在这里删除。", "满唯杀毒", MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }
            if (MessageBox.Show(this, "确定删除该项吗？\n\n类别: " + it.Category + "\n名称: " + it.Name + "\n位置: " + it.Location + "\n\n操作不可撤销。",
                "确认删除", MessageBoxButtons.YesNo, MessageBoxIcon.Warning, MessageBoxDefaultButton.Button2) != DialogResult.Yes) return;
            try
            {
                if (it.DeleteKind == "registry")
                {
                    DeleteRegistryValue(it.DeleteRef, it.DeleteValue);
                }
                else
                {
                    File.SetAttributes(it.DeleteRef, FileAttributes.Normal);
                    File.Delete(it.DeleteRef);
                }
                AppendLog("已删除审计项: " + it.Name + " (" + it.Location + ")");
                lvAudit.SelectedItems[0].SubItems[5].Text = "已删除";
            }
            catch (Exception ex)
            {
                MessageBox.Show(this, "删除失败: " + ex.Message, "满唯杀毒", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private static void DeleteRegistryValue(string location, string valuename)
        {
            string hive = "";
            string sub = location;
            if (location.StartsWith("HKCU\\", StringComparison.OrdinalIgnoreCase)) { hive = "HKCU"; sub = location.Substring(5); }
            else if (location.StartsWith("HKLM\\", StringComparison.OrdinalIgnoreCase)) { hive = "HKLM"; sub = location.Substring(5); }
            if (hive.Length == 0) throw new Exception("无法识别的注册表路径: " + location);
            RegistryKey baseKey = hive == "HKCU" ? Registry.CurrentUser : Registry.LocalMachine;
            using (RegistryKey rk = baseKey.OpenSubKey(sub, true))
            {
                if (rk == null) throw new Exception("注册表项不存在: " + location);
                rk.DeleteValue(valuename, false);
            }
        }

        private void ExportReport()
        {
            if (_threats.Count == 0 && _audit.Count == 0)
            {
                MessageBox.Show(this, "还没有扫描或审计结果可导出。", "满唯杀毒", MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }
            string dir = AppPaths.ReportsDir;
            try { Directory.CreateDirectory(dir); } catch { }
            string file = Path.Combine(dir, "满唯杀毒-" + DateTime.Now.ToString("yyyyMMdd-HHmmss") + ".html");
            StringBuilder sb = new StringBuilder();
            sb.AppendLine("<!DOCTYPE html><html lang=\"zh-Cn\"><head><meta charset=\"utf-8\"><title>满唯杀毒 报告</title>");
            sb.AppendLine("<style>body{font-family:'Microsoft YaHei UI',sans-serif;margin:24px;color:#222}h1{font-size:20px}table{border-collapse:collapse;width:100%;margin:12px 0;font-size:13px}th,td{border:1px solid #ccc;padding:6px 8px;text-align:left;vertical-align:top}th{background:#f2f2f2}.high{color:#b00020;font-weight:bold}.med{color:#b36b00}.low{color:#555}</style></head><body>");
            sb.AppendLine("<h1>满唯杀毒 扫描报告</h1>");
            sb.AppendLine("<p>生成时间：" + DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss") + "　主机：" + Environment.MachineName + "　用户：" + Environment.UserName + "　规则库：" + _sigs.Rules.Version + "</p>");
            sb.AppendLine("<h2>威胁列表（" + _threats.Count + "）</h2><table><tr><th>严重度</th><th>名称</th><th>大小</th><th>类型</th><th>说明</th><th>磁盘</th><th>路径</th></tr>");
            foreach (Threat t in _threats)
            {
                sb.AppendLine("<tr><td class=\"" + ClassOf(t.Sev) + "\">" + Sev.Text(t.Sev) + "</td><td>" + H(t.Name) + "</td><td>" + H(FormatSize(t.Size)) + "</td><td>" + H(t.Kind) + "</td><td>" + H(DetailWithDefender(t)) + "</td><td>" + H(DriveOf(t.Path)) + "</td><td>" + H(t.Path) + "</td></tr>");
            }
            sb.AppendLine("</table>");
            sb.AppendLine("<h2>启动项 / 服务 / 计划任务（" + _audit.Count + "）</h2><table><tr><th>类别</th><th>名称</th><th>命令/路径</th><th>签名</th><th>严重度</th><th>说明</th></tr>");
            foreach (AuditItem it in _audit)
            {
                sb.AppendLine("<tr><td>" + H(it.Category) + "</td><td>" + H(it.Name) + "</td><td>" + H(it.Command) + "</td><td>" + H(it.Signer) + "</td><td class=\"" + ClassOf(it.Sev) + "\">" + Sev.Text(it.Sev) + "</td><td>" + H(it.Note) + "</td></tr>");
            }
            sb.AppendLine("</table><p style=\"color:#666;font-size:12px\">本报告由 满唯杀毒 生成；扫描为只读操作，报告中“已删除”状态需人工确认。</p></body></html>");
            try
            {
                File.WriteAllText(file, sb.ToString(), new UTF8Encoding(true));
                AppendLog("报告已导出: " + file);
                if (MessageBox.Show(this, "报告已保存到：\n" + file + "\n\n是否打开？", "满唯杀毒", MessageBoxButtons.YesNo, MessageBoxIcon.Information) == DialogResult.Yes)
                    Process.Start(file);
            }
            catch (Exception ex)
            {
                MessageBox.Show(this, "导出失败: " + ex.Message, "满唯杀毒", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        // 大文件页的 HTML 报告：按"放心删 / 疑似垃圾"分组列出，附合计体积。
        private void ExportBigReport()
        {
            if (_bigItems.Count == 0)
            {
                MessageBox.Show(this, "还没有大文件扫描结果可导出。", "满唯杀毒", MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }
            int safen = 0, mayben = 0;
            long safeB = 0, maybeB = 0;
            foreach (BigFileItem it in _bigItems)
            {
                if (it.Safe) { safen++; safeB += it.Size; }
                else { mayben++; maybeB += it.Size; }
            }

            string dir = AppPaths.ReportsDir;
            try { Directory.CreateDirectory(dir); } catch { }
            string file = Path.Combine(dir, "满唯杀毒-大文件-" + DateTime.Now.ToString("yyyyMMdd-HHmmss") + ".html");
            StringBuilder sb = new StringBuilder();
            sb.AppendLine("<!DOCTYPE html><html lang=\"zh-Cn\"><head><meta charset=\"utf-8\"><title>满唯杀毒 大文件报告</title>");
            sb.AppendLine("<style>body{font-family:'Microsoft YaHei UI',sans-serif;margin:24px;color:#222}h1{font-size:20px}h2{font-size:16px;margin-top:20px}table{border-collapse:collapse;width:100%;margin:12px 0;font-size:13px}th,td{border:1px solid #ccc;padding:6px 8px;text-align:left;vertical-align:top}th{background:#f2f2f2}.high{color:#b00020;font-weight:bold}.med{color:#b36b00}</style></head><body>");
            sb.AppendLine("<h1>满唯杀毒 大文件扫描报告</h1>");
            sb.AppendLine("<p>生成时间：" + DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss") + "　主机：" + Environment.MachineName + "　用户：" + Environment.UserName + "</p>");
            sb.AppendLine("<p>共 " + _bigItems.Count + " 个文件；放心删 " + safen + " 个（" + FormatSize(safeB) + "），疑似垃圾 " + mayben + " 个（" + FormatSize(maybeB) + "）。</p>");

            sb.AppendLine("<h2>放心删（" + safen + " 个 · " + FormatSize(safeB) + "）</h2>");
            AppendBigTable(sb, true);
            sb.AppendLine("<h2>疑似垃圾（" + mayben + " 个 · " + FormatSize(maybeB) + "）</h2>");
            AppendBigTable(sb, false);
            sb.AppendLine("<p style=\"color:#666;font-size:12px\">本报告由 满唯杀毒 生成；删除为永久删除，执行前请再次确认。</p></body></html>");

            try
            {
                File.WriteAllText(file, sb.ToString(), new UTF8Encoding(true));
                AppendLog("大文件报告已导出: " + file);
                if (MessageBox.Show(this, "报告已保存到：\n" + file + "\n\n是否打开？", "满唯杀毒", MessageBoxButtons.YesNo, MessageBoxIcon.Information) == DialogResult.Yes)
                    Process.Start(file);
            }
            catch (Exception ex)
            {
                MessageBox.Show(this, "导出失败: " + ex.Message, "满唯杀毒", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void AppendBigTable(StringBuilder sb, bool safeGroup)
        {
            sb.AppendLine("<table><tr><th>严重度</th><th>名称</th><th>大小</th><th>类别</th><th>原因</th><th>最后修改</th><th>磁盘</th><th>路径</th></tr>");
            bool any = false;
            foreach (BigFileItem it in _bigItems)
            {
                if (it.Safe != safeGroup) continue;
                any = true;
                sb.AppendLine("<tr><td class=\"" + ClassOf(it.Sev) + "\">" + Sev.Text(it.Sev) + "</td><td>" + H(Path.GetFileName(it.Path)) + "</td><td>" + H(FormatSize(it.Size)) + "</td><td>" + H(it.Category) + "</td><td>" + H(it.Reason) + "</td><td>" + H(it.Modified.ToString("yyyy-MM-dd HH:mm")) + "</td><td>" + H(DriveOf(it.Path)) + "</td><td>" + H(it.Path) + "</td></tr>");
            }
            sb.AppendLine("</table>");
            if (!any) sb.AppendLine("<p style=\"color:#666\">（无）</p>");
        }

        private static string ClassOf(Severity s)
        {
            if (s == Severity.High) return "high";
            if (s == Severity.Medium) return "med";
            return "low";
        }

        private static string H(string s)
        {
            if (s == null) return "";
            return s.Replace("&", "&amp;").Replace("<", "&lt;").Replace(">", "&gt;").Replace("\"", "&quot;");
        }

        private static string FormatSize(long bytes)
        {
            if (bytes < 1024) return bytes + " B";
            if (bytes < 1024 * 1024) return (bytes / 1024.0).ToString("0.0", CultureInfo.InvariantCulture) + " KB";
            if (bytes < 1024L * 1024 * 1024) return (bytes / 1024.0 / 1024.0).ToString("0.0", CultureInfo.InvariantCulture) + " MB";
            return (bytes / 1024.0 / 1024.0 / 1024.0).ToString("0.00", CultureInfo.InvariantCulture) + " GB";
        }

        // 结果来自哪个盘：取路径根（C:\ → "C:"），注册表等无盘符项显示 "-"。
        private static string DriveOf(string path)
        {
            if (string.IsNullOrEmpty(path)) return "-";
            try
            {
                string root = Path.GetPathRoot(path);
                if (string.IsNullOrEmpty(root) || root.Length < 2 || root[1] != ':') return "-";
                return root.Substring(0, 2).ToUpperInvariant();
            }
            catch
            {
                return "-";
            }
        }

        // 汇总行右侧的全选按钮：已全选则取消，否则全选。
        private void ToggleSelectAllThreats()
        {
            bool all = lvThreats.Items.Count > 0 && lvThreats.SelectedItems.Count >= lvThreats.Items.Count;
            SelectAllThreats(!all);
        }

        private void ToggleSelectAllBig()
        {
            bool all = lvBig.Items.Count > 0 && lvBig.SelectedItems.Count >= lvBig.Items.Count;
            SetAllBigSelected(!all);
        }

        private void SelectAllThreats(bool select)
        {
            lvThreats.BeginUpdate();
            try
            {
                foreach (ListViewItem li in lvThreats.Items) li.Selected = select;
            }
            finally
            {
                lvThreats.EndUpdate();
            }
            if (btnSelectAll != null) btnSelectAll.Text = select ? "取消全选" : "全选";
            // 把焦点交给列表，否则列表处于"非活动"状态，选中行不会显示蓝色高亮。
            if (lvThreats.Items.Count > 0)
            {
                lvThreats.Focus();
            }
        }

        private void ShowAbout()
        {
            string msg = "满唯杀毒 v" + Program.AppVersion + Environment.NewLine + Environment.NewLine
                + "本地查杀与启动项审计（辅助排查工具，不提供实时防护）" + Environment.NewLine
                + "规则库: " + _sigs.Rules.Version + "（哈希 " + _sigs.Rules.Hashes.Count
                + " / 特征串 " + _sigs.Rules.Strings.Count
                + " / 文件名 " + _sigs.Rules.Names.Count
                + " / 路径 " + _sigs.Rules.Paths.Count
                + " / 行为 " + _sigs.Rules.Behaviors.Count + "）" + Environment.NewLine
                + "程序构建: " + BuildStamp() + Environment.NewLine
                + "程序 SHA256: " + ShortHash(SignatureStore.Sha256File(Application.ExecutablePath)) + Environment.NewLine
                + "规则完整性: " + RuleIntegrityText() + Environment.NewLine
                + "配置目录: " + AppPaths.DataDir + Environment.NewLine
                + "当前权限: " + (Program.IsAdmin() ? "管理员" : "普通用户") + Environment.NewLine + Environment.NewLine
                + "遇到问题请右键托盘图标 → 导出诊断信息，把文件发给开发者。";
            MessageBox.Show(this, msg, "关于 满唯杀毒", MessageBoxButtons.OK, MessageBoxIcon.Information);
        }

        // 离线更新规则：校验格式与正则可编译性，备份旧规则后替换；失败自动回滚。
        private void ImportRulePack()
        {
            using (OpenFileDialog d = new OpenFileDialog())
            {
                d.Title = "选择规则包（signatures.json）";
                d.Filter = "规则包 (*.json)|*.json|所有文件 (*.*)|*.*";
                if (d.ShowDialog(this) != DialogResult.OK) return;

                string msg;
                if (!RulePack.Import(d.FileName, out msg))
                {
                    MessageBox.Show(this, msg, "满唯杀毒", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }
                SignatureStore fresh = new SignatureStore();
                fresh.Load(SignatureStore.DefaultRulePath);
                _sigs = fresh;
                AppendLog("规则包已导入并生效: " + msg);
                MessageBox.Show(this, msg + "\r\n\r\n已立即生效，无需重启。", "满唯杀毒", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
        }

        private static string ShortHash(string hash)
        {
            if (string.IsNullOrEmpty(hash)) return "不可用";
            return hash.Substring(0, Math.Min(16, hash.Length)) + "…";
        }

        private string RuleIntegrityText()
        {
            try
            {
                string h = SignatureStore.Sha256File(SignatureStore.DefaultRulePath);
                if (string.IsNullOrEmpty(h)) return "规则文件不可读";
                return string.Equals(h, RulesHash.Sha256, StringComparison.OrdinalIgnoreCase)
                    ? "与随程序发布的版本一致"
                    : "已被替换（自定义规则包或被修改）";
            }
            catch { return "校验失败"; }
        }

        private void ExportDiagnostics()
        {
            try
            {
                string text = Diagnostics.Build(_sigs, _settings, rtbLog == null ? "" : rtbLog.Text);
                string file = Diagnostics.Save(text);
                AppendLog("诊断信息已导出: " + file);
                try { Process.Start("explorer.exe", "/select,\"" + file + "\""); } catch { }
            }
            catch (Exception ex)
            {
                MessageBox.Show(this, "导出诊断信息失败: " + ex.Message, "满唯杀毒", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        // 启动时把可执行文件自身的编译时间打进日志，方便确认当前跑的是哪个版本。
        private static string BuildStamp()
        {
            try { return System.IO.File.GetLastWriteTime(Application.ExecutablePath).ToString("yyyy-MM-dd HH:mm:ss"); }
            catch { return "未知"; }
        }

        private void SetStatus(string text)
        {
            if (lblStatus == null) return;
            lblStatus.Text = text == null ? "" : text;
        }

        private void AppendLog(string msg)
        {
            if (rtbLog == null) return;
            rtbLog.AppendText("[" + DateTime.Now.ToString("HH:mm:ss") + "] " + msg + Environment.NewLine);
            rtbLog.SelectionStart = rtbLog.TextLength;
            rtbLog.ScrollToCaret();
        }

        private void LoadSettings()
        {
            try
            {
                string file = AppPaths.SettingsFile;
                if (File.Exists(file))
                {
                    JavaScriptSerializer ser = new JavaScriptSerializer();
                    AppSettings s = ser.Deserialize<AppSettings>(File.ReadAllText(file, Encoding.UTF8));
                    if (s != null) _settings = s;
                }
            }
            catch { }
        }

        private void SaveSettings()
        {
            try
            {
                string file = AppPaths.SettingsFile;
                JavaScriptSerializer ser = new JavaScriptSerializer();
                File.WriteAllText(file, ser.Serialize(_settings), Encoding.UTF8);
            }
            catch { }
        }
    }
}

namespace GuardScan
{
internal class ThreatItemComparer : System.Collections.IComparer
{
    private readonly int _col;
    private readonly bool _asc;
    public ThreatItemComparer(int col, bool asc) { _col = col; _asc = asc; }

    public int Compare(object x, object y)
    {
        ListViewItem a = (ListViewItem)x;
        ListViewItem b = (ListViewItem)y;
        int r;
        Threat ta = a.Tag as Threat;
        Threat tb = b.Tag as Threat;
        if (ta != null && tb != null)
        {
            switch (_col)
            {
                case 0: r = ta.Sev.CompareTo(tb.Sev); break;
                case 1: r = string.Compare(ta.Name, tb.Name, StringComparison.OrdinalIgnoreCase); break;
                case 2: r = ta.Size.CompareTo(tb.Size); break;
                case 4: r = string.Compare(ta.Detail, tb.Detail, StringComparison.OrdinalIgnoreCase); break;
                case 6: r = string.Compare(ta.Path, tb.Path, StringComparison.OrdinalIgnoreCase); break;
                default: r = string.Compare(a.SubItems[_col].Text, b.SubItems[_col].Text, StringComparison.OrdinalIgnoreCase); break;
            }
        }
        else
        {
            r = string.Compare(a.SubItems[_col].Text, b.SubItems[_col].Text, StringComparison.OrdinalIgnoreCase);
        }
        return _asc ? r : -r;
    }
}
}
