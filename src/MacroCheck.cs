using System;
using System.Collections.Generic;
using System.Text;

namespace GuardScan
{
    // Office 宏内容判定：vbaProject.bin 里出现哪些危险调用，决定严重度。
    // 只看“有没有宏”会把大量正常带宏表格判成可疑；这里按实际 API 组合给结论。
    internal static class MacroCheck
    {
        private struct Marker
        {
            public string Text;
            public string Label;
            public Marker(string text, string label) { Text = text; Label = label; }
        }

        private static readonly Marker[] Markers = new Marker[]
        {
            new Marker("autoopen", "打开文档自动执行"),
            new Marker("document_open", "打开文档自动执行"),
            new Marker("workbook_open", "打开工作簿自动执行"),
            new Marker("auto_open", "打开文档自动执行"),
            new Marker("autoexec", "启用时自动执行"),
            new Marker("documentbeforeclose", "关闭时自动执行"),
            new Marker("wscript.shell", "调用命令行"),
            new Marker("shell(", "调用命令行"),
            new Marker("createobject", "创建 COM 对象"),
            new Marker("urldownloadtofile", "下载文件"),
            new Marker("msxml2.xmlhttp", "发起网络请求"),
            new Marker("winhttp.winhttprequest", "发起网络请求"),
            new Marker("powershell", "调用 PowerShell"),
            new Marker("cmd.exe", "调用命令行"),
            new Marker("strreverse", "字符串反转混淆"),
            new Marker("chr(", "字符拼接混淆"),
            new Marker("environ(", "读取环境变量"),
            new Marker("filecopy", "复制文件"),
            new Marker("kill ", "删除文件"),
        };

        // 返回 null 表示没有可判定的宏内容（调用方保留原有提示）。
        public static Threat Analyze(string virtualPath, byte[] data, int len)
        {
            if (data == null || len <= 0) return null;
            string ascii = Encoding.ASCII.GetString(data, 0, len).ToLowerInvariant();
            string utf16 = Encoding.Unicode.GetString(data, 0, len - (len % 2)).ToLowerInvariant();

            List<string> hits = new List<string>();
            foreach (Marker m in Markers)
            {
                if (ascii.Contains(m.Text) || utf16.Contains(m.Text))
                {
                    if (!hits.Contains(m.Label)) hits.Add(m.Label);
                }
            }
            if (hits.Count == 0) return null;

            Severity sev = hits.Count >= 3 ? Severity.High : Severity.Medium;
            string detail = "宏工程包含可疑调用：" + string.Join("、", hits.ToArray())
                + "。宏可执行任意命令，打开前请确认来源";
            return SignatureStore.MakeThreat(virtualPath, "Doc.VbaMacro.Suspicious", "宏文档", sev, detail);
        }
    }
}
