using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Web.Script.Serialization;

namespace GuardScan
{
    // 离线规则包导入：校验 → 备份 → 替换 → 用独立实例复验，失败自动回滚。
    internal static class RulePack
    {
        public static int CountRules(RuleSet rs)
        {
            if (rs == null) return 0;
            return (rs.Hashes == null ? 0 : rs.Hashes.Count)
                + (rs.Strings == null ? 0 : rs.Strings.Count)
                + (rs.Names == null ? 0 : rs.Names.Count)
                + (rs.Paths == null ? 0 : rs.Paths.Count)
                + (rs.Behaviors == null ? 0 : rs.Behaviors.Count);
        }

        // 只校验不落盘，用于“检查规则包”场景。
        public static bool Validate(string sourceFile, out RuleSet parsed, out string error)
        {
            parsed = null;
            error = "";
            string text;
            try { text = File.ReadAllText(sourceFile, Encoding.UTF8); }
            catch (Exception ex) { error = "读取失败: " + ex.Message; return false; }
            try
            {
                JavaScriptSerializer ser = new JavaScriptSerializer();
                ser.MaxJsonLength = 8 * 1024 * 1024;
                parsed = ser.Deserialize<RuleSet>(text);
            }
            catch (Exception ex) { error = "不是有效的 JSON: " + ex.Message; return false; }
            if (parsed == null || string.IsNullOrEmpty(parsed.Version)) { error = "缺少 Version 字段"; return false; }
            if (CountRules(parsed) == 0) { error = "规则包里没有任何规则"; return false; }

            SignatureStore probe = new SignatureStore();
            bool ok = probe.LoadFromText(text, sourceFile);
            if (!ok || !string.IsNullOrEmpty(probe.LoadError))
            {
                error = "正则或字段校验失败: " + probe.LoadError;
                return false;
            }
            if (probe.RegexErrors > 0)
            {
                error = probe.RegexErrors + " 条正则无法编译，第一条: " + probe.FirstRegexError;
                return false;
            }
            return true;
        }

        public static bool Import(string sourceFile, out string message)
        {
            message = "";
            RuleSet rs;
            string err;
            if (!Validate(sourceFile, out rs, out err))
            {
                message = "规则包校验失败: " + err;
                return false;
            }

            string target = SignatureStore.DefaultRulePath;
            string backup = null;
            try
            {
                Directory.CreateDirectory(Path.GetDirectoryName(target));
                if (File.Exists(target))
                {
                    backup = target + ".bak-" + DateTime.Now.ToString("yyyyMMdd-HHmmss");
                    File.Copy(target, backup, true);
                }
                File.Copy(sourceFile, target, true);

                SignatureStore fresh = new SignatureStore();
                bool ok = fresh.Load(target);
                if (!ok || !string.IsNullOrEmpty(fresh.LoadError))
                {
                    if (backup != null) { try { File.Copy(backup, target, true); } catch { } }
                    message = "导入后加载失败，已回滚: " + fresh.LoadError;
                    return false;
                }
                message = "已导入规则版本 " + fresh.Rules.Version
                    + "（哈希 " + fresh.Rules.Hashes.Count
                    + " / 特征串 " + fresh.Rules.Strings.Count
                    + " / 文件名 " + fresh.Rules.Names.Count
                    + " / 路径 " + fresh.Rules.Paths.Count
                    + " / 行为 " + fresh.Rules.Behaviors.Count + "）";
                if (backup != null) message += "；旧规则备份: " + Path.GetFileName(backup);
                return true;
            }
            catch (Exception ex)
            {
                message = "写入失败: " + ex.Message;
                return false;
            }
        }
    }
}
