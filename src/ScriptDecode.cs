using System;
using System.Collections.Generic;
using System.Text;
using System.Text.RegularExpressions;

namespace GuardScan
{
    // 把脚本里的 base64 / -EncodedCommand 载荷解出来，附在原文后面一起匹配。
    // 只做一层解码，总长度受限，避免被超大载荷拖慢。
    internal static class ScriptDecode
    {
        private const int MaxDecodedChars = 2 * 1024 * 1024;

        private static readonly Regex EncodedArg = new Regex(
            @"-(?:encodedcommand|enc|e)\s+([A-Za-z0-9+/=]{16,})",
            RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.Compiled);

        private static readonly Regex Base64Literal = new Regex(
            @"(?:frombase64string\s*\(\s*)?[""']([A-Za-z0-9+/=]{32,})[""']",
            RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.Compiled);

        public static string Expand(string text)
        {
            if (string.IsNullOrEmpty(text)) return text;
            StringBuilder sb = new StringBuilder(text.Length + 4096);
            sb.Append(text);
            int added = 0;

            MatchCollection enc = EncodedArg.Matches(text);
            foreach (Match m in enc)
            {
                string dec = DecodePayload(m.Groups[1].Value);
                if (string.IsNullOrEmpty(dec)) continue;
                sb.Append('\n').Append(dec);
                added += dec.Length;
                if (added >= MaxDecodedChars) return sb.ToString();
            }

            MatchCollection b64 = Base64Literal.Matches(text);
            foreach (Match m in b64)
            {
                string tok = m.Groups[1].Value;
                if (tok.Length < 32) continue;
                string dec = DecodePayload(tok);
                if (string.IsNullOrEmpty(dec)) continue;
                sb.Append('\n').Append(dec);
                added += dec.Length;
                if (added >= MaxDecodedChars) return sb.ToString();
            }
            return sb.ToString();
        }

        private static string DecodePayload(string token)
        {
            try
            {
                byte[] data = Convert.FromBase64String(token);
                if (data.Length < 8) return null;

                string utf8 = Encoding.UTF8.GetString(data);
                if (LooksLikeText(utf8)) return utf8;

                string utf16 = Encoding.Unicode.GetString(data);
                if (LooksLikeText(utf16)) return utf16;
                return null;
            }
            catch { return null; }
        }

        // 认为“像文本”：可打印字符（含中文）占比高、没有大量 NUL。
        private static bool LooksLikeText(string s)
        {
            if (string.IsNullOrEmpty(s)) return false;
            int bad = 0;
            int n = s.Length > 4096 ? 4096 : s.Length;
            for (int i = 0; i < n; i++)
            {
                char c = s[i];
                if (c == '\0') return false;
                if (char.IsControl(c) && c != '\r' && c != '\n' && c != '\t') bad++;
            }
            return bad * 20 < n;
        }
    }
}
