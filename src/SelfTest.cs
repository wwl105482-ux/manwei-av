using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace GuardScan
{
    public static class SelfTest
    {
        public static int Run()
        {
            int failures = 0;
            Console.WriteLine("=== 满唯杀毒 selftest ===");
            string baseDir = AppDomain.CurrentDomain.BaseDirectory;
            string rulesPath = Path.Combine(baseDir, "rules", "signatures.json");
            SignatureStore sigs = new SignatureStore();
            bool loaded = sigs.Load(rulesPath);
            Console.WriteLine("rules_loaded=" + loaded + " version=" + sigs.Rules.Version +
                " hashes=" + sigs.Rules.Hashes.Count + " strings=" + sigs.Rules.Strings.Count +
                " names=" + sigs.Rules.Names.Count + " paths=" + sigs.Rules.Paths.Count +
                " behaviors=" + sigs.Rules.Behaviors.Count);
            if (!loaded) failures++;

            string samples = Path.Combine(baseDir, "tests", "samples");
            if (!Directory.Exists(samples))
            {
                Console.WriteLine("SKIP|samples_missing|" + samples);
            }
            else
            {
                ScanOptions opt = new ScanOptions();
                opt.Targets.Add(samples);
                opt.Threads = 2;
                opt.HashFiles = false;
                ScanEngine eng = new ScanEngine(sigs, opt);
                List<Threat> found = new List<Threat>();
                eng.ThreatFound += delegate (Threat t) { found.Add(t); };
                eng.Run();

                bool sample = false;
                bool benignHit = false;
                bool behaviorSample = false;
                bool macroSample = false;
                foreach (Threat t in found)
                {
                    if (t.Path.ToLowerInvariant().EndsWith("selftest-threat.ps1")) sample = true;
                    if (t.Path.ToLowerInvariant().Contains("benign")) benignHit = true;
                    if (t.Path.ToLowerInvariant().Contains("selftest-behavior.ps1")) behaviorSample = true;
                    if (t.Path.ToLowerInvariant().Contains("macro-sample.docx")) macroSample = true;
                    Console.WriteLine("FOUND|" + Sev.Text(t.Sev) + "|" + t.Name + "|" + t.Path);
                }
                Console.WriteLine("sample_detected=" + sample);
                Console.WriteLine("benign_false_positive=" + benignHit);
                Console.WriteLine("behavior_detected=" + behaviorSample);
                Console.WriteLine("macro_detected=" + macroSample);
                if (!sample) { Console.WriteLine("FAIL|sample_not_detected"); failures++; }
                else Console.WriteLine("PASS|sample_detected");
                if (benignHit) { Console.WriteLine("FAIL|benign_false_positive"); failures++; }
                else Console.WriteLine("PASS|benign_clean");
                if (!behaviorSample) { Console.WriteLine("FAIL|behavior_not_detected"); failures++; }
                else Console.WriteLine("PASS|behavior_detected");
                if (!macroSample) { Console.WriteLine("FAIL|macro_not_detected"); failures++; }
                else Console.WriteLine("PASS|macro_detected");
            }

            bool doubleExt = FileChecks.HasDoubleExtension("invoice.pdf.exe");
            Console.WriteLine("double_ext_test=" + doubleExt);
            if (!doubleExt) { Console.WriteLine("FAIL|double_ext"); failures++; }
            else Console.WriteLine("PASS|double_ext");

            List<AuditItem> startup = Audit.CollectStartup();
            Console.WriteLine("startup_items=" + startup.Count);
            if (startup.Count == 0) { Console.WriteLine("FAIL|startup_empty"); failures++; }
            else Console.WriteLine("PASS|startup_items");

            Console.WriteLine("=== " + (failures == 0 ? "ALL PASS" : failures + " FAILED") + " ===");
            return failures == 0 ? 0 : 1;
        }
    }
}
