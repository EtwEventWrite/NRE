using System;
using System.IO;
using System.Runtime.InteropServices;
using Microsoft.Win32;

namespace NRE.Stub.Evasion
{
    /// <summary>
    /// Anti-VM: registry, files, environment, and system identifiers for VMware, VirtualBox, Hyper-V, QEMU.
    /// </summary>
    public static class AntiVM
    {
        private static readonly string[] VmEnvVars = new string[]
        {
            "VBOX_*", "VMWARE_*", "VBOX_USER_HOME", "VMWARE_ROOT", "VMPRODUCT",
            "VMCHECK", "VIRTUALBOX", "VMWARE", "HYPERV", "QEMU", "XEN"
        };

        private static readonly string[] VmRegPaths = new string[]
        {
                @"SOFTWARE\VMware, Inc.\VMware Tools",
            @"SOFTWARE\Oracle\VirtualBox Guest Additions",
            @"SYSTEM\CurrentControlSet\Services\VBoxGuest",
            @"SYSTEM\CurrentControlSet\Services\VBoxMouse",
            @"SYSTEM\CurrentControlSet\Services\VBoxService",
            @"SYSTEM\CurrentControlSet\Services\VBoxSF",
            @"SYSTEM\CurrentControlSet\Services\vmicheartbeat",
            @"SYSTEM\CurrentControlSet\Services\vmicvss",
            @"HARDWARE\ACPI\DSDT\VBOX__",
            @"HARDWARE\DEVICEMAP\Scsi\Scsi Port 0\Scsi Bus 0\Target Id 0\Logical Unit Id 0"
        };

        private static readonly string[] VmFiles = new string[]
        {
            @"C:\Windows\System32\drivers\vmmouse.sys",
            @"C:\Windows\System32\drivers\vmhgfs.sys",
            @"C:\Windows\System32\drivers\VBoxMouse.sys",
            @"C:\Windows\System32\drivers\VBoxGuest.sys",
            @"C:\Windows\System32\vboxdisp.dll",
            @"C:\Windows\System32\vboxhook.dll",
            @"C:\Windows\System32\vboxoglerrorspu.dll",
            @"C:\Windows\System32\vboxservice.exe",
            @"C:\Windows\System32\vmci.sys"
        };

        public static bool IsVirtualMachine()
        {
            if (CheckEnvironment()) return true;
            if (CheckRegistry()) return true;
            if (CheckFiles()) return true;
            if (CheckBios()) return true;
            return false;
        }

        private static bool CheckEnvironment()
    {
        try
        {
            foreach (var key in new[] { "VBOX_USER_HOME", "VMWARE_ROOT", "VMPRODUCT", "VMCHECK", "VIRTUALBOX", "VMWARE", "HYPERV", "QEMU" })
            {
                var v = Environment.GetEnvironmentVariable(key);
                if (!string.IsNullOrEmpty(v)) return true;
            }
            var all = Environment.GetEnvironmentVariables();
            foreach (var k in all.Keys)
            {
                var s = k?.ToString() ?? "";
                if (s.StartsWith("VBOX", StringComparison.OrdinalIgnoreCase) ||
                    s.StartsWith("VMWARE", StringComparison.OrdinalIgnoreCase))
                    return true;
            }
        }
        catch { }
        return false;
    }

        private static bool CheckRegistry()
        {
            try
            {
                using (var lm = Registry.LocalMachine)
                {
                    foreach (var sub in new string[] {
                        @"SOFTWARE\VMware, Inc.\VMware Tools",
                        @"SOFTWARE\Oracle\VirtualBox Guest Additions",
                        @"SYSTEM\CurrentControlSet\Services\VBoxGuest",
                        @"SYSTEM\CurrentControlSet\Services\VBoxMouse",
                        @"SYSTEM\CurrentControlSet\Services\vmicheartbeat"
                    })
                    {
                        try
                        {
                            using (var key = lm.OpenSubKey(sub))
                            {
                                if (key != null) return true;
                            }
                        }
                        catch { }
                    }
                }
            }
            catch { }
            return false;
        }

        private static bool CheckFiles()
        {
            try
            {
                foreach (var path in VmFiles)
                {
                    if (File.Exists(path)) return true;
                }
            }
            catch { }
            return false;
        }

        private static bool CheckBios()
        {
            try
            {
                using (var key = Registry.LocalMachine.OpenSubKey(@"HARDWARE\DESCRIPTION\System\BIOS"))
                {
                    var sysProd = (key != null && key.GetValue("SystemProductName") != null) ? key.GetValue("SystemProductName").ToString() : "";
                    var baseProd = (key != null && key.GetValue("BaseBoardProduct") != null) ? key.GetValue("BaseBoardProduct").ToString() : "";
                    var v = (sysProd + baseProd).ToUpperInvariant();
                    if (v.Contains("VIRTUAL") || v.Contains("VMWARE") || v.Contains("VBOX") ||
                        v.Contains("QEMU") || v.Contains("XEN") || v.Contains("HYPER-V"))
                        return true;
                }
            }
            catch { }
            return false;
        }
    }
}
