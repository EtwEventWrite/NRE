using System;

namespace NRE.Core.Evasion
{
/// <summary>
/// PE parsing helpers for run-from-memory: entry point, image size, TLS directory.
/// Actual execution is in NRE.Stub.Loaders.NativePELoader.
/// </summary>
public static class RunPE
{
    public const ushort IMAGE_DIRECTORY_ENTRY_TLS = 9;

    /// <summary>
    /// Get entry point RVA and whether the PE is a DLL. Returns (entryRva, isDll); entryRva 0 if invalid.
    /// </summary>
    public static (int EntryRva, bool IsDll) GetEntryInfo(byte[] peBytes)
    {
        if (peBytes == null || peBytes.Length < 64) return (0, false);
        if (BitConverter.ToUInt16(peBytes, 0) != 0x5A4D) return (0, false);

        int eLfanew = BitConverter.ToInt32(peBytes, 0x3C);
        if (eLfanew <= 0 || eLfanew + 24 >= peBytes.Length || BitConverter.ToUInt32(peBytes, eLfanew) != 0x00004550)
            return (0, false);

        ushort characteristics = BitConverter.ToUInt16(peBytes, eLfanew + 22);
        const ushort IMAGE_FILE_DLL = 0x2000;
        bool isDll = (characteristics & IMAGE_FILE_DLL) != 0;

        ushort sizeOfOptionalHeader = BitConverter.ToUInt16(peBytes, eLfanew + 20);
        int optHeaderOff = eLfanew + 24;
        ushort magic = BitConverter.ToUInt16(peBytes, optHeaderOff);
        int entryRva = magic == 0x20B
            ? BitConverter.ToInt32(peBytes, optHeaderOff + 16)
            : BitConverter.ToInt32(peBytes, optHeaderOff + 16);
        return (entryRva, isDll);
    }

    /// <summary>
    /// Get TLS directory RVA and size if present.
    /// </summary>
    public static (uint Rva, uint Size) GetTlsDirectory(byte[] peBytes)
    {
        if (peBytes == null || peBytes.Length < 64) return (0, 0);
        int eLfanew = BitConverter.ToInt32(peBytes, 0x3C);
        if (eLfanew <= 0 || eLfanew + 24 >= peBytes.Length) return (0, 0);
        ushort magic = BitConverter.ToUInt16(peBytes, eLfanew + 24);
        int dataDirOff = magic == 0x20B ? eLfanew + 24 + 112 : eLfanew + 24 + 96;
        if (dataDirOff + (IMAGE_DIRECTORY_ENTRY_TLS + 1) * 8 > peBytes.Length) return (0, 0);
        uint rva = BitConverter.ToUInt32(peBytes, dataDirOff + IMAGE_DIRECTORY_ENTRY_TLS * 8);
        uint size = BitConverter.ToUInt32(peBytes, dataDirOff + IMAGE_DIRECTORY_ENTRY_TLS * 8 + 4);
        return (rva, size);
    }

    /// <summary>
    /// Get size of image from optional header.
    /// </summary>
    public static uint GetSizeOfImage(byte[] peBytes)
    {
        if (peBytes == null || peBytes.Length < 64) return 0;
        int eLfanew = BitConverter.ToInt32(peBytes, 0x3C);
        if (eLfanew <= 0 || eLfanew + 64 >= peBytes.Length) return 0;
        return BitConverter.ToUInt32(peBytes, eLfanew + 24 + 56);
    }
}
}
