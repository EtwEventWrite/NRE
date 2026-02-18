using NRE.Core.Common;

using System;
using System.IO;

namespace NRE.Builder.Utilities
{
/// <summary>
/// Detects if a PE file is .NET assembly or native, and whether it's EXE or DLL.
/// </summary>
public static class FileTypeDetector
{
    private const ushort DosSignature = 0x5A4D; // MZ
    private const uint PeSignature = 0x00004550; // PE\0\0
    private const uint Pe32Magic = 0x10B; // PE32
    private const uint Pe64Magic = 0x20B;  // PE32+
    private const int DirectoryEntryComDescriptor = 14; // .NET metadata
    private const int DirectoryEntryExport = 0;
    private const int DirectoryEntryEntryPoint = 16; // TLS not used for entry

    public static PayloadType Detect(byte[] peBytes)
    {
        if (peBytes == null || peBytes.Length < 64)
            return PayloadType.RawShellcode; // treat as shellcode if too small for PE

        if (peBytes.Length >= 2 && BitConverter.ToUInt16(peBytes, 0) != DosSignature)
            return PayloadType.RawShellcode; // no MZ

        var eLfanew = BitConverter.ToInt32(peBytes, 0x3C);
        if (eLfanew < 0 || eLfanew + 24 > peBytes.Length)
            return PayloadType.RawShellcode;

        if (BitConverter.ToUInt32(peBytes, eLfanew) != PeSignature)
            return PayloadType.RawShellcode;

        ushort sizeOfOptionalHeader = BitConverter.ToUInt16(peBytes, eLfanew + 20);
        if (sizeOfOptionalHeader < 128)
            return PayloadType.RawShellcode;

        var magic = BitConverter.ToUInt16(peBytes, eLfanew + 24);
        int dataDirOffset = eLfanew + 24 + sizeOfOptionalHeader - 128;
        if (dataDirOffset + 15 * 8 > peBytes.Length)
            return PayloadType.RawShellcode;

        // Data directory 14 = COM descriptor (.NET)
        var comDirRva = BitConverter.ToUInt32(peBytes, dataDirOffset + DirectoryEntryComDescriptor * 8);
        var comDirSize = BitConverter.ToUInt32(peBytes, dataDirOffset + DirectoryEntryComDescriptor * 8 + 4);
        bool isDotNet = comDirRva != 0 && comDirSize != 0;

        // EXE vs DLL: Characteristics in COFF header at eLfanew+22
        var characteristics = BitConverter.ToUInt16(peBytes, eLfanew + 22);
        const ushort ImageFileDll = 0x2000;
        bool isDll = (characteristics & ImageFileDll) != 0;

        if (isDotNet)
            return PayloadType.DotNetAssembly;
        if (isDll)
            return PayloadType.NativeDll;
        return PayloadType.NativeExe;
    }

    public static PayloadType DetectFromFile(string path)
    {
        var bytes = File.ReadAllBytes(path);
        return Detect(bytes);
    }
}
}
