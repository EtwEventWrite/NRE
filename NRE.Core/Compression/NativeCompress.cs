using System;
using System.Runtime.InteropServices;
using NRE.Core.Common;

namespace NRE.Core.Compression
{
/// <summary>
/// Wraps RtlCompressBuffer for LZNT1/Xpress compression (builder side).
/// </summary>
public static class NativeCompress
{
    /// <summary>
    /// Compress data using LZNT1.
    /// </summary>
    public static byte[] CompressLZNT1(byte[] data)
    {
        return Compress(data, NativeMethods.COMPRESSION_FORMAT_LZNT1);
    }

    /// <summary>
    /// Compress data using Xpress.
    /// </summary>
    public static byte[] CompressXpress(byte[] data)
    {
        return Compress(data, NativeMethods.COMPRESSION_FORMAT_XPRESS);
    }

    private static byte[] Compress(byte[] data, ushort format)
    {
        var formatAndEngine = NativeMethods.MakeCompressionFormat(format);
        NativeMethods.RtlGetCompressionWorkSpaceSize(formatAndEngine, out var workSpaceSize, out _);

        var workSpace = Marshal.AllocHGlobal((int)workSpaceSize);
        try
        {
            // Output buffer: in worst case, compressed can be slightly larger than input
            var maxOut = (uint)(data.Length + (data.Length / 8) + 256);
            var compressed = new byte[maxOut];

            unsafe
            {
                fixed (byte* pIn = data)
                fixed (byte* pOut = compressed)
                {
                    var status = NativeMethods.RtlCompressBuffer(
                        formatAndEngine,
                        pIn,
                        (uint)data.Length,
                        pOut,
                        maxOut,
                        4096,
                        out var finalSize,
                        workSpace);

                    if (status != 0)
                        throw new InvalidOperationException($"RtlCompressBuffer failed: 0x{status:X8}");

                    var result = new byte[finalSize];
                    Buffer.BlockCopy(compressed, 0, result, 0, (int)finalSize);
                    return result;
                }
            }
        }
        finally
        {
            Marshal.FreeHGlobal(workSpace);
        }
    }
}
}
