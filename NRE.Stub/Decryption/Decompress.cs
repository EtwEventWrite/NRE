using System;
using System.Runtime.InteropServices;
using NRE.Core.Common;

namespace NRE.Stub.Decryption
{
    /// <summary>
    /// Decompression using RtlDecompressBuffer (LZNT1/Xpress) for stub runtime.
    /// </summary>
    public static class Decompress
    {
        public static byte[] DecompressBuffer(byte[] compressed, NRE.Core.Common.CompressionFormat format)
        {
            if (compressed == null || compressed.Length == 0)
                return new byte[0];
            if (format == NRE.Core.Common.CompressionFormat.None)
                return compressed;

            if (format == NRE.Core.Common.CompressionFormat.Aplib)
                return NRE.Core.Compression.APLIBWrapper.Decompress(compressed);

            ushort fmt = (ushort)(format == NRE.Core.Common.CompressionFormat.LZNT1
                ? NativeMethods.COMPRESSION_FORMAT_LZNT1
                : NativeMethods.COMPRESSION_FORMAT_XPRESS);

            uint maxOut = (uint)Math.Max(compressed.Length * 4, 64 * 1024);
            byte[] decompressed = null;
            for (int attempt = 0; attempt < 3; attempt++)
            {
                decompressed = new byte[maxOut];
                unsafe
                {
                    fixed (byte* pComp = compressed)
                    fixed (byte* pOut = decompressed)
                    {
                        uint finalSize;
                        int status = NativeMethods.RtlDecompressBuffer(
                            fmt,
                            pOut,
                            maxOut,
                            pComp,
                            (uint)compressed.Length,
                            out finalSize);

                        if (status == 0)
                        {
                            var result = new byte[finalSize];
                            Buffer.BlockCopy(decompressed, 0, result, 0, (int)finalSize);
                            return result;
                        }
                        if (status == unchecked((int)0xC0000023)) // STATUS_BUFFER_TOO_SMALL
                        {
                            maxOut *= 2;
                            continue;
                        }
                        throw new InvalidOperationException("RtlDecompressBuffer failed: 0x" + status.ToString("X8"));
                    }
                }
            }

            throw new InvalidOperationException("RtlDecompressBuffer: buffer too small after retries.");
        }
    }
}
