using System;
using System.Collections.Generic;
using System.IO;

namespace NRE.Core.Compression
{
/// <summary>
/// aPLib (Jorgen Ibsen) compress/decompress - pure managed implementation.
/// Small decompressor footprint; LZ-style with bit stream and gamma-coded lengths.
/// </summary>
public static class APLIBWrapper
{
    public static byte[] Compress(byte[] data)
    {
        if (data == null || data.Length == 0) return Array.Empty<byte>();
        var output = new List<byte>(data.Length / 2);
        var bitWriter = new BitWriter(output);
        int pos = 0;
        while (pos < data.Length)
        {
            int bestLen = 0;
            int bestOff = 0;
            int maxLen = Math.Min(255, data.Length - pos);
            int maxOff = Math.Min(65535, pos);
            for (int off = 1; off <= maxOff && off <= 65535; off++)
            {
                int matchLen = 0;
                while (matchLen < maxLen && data[pos + matchLen] == data[pos - off + (matchLen % off)])
                    matchLen++;
                if (matchLen >= 2 && matchLen > bestLen)
                {
                    bestLen = matchLen;
                    bestOff = off;
                }
            }
            if (bestLen >= 2)
            {
                bitWriter.WriteBit(1);
                bitWriter.WriteGamma(bestOff);
                bitWriter.WriteGamma(bestLen);
                pos += bestLen;
            }
            else
            {
                bitWriter.WriteBit(0);
                bitWriter.WriteByte(data[pos++]);
            }
        }
        bitWriter.WriteBit(1);
        bitWriter.WriteGamma(0);
        bitWriter.Flush();
        return output.ToArray();
    }

    public static byte[] Decompress(byte[] data)
    {
        if (data == null || data.Length == 0) return Array.Empty<byte>();
        var output = new List<byte>(data.Length * 2);
        var br = new BitReader(data);
        try
        {
            while (true)
            {
                if (br.ReadBit() != 0)
                {
                    int off = br.ReadGamma();
                    if (off == 0) break;
                    int len = br.ReadGamma();
                    int start = output.Count - off;
                    for (int i = 0; i < len; i++)
                        output.Add(output[start + (i % off)]);
                }
                else
                {
                    output.Add(br.ReadByte());
                }
            }
        }
        catch (EndOfStreamException) { }
        return output.ToArray();
    }

    private sealed class BitReader
    {
        private readonly byte[] _data;
        private int _bytePos;
        private int _bitPos = 8;

        public BitReader(byte[] data) => _data = data;

        public int ReadBit()
        {
            if (_bitPos > 7) { _bitPos = 0; _bytePos++; }
            if (_bytePos >= _data.Length) throw new EndOfStreamException();
            int b = (_data[_bytePos] >> _bitPos) & 1;
            _bitPos++;
            return b;
        }

        public byte ReadByte()
        {
            byte v = 0;
            for (int i = 0; i < 8; i++)
                v |= (byte)(ReadBit() << i);
            return v;
        }

        public int ReadGamma()
        {
            int len = 0;
            while (ReadBit() != 0) len++;
            int v = 0;
            for (int i = 0; i < len; i++)
                v = (v << 1) | ReadBit();
            return (1 << len) + v;
        }
    }

    private sealed class BitWriter
    {
        private readonly List<byte> _out;
        private byte _cur;
        private int _bits;

        public BitWriter(List<byte> output) => _out = output;

        public void WriteBit(int b)
        {
            _cur |= (byte)((b & 1) << _bits);
            _bits++;
            if (_bits == 8) { _out.Add(_cur); _cur = 0; _bits = 0; }
        }

        public void WriteByte(byte b)
        {
            for (int i = 0; i < 8; i++)
                WriteBit((b >> i) & 1);
        }

        public void WriteGamma(int value)
        {
            value++;
            int len = 0;
            int v = value;
            while (v > 0) { len++; v >>= 1; }
            for (int i = 0; i < len - 1; i++) WriteBit(1);
            WriteBit(0);
            for (int i = len - 1; i >= 0; i--)
                WriteBit((value >> i) & 1);
        }

        public void Flush()
        {
            if (_bits > 0) _out.Add(_cur);
        }
    }
}
}
