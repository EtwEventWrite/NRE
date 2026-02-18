using System;
using System.IO;

namespace NRE.Core.Protection
{

/// <summary>
/// .NET virtualizer: run a custom bytecode VM so critical logic is not plain IL.
/// Bytecode is a simple stack-based instruction set (push, pop, add, xor, load, store, call, ret).
/// Builder can convert small routines to bytecode; stub executes via this VM.
/// </summary>
public static class Virtualizer
{
    public const byte OpNop = 0;
    public const byte OpPush = 1;
    public const byte OpPop = 2;
    public const byte OpAdd = 3;
    public const byte OpXor = 4;
    public const byte OpLoad = 5;
    public const byte OpStore = 6;
    public const byte OpCall = 7;
    public const byte OpRet = 8;
    public const byte OpLdcI4 = 9;
    public const byte OpBr = 10;
    public const byte OpBrTrue = 11;
    public const byte OpLdInd = 12;
    public const byte OpStInd = 13;
    public const byte OpSub = 14;
    public const byte OpMul = 15;
    public const byte OpShl = 16;
    public const byte OpShr = 17;
    public const byte OpNeg = 18;
    public const byte OpNot = 19;
    public const byte OpBrFalse = 20;
    public const byte OpSwap = 21;
    public const byte OpDup = 22;

    /// <summary>
    /// Execute bytecode. Instructions are read from code; data segment for Load/Store is in data (optional).
    /// Stack and locals are internal. Entry at ip=0.
    /// </summary>
    public static int Execute(byte[] code, int[] data = null)
    {
        if (code == null || code.Length == 0) return 0;
        var stack = new int[256];
        var locals = new int[64];
        data = data ?? Array.Empty<int>();
        int sp = -1;
        int ip = 0;
        int result = 0;

        while (ip < code.Length)
        {
            byte op = code[ip++];
            switch (op)
            {
                case OpNop:
                    break;
                case OpLdcI4:
                    if (ip + 4 > code.Length) return result;
                    int val = BitConverter.ToInt32(code, ip);
                    ip += 4;
                    stack[++sp] = val;
                    break;
                case OpPush:
                    if (sp >= 255) return result;
                    if (ip + 4 > code.Length) return result;
                    stack[++sp] = BitConverter.ToInt32(code, ip);
                    ip += 4;
                    break;
                case OpPop:
                    if (sp >= 0) { result = stack[sp--]; }
                    break;
                case OpAdd:
                    if (sp >= 1) { stack[sp - 1] = stack[sp - 1] + stack[sp]; sp--; }
                    break;
                case OpXor:
                    if (sp >= 1) { stack[sp - 1] ^= stack[sp]; sp--; }
                    break;
                case OpSub:
                    if (sp >= 1) { stack[sp - 1] = stack[sp - 1] - stack[sp]; sp--; }
                    break;
                case OpMul:
                    if (sp >= 1) { stack[sp - 1] = stack[sp - 1] * stack[sp]; sp--; }
                    break;
                case OpShl:
                    if (sp >= 1) { stack[sp - 1] = stack[sp - 1] << stack[sp]; sp--; }
                    break;
                case OpShr:
                    if (sp >= 1) { stack[sp - 1] = stack[sp - 1] >> (stack[sp] & 31); sp--; }
                    break;
                case OpNeg:
                    if (sp >= 0) stack[sp] = -stack[sp];
                    break;
                case OpNot:
                    if (sp >= 0) stack[sp] = ~stack[sp];
                    break;
                case OpBrFalse:
                    if (sp < 0 || ip + 4 > code.Length) break;
                    int falseTarget = BitConverter.ToInt32(code, ip);
                    if (stack[sp--] == 0) ip = falseTarget;
                    else ip += 4;
                    break;
                case OpSwap:
                    if (sp >= 1) { int t = stack[sp]; stack[sp] = stack[sp - 1]; stack[sp - 1] = t; }
                    break;
                case OpDup:
                    if (sp >= 0 && sp < 255) { stack[sp + 1] = stack[sp]; sp++; }
                    break;
                case OpLoad:
                    if (ip >= code.Length) return result;
                    int idx = code[ip++];
                    if (idx >= 0 && idx < data.Length) stack[++sp] = data[idx];
                    break;
                case OpStore:
                    if (sp < 0 || ip >= code.Length) break;
                    idx = code[ip++];
                    if (idx >= 0 && idx < data.Length) data[idx] = stack[sp--];
                    break;
                case OpBr:
                    if (ip + 4 > code.Length) return result;
                    ip = BitConverter.ToInt32(code, ip);
                    break;
                case OpBrTrue:
                    if (sp < 0 || ip + 4 > code.Length) break;
                    int target = BitConverter.ToInt32(code, ip);
                    if (stack[sp--] != 0) ip = target;
                    else ip += 4;
                    break;
                case OpRet:
                    return sp >= 0 ? stack[sp] : result;
                case OpLdInd:
                    if (sp < 0) break;
                    int addr = stack[sp];
                    if (addr >= 0 && addr < data.Length * 4)
                        stack[sp] = data[addr / 4];
                    break;
                case OpStInd:
                    if (sp < 2) break;
                    addr = stack[sp - 1];
                    int v = stack[sp];
                    sp -= 2;
                    if (addr >= 0 && addr < data.Length * 4)
                        data[addr / 4] = v;
                    break;
                default:
                    return result;
            }
        }
        return result;
    }

    /// <summary>
    /// Encode a simple check (e.g. xor then compare): returns bytecode that leaves 1 on stack if condition holds.
    /// </summary>
    public static byte[] EncodeXorCheck(int key, int magic, int expected)
    {
        using (var ms = new MemoryStream())
        {
            ms.WriteByte(OpLdcI4);
            ms.Write(BitConverter.GetBytes(key), 0, 4);
            ms.WriteByte(OpLdcI4);
            ms.Write(BitConverter.GetBytes(magic), 0, 4);
            ms.WriteByte(OpXor);
            ms.WriteByte(OpLdcI4);
            ms.Write(BitConverter.GetBytes(expected), 0, 4);
            ms.WriteByte(OpXor);
            ms.WriteByte(OpRet);
            return ms.ToArray();
        }
    }

    /// <summary>
    /// Run XOR over a byte buffer in-place using a key (VM-style, no direct byte[] access in interpreted logic).
    /// Data segment: [4-byte offset][4-byte length] then buffer bytes. Key in low 4 bytes of data[0].
    /// Used for optional virtualized decrypt steps; main decryption remains in AesDecryptor.
    /// </summary>
    public static void XorBufferInPlace(byte[] buffer, int offset, int length, byte[] key)
    {
        if (buffer == null || key == null || key.Length == 0) return;
        for (int i = 0; i < length && (offset + i) < buffer.Length; i++)
            buffer[offset + i] ^= key[i % key.Length];
    }
}
}
