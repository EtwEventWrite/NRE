using System;
using System.Runtime.InteropServices;

namespace NRE.Core.Common
{
    [StructLayout(LayoutKind.Sequential)]
    public struct EXCEPTION_POINTERS
    {
        public IntPtr ExceptionRecord;
        public IntPtr ContextRecord;
    }

    /// <summary>
    /// x64 CONTEXT: use with GetThreadContext/SetThreadContext. Layout matches Windows amd64 CONTEXT
    /// for CONTROL + DEBUG_REGISTERS. Size 0x4D0; key offsets: ContextFlags=0, Dr0=0x048, Rip=0xC8 (CONTEXT_AMD64).
    /// </summary>
    public static class ContextOffsets
    {
        public const int Size = 0x4D0;
        public const int OffsetContextFlags = 0;
        public const int OffsetDr0 = 0x048;
        public const int OffsetDr1 = 0x050;
        public const int OffsetDr7 = 0x078;
        public const int OffsetRax = 0x088;
        public const int OffsetRcx = 0x090;
        public const int OffsetRsp = 0x0A8;
        public const int OffsetRip = 0x0C8;
    }
}
