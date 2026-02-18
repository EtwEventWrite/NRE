using System;
using System.Runtime.InteropServices;

namespace NRE.Core.Common
{
    /// <summary>
    /// P/Invoke declarations for ntdll and kernel32 used by compression, evasion, unhooking, and AMSI HBP.
    /// </summary>
    public static unsafe class NativeMethods
    {
        public const int COMPRESSION_FORMAT_LZNT1 = 2;
        public const int COMPRESSION_FORMAT_XPRESS = 3;
        public const int COMPRESSION_ENGINE_STANDARD = 0;
        public const int COMPRESSION_ENGINE_MAXIMUM = 0x100;

        [DllImport("ntdll.dll")]
        public static extern int RtlCompressBuffer(
            ushort CompressionFormatAndEngine,
            byte* UncompressedBuffer,
            uint UncompressedBufferSize,
            byte* CompressedBuffer,
            uint CompressedBufferSize,
            uint ChunkSize,
            out uint FinalCompressedSize,
            IntPtr WorkSpace);

        [DllImport("ntdll.dll")]
        public static extern int RtlDecompressBuffer(
            ushort CompressionFormat,
            byte* UncompressedBuffer,
            uint UncompressedBufferSize,
            byte* CompressedBuffer,
            uint CompressedBufferSize,
            out uint FinalUncompressedSize);

        [DllImport("ntdll.dll")]
        public static extern int RtlGetCompressionWorkSpaceSize(
            ushort CompressionFormatAndEngine,
            out uint CompressBufferWorkSpaceSize,
            out uint CompressFragmentWorkSpaceSize);

        public static ushort MakeCompressionFormat(ushort format, ushort engine = COMPRESSION_ENGINE_STANDARD)
        {
            return (ushort)((engine << 8) | format);
        }

        public const uint PAGE_NOACCESS = 0x01;
        public const uint PAGE_READONLY = 0x02;
        public const uint PAGE_READWRITE = 0x04;
        public const uint PAGE_EXECUTE_READ = 0x20;
        public const uint PAGE_EXECUTE_READWRITE = 0x40;

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern uint GetModuleFileNameW(IntPtr hModule, IntPtr lpFilename, uint nSize);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
        public static extern IntPtr GetModuleHandleW(string lpModuleName);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr AddVectoredExceptionHandler(uint First, IntPtr Handler);

        [DllImport("kernel32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool RemoveVectoredExceptionHandler(IntPtr Handler);

        [DllImport("kernel32.dll")]
        public static extern IntPtr GetCurrentProcess();

        [DllImport("kernel32.dll")]
        public static extern IntPtr GetCurrentThread();

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool GetThreadContext(IntPtr hThread, IntPtr lpContext);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool SetThreadContext(IntPtr hThread, IntPtr lpContext);

        public const uint CONTEXT_CONTROL = 0x00100001;
        public const uint CONTEXT_DEBUG_REGISTERS = 0x00100010;
        public const uint CONTEXT_FULL = 0x00100007;
        public const uint EXCEPTION_CONTINUE_EXECUTION = unchecked((uint)(-1));
        public const uint EXCEPTION_CONTINUE_SEARCH = 0;
        public const uint STATUS_SINGLE_STEP = 0x80000004;

        [DllImport("kernel32.dll")]
        public static extern uint GetCurrentThreadId();

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenThread(uint dwDesiredAccess, [MarshalAs(UnmanagedType.Bool)] bool bInheritHandle, uint dwThreadId);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern uint SuspendThread(IntPtr hThread);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern uint ResumeThread(IntPtr hThread);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CloseHandle(IntPtr hObject);

        public const uint THREAD_SUSPEND_RESUME = 0x0002;
        public const uint THREAD_GET_CONTEXT = 0x0008;
        public const uint THREAD_SET_CONTEXT = 0x0010;
    }
}
