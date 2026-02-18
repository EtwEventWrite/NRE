using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace NRE.Stub.Execution
{
    /// <summary>
    /// Indirect API calls: resolve and invoke Win32 APIs via dynamic GetProcAddress/GetModuleHandle at runtime.
    /// </summary>
    public static class IndirectCall
    {
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
        private static extern IntPtr GetModuleHandleW(string lpModuleName);

        [DllImport("kernel32.dll", CharSet = CharSet.Ansi)]
        private static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);

        private static readonly Dictionary<Tuple<string, string>, IntPtr> _cache = new Dictionary<Tuple<string, string>, IntPtr>();

        public static IntPtr GetProc(string moduleName, string procName)
        {
            var key = Tuple.Create(moduleName, procName);
            lock (_cache)
            {
                IntPtr ptr;
                if (_cache.TryGetValue(key, out ptr))
                    return ptr;
            }
            IntPtr hMod = GetModuleHandleW(moduleName);
            if (hMod == IntPtr.Zero) return IntPtr.Zero;
            IntPtr addr = GetProcAddress(hMod, procName);
            lock (_cache)
            {
                _cache[key] = addr;
            }
            return addr;
        }

        public static void InvokeVoid(string moduleName, string procName)
        {
            IntPtr ptr = GetProc(moduleName, procName);
            if (ptr == IntPtr.Zero) return;
            var fn = (VoidDelegate)Marshal.GetDelegateForFunctionPointer(ptr, typeof(VoidDelegate));
            fn();
        }

        public static IntPtr InvokeVirtualAlloc(string moduleName, string procName, IntPtr addr, UIntPtr size, uint allocType, uint protect)
        {
            IntPtr ptr = GetProc(moduleName, procName);
            if (ptr == IntPtr.Zero) return IntPtr.Zero;
            var fn = (VirtualAllocDelegate)Marshal.GetDelegateForFunctionPointer(ptr, typeof(VirtualAllocDelegate));
            return fn(addr, size, allocType, protect);
        }

        private delegate void VoidDelegate();
        private delegate IntPtr VirtualAllocDelegate(IntPtr lpAddress, UIntPtr dwSize, uint flAllocationType, uint flProtect);

        public static T Invoke<T>(IntPtr functionPtr, Type delegateType, params object[] args) where T : class
        {
            if (functionPtr == IntPtr.Zero) return null;
            var del = Marshal.GetDelegateForFunctionPointer(functionPtr, delegateType);
            return del.DynamicInvoke(args) as T;
        }
    }
}
