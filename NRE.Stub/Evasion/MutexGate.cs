using System;
using System.Runtime.InteropServices;

namespace NRE.Stub.Evasion
{
    /// <summary>
    /// Single-instance gate via named mutex. Exit if another instance is already running.
    /// </summary>
    public static class MutexGate
    {
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CloseHandle(IntPtr hObject);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr CreateMutexW(IntPtr lpMutexAttributes, [MarshalAs(UnmanagedType.Bool)] bool bInitialOwner, string lpName);

        private const uint ERROR_ALREADY_EXISTS = 183;

        /// <summary>
        /// Try to acquire the mutex. Returns false if another instance owns it (caller should exit).
        /// On success, we keep the handle until process exit so the mutex stays owned.
        /// </summary>
        public static bool TryAcquire(string mutexName)
        {
            if (string.IsNullOrEmpty(mutexName)) return true;
            IntPtr h = CreateMutexW(IntPtr.Zero, true, mutexName);
            if (h == IntPtr.Zero) return true; // assume ok on failure
            if (Marshal.GetLastWin32Error() == ERROR_ALREADY_EXISTS)
            {
                CloseHandle(h);
                return false;
            }
            // Keep handle; mutex stays owned until process exits
            return true;
        }
    }
}
