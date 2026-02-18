namespace NRE.Core.Common
{
/// <summary>
/// Payload type detected by builder and used by stub for execution path.
/// </summary>
public enum PayloadType : byte
{
    DotNetAssembly = 0,
    NativeExe = 1,
    NativeDll = 2,
    RawShellcode = 3,
}
}
