namespace NRE.Core.Common
{
/// <summary>
/// Compression format used for payload; must match between builder and stub.
/// </summary>
public enum CompressionFormat : byte
{
    None = 0,
    LZNT1 = 1,
    Xpress = 2,
    Aplib = 3,
}
}
