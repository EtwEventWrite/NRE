using System;

namespace NRE.Core.Cryptography
{
/// <summary>
/// Helpers for securing sensitive data in memory (e.g. zeroing after use).
/// </summary>
public static class MemoryProtection
{
    public static void Zero(byte[] buffer)
    {
        if (buffer == null) return;
        Array.Clear(buffer, 0, buffer.Length);
    }
}
}
