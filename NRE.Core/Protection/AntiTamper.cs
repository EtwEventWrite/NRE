using System;
using System.Security.Cryptography;

namespace NRE.Core.Protection
{
/// <summary>
/// Scantime/runtime anti-tamper: verify hash of critical blob at runtime.
/// </summary>
public static class AntiTamper
{
    /// <summary>
    /// Compute SHA256 hash of data (for builder to embed).
    /// </summary>
    public static byte[] ComputeHash(byte[] data)
    {
        if (data == null || data.Length == 0) return new byte[0];
        using (var sha = SHA256.Create())
            return sha.ComputeHash(data);
    }

    /// <summary>
    /// Verify data against expected hash. Returns true if equal.
    /// </summary>
    public static bool Verify(byte[] data, byte[] expectedHash)
    {
        if (data == null || expectedHash == null || expectedHash.Length != 32) return false;
        byte[] computed;
        using (var sha = SHA256.Create())
            computed = sha.ComputeHash(data);
        if (computed.Length != expectedHash.Length) return false;
        int diff = 0;
        for (int i = 0; i < computed.Length; i++)
            diff |= computed[i] ^ expectedHash[i];
        return diff == 0;
    }

    /// <summary>
    /// Constant-time comparison to avoid timing leaks.
    /// </summary>
    public static bool ConstantTimeEquals(byte[] a, byte[] b)
    {
        if (a == null || b == null || a.Length != b.Length) return false;
        int diff = 0;
        for (int i = 0; i < a.Length; i++)
            diff |= a[i] ^ b[i];
        return diff == 0;
    }
}
}
