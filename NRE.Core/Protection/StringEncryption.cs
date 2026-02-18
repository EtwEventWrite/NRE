using System;
using System.Security.Cryptography;
using System.Text;

namespace NRE.Core.Protection
{
/// <summary>
/// Scantime protection: encrypt strings at build/embed time, decrypt at runtime to avoid static signatures.
/// </summary>
public static class StringEncryption
{
    private static readonly byte[] DefaultKey = Encoding.UTF8.GetBytes("NRE_StrEnc_Key_32bytes!!");

    public static string Encrypt(string plain, byte[] key = null)
    {
        if (string.IsNullOrEmpty(plain)) return "";
        key = key ?? DefaultKey;
        if (key.Length != 32) throw new ArgumentException("Key must be 32 bytes.", "key");
        var iv = new byte[16];
        using (var rng = RandomNumberGenerator.Create())
            rng.GetBytes(iv);
        var bytes = Encoding.UTF8.GetBytes(plain);
        using (var aes = Aes.Create())
        {
            aes.Key = key;
            aes.IV = iv;
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;
            using (var encryptor = aes.CreateEncryptor(key, iv))
            {
                var encrypted = encryptor.TransformFinalBlock(bytes, 0, bytes.Length);
                var combined = new byte[iv.Length + encrypted.Length];
                Buffer.BlockCopy(iv, 0, combined, 0, iv.Length);
                Buffer.BlockCopy(encrypted, 0, combined, iv.Length, encrypted.Length);
                return Convert.ToBase64String(combined);
            }
        }
    }

    public static string Decrypt(string cipherBase64, byte[] key = null)
    {
        if (string.IsNullOrEmpty(cipherBase64)) return "";
        key = key ?? DefaultKey;
        if (key.Length != 32) return "";
        try
        {
            var combined = Convert.FromBase64String(cipherBase64);
            if (combined.Length < 17) return "";
            var iv = new byte[16];
            var encrypted = new byte[combined.Length - 16];
            Buffer.BlockCopy(combined, 0, iv, 0, 16);
            Buffer.BlockCopy(combined, 16, encrypted, 0, encrypted.Length);
            using (var aes = Aes.Create())
            {
                aes.Key = key;
                aes.IV = iv;
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;
                using (var decryptor = aes.CreateDecryptor(key, iv))
                {
                    var decrypted = decryptor.TransformFinalBlock(encrypted, 0, encrypted.Length);
                    return Encoding.UTF8.GetString(decrypted);
                }
            }
        }
        catch
        {
            return "";
        }
    }

    public static string XorDecrypt(string base64, byte[] key)
    {
        if (string.IsNullOrEmpty(base64) || key == null || key.Length == 0) return "";
        try
        {
            var data = Convert.FromBase64String(base64);
            for (int i = 0; i < data.Length; i++)
                data[i] ^= key[i % key.Length];
            return Encoding.UTF8.GetString(data);
        }
        catch { return ""; }
    }

    public static string XorEncrypt(string plain, byte[] key)
    {
        if (key == null || key.Length == 0) return "";
        var data = Encoding.UTF8.GetBytes(plain ?? "");
        for (int i = 0; i < data.Length; i++)
            data[i] ^= key[i % key.Length];
        return Convert.ToBase64String(data);
    }
}
}
