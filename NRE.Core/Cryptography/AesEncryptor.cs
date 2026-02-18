using System;
using System.Security.Cryptography;

namespace NRE.Core.Cryptography
{
/// <summary>
/// AES-256-CBC encryption using .NET's Aes class (EncryptCbc for .NET 6+).
/// </summary>
public static class AesEncryptor
{
    public static byte[] Encrypt(byte[] plaintext, byte[] key, byte[] iv)
    {
        if (plaintext == null) throw new ArgumentNullException("plaintext");
        if (key == null) throw new ArgumentNullException("key");
        if (iv == null) throw new ArgumentNullException("iv");
        if (key.Length != 32) throw new ArgumentException("Key must be 32 bytes for AES-256.", "key");
        if (iv.Length != 16) throw new ArgumentException("IV must be 16 bytes.", "iv");

        using (var aes = Aes.Create())
        {
            aes.Key = key;
            aes.IV = iv;
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;
            using (var encryptor = aes.CreateEncryptor(key, iv))
            {
                return encryptor.TransformFinalBlock(plaintext, 0, plaintext.Length);
            }
        }
    }
}
}
