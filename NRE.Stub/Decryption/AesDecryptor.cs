using System;
using System.Security.Cryptography;

namespace NRE.Stub.Decryption
{
    /// <summary>
    /// AES-256-CBC decryption for embedded payload.
    /// </summary>
    public static class AesDecryptor
    {
        public static byte[] Decrypt(byte[] ciphertext, byte[] key, byte[] iv)
        {
            if (ciphertext == null || ciphertext.Length == 0)
                throw new ArgumentNullException("ciphertext");
            if (key == null || key.Length != 32)
                throw new ArgumentException("Key must be 32 bytes.", "key");
            if (iv == null || iv.Length != 16)
                throw new ArgumentException("IV must be 16 bytes.", "iv");

            using (var aes = Aes.Create())
            {
                aes.Key = key;
                aes.IV = iv;
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;
                using (var decryptor = aes.CreateDecryptor(key, iv))
                {
                    return decryptor.TransformFinalBlock(ciphertext, 0, ciphertext.Length);
                }
            }
        }
    }
}
