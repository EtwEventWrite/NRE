using System;
using System.Security.Cryptography;

namespace NRE.Core.Cryptography
{
    /// <summary>
    /// Generates cryptographically random AES-256 key and IV.
    /// </summary>
    public static class KeyGenerator
    {
        public const int KeySizeBytes = 32;  // AES-256
        public const int BlockSizeBytes = 16; // AES block = 16 bytes = IV size

        public static byte[] GenerateKey()
        {
            var key = new byte[KeySizeBytes];
            using (var rng = RandomNumberGenerator.Create())
                rng.GetBytes(key);
            return key;
        }

        public static byte[] GenerateIV()
        {
            var iv = new byte[BlockSizeBytes];
            using (var rng = RandomNumberGenerator.Create())
                rng.GetBytes(iv);
            return iv;
        }

        public static Tuple<byte[], byte[]> GenerateKeyAndIV()
        {
            return Tuple.Create(GenerateKey(), GenerateIV());
        }
    }
}
