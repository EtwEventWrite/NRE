using System;
using NRE.Core.Common;
using NRE.Core.Compression;
using NRE.Core.Cryptography;
using NRE.Builder.Configuration;

namespace NRE.Builder.Commands
{
    /// <summary>
    /// Encrypts (and optionally compresses) payload for embedding in stub.
    /// </summary>
    public static class EncryptCommands
    {
        /// <summary>
        /// Returns (encryptedPayload, key, iv). If config.Compress is true, compresses first then encrypts.
        /// </summary>
        public static Tuple<byte[], byte[], byte[]> EncryptPayload(byte[] rawPayload, BuildConfig config)
        {
            byte[] toEncrypt = rawPayload;
            if (config.Compress)
            {
                switch (config.CompressionFormat)
                {
                    case CompressionFormat.LZNT1:
                        toEncrypt = NativeCompress.CompressLZNT1(rawPayload);
                        break;
                    case CompressionFormat.Xpress:
                        toEncrypt = NativeCompress.CompressXpress(rawPayload);
                        break;
                    case CompressionFormat.Aplib:
                        toEncrypt = APLIBWrapper.Compress(rawPayload);
                        break;
                    default:
                        break;
                }
            }

            var keyAndIv = KeyGenerator.GenerateKeyAndIV();
            byte[] key = keyAndIv.Item1;
            byte[] iv = keyAndIv.Item2;
            byte[] encrypted = AesEncryptor.Encrypt(toEncrypt, key, iv);
            return Tuple.Create(encrypted, key, iv);
        }
    }
}
