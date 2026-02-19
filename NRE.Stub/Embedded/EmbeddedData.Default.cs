// Fallback when EmbeddedData.g.cs is missing (e.g. fresh clone before running builder).
// Builder overwrites EmbeddedData.g.cs when you run with -c; this file is not compiled when .g.cs exists.
using NRE.Core.Common;
using NRE.Core.Evasion;

namespace NRE.Stub.Embedded
{
    public static class EmbeddedData
    {
        private static readonly byte[] EmptyPayload = new byte[0];
        private static readonly byte[] DefaultKey = new byte[32];
        private static readonly byte[] DefaultIv = new byte[16];

        public static byte[] Payload => EmptyPayload;
        public static byte[] Key => DefaultKey;
        public static byte[] IV => DefaultIv;
        public static PayloadType PayloadType => PayloadType.DotNetAssembly;
        public static CompressionFormat CompressionFormat => CompressionFormat.None;
        public static EvasionOptions Evasion => EvasionOptions.None;
        public static int DelaySeconds => 0;
        public static string MutexName => "";
    }
}
