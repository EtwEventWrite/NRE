using System;
using System.Text;

namespace NRE.Core.Common
{
    /// <summary>
    /// Runtime-decoded strings to avoid static signatures (e.g. "ntdll.dll", "amsi.dll").
    /// </summary>
    public static class RuntimeStrings
    {
        public static string Decode(string b64)
        {
            if (string.IsNullOrEmpty(b64)) return "";
            try
            {
                return Encoding.UTF8.GetString(Convert.FromBase64String(b64));
            }
            catch
            {
                return "";
            }
        }
    }
}
