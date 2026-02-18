using NRE.Core.Common;
using NRE.Core.Evasion;

namespace NRE.Builder.Configuration
{
/// <summary>
/// Configuration for a single build: input, output, and options.
/// </summary>
public class BuildConfig
{
    public string InputPath { get; set; } = "";
    public string OutputPath { get; set; } = "crypted.exe";
    public bool Compress { get; set; }
    public CompressionFormat CompressionFormat { get; set; } = CompressionFormat.LZNT1;
    public EvasionOptions Evasion { get; set; } = EvasionOptions.PatchAMSI | EvasionOptions.PatchETW;
    public string StubProjectPath { get; set; } = "";
    public bool OutputBat { get; set; }
}
}
