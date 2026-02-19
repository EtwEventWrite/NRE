# NRE

**N**et **R**untime **E**ncryptor — a .NET crypter that packs your payload into a single executable. The **builder** encrypts and embeds a payload; the **stub** loads and runs it at runtime with optional evasion.

---

## Disclaimer

This project was **fully AI-generated**. None of the code was written by the repo owner.

**Refunds or support:** contact **@noircodes** on Telegram.

---

## Overview

| Project | Description |
|--------|-------------|
| **NRE.Builder** | CLI: encrypts a payload, optionally obfuscates the stub, outputs one exe |
| **NRE.BuilderGui** | ImGui GUI for the builder (optional) |
| **NRE.Stub** | Single-file loader (Costura); decrypts and runs the payload |
| **NRE.Core** | Shared code (logging, evasion helpers) |
| **NRE.TestPayload** | Example .NET payload for testing |
| **NRE.Tests** | Unit tests |

---

## Requirements

- **.NET Framework 4.8**
- **Windows** (stub uses Win32 and optional evasion)
- **Visual Studio 2022** or **dotnet** CLI

---

## Build

```bash
dotnet build NRE.sln -c Release
```

- **Stub:** Builds as a single exe. If `NRE.Stub/Embedded/EmbeddedData.g.cs` is missing (e.g. fresh clone), the project uses `EmbeddedData.Default.cs` (empty payload). Run the builder with `-c` to embed a real payload and regenerate that file.
- **Builder:** Use `NRE.Builder` to crypt a payload into the stub and produce the output exe.
- **GUI:** Run `NRE.BuilderGui\bin\Release\net48\NRE.BuilderGui.exe` (64-bit; run from repo root so the stub path resolves when you click Build).

---

## Usage

### CLI (NRE.Builder)

```text
NRE.Builder.exe -i <input.exe> -o <output.exe> [-c] [options...]
```

| Option | Description |
|--------|-------------|
| `-i`, `-o` | Input payload and output exe path |
| `-c` | Crypt: encrypt payload and embed into stub |
| `--compress-format lznt1\|xpress\|aplib` | Compression (when using `-c`) |
| `--delay <sec>` | Sleep N seconds before execution |
| `--mutex <name>` | Single-instance mutex; exit if already running |
| `--earlybird` | Shellcode via Early Bird APC injection |
| `--module-stomping` | Shellcode via module stomping |
| `--specific` | AV-specific bypass options |
| `--wldp` | WLDP policy |
| `--scriptblock-log` | Scriptblock logging bypass |

Run with `--help` for the full list.

### Payload types

- **.NET assembly** — in-memory load and entry-point invoke  
- **Native EXE/DLL** — manual map and run  
- **Raw shellcode** — VirtualAlloc + execute (or thread-pool)

---

## Troubleshooting

| Issue | Fix |
|-------|-----|
| Stub build fails | Build `NRE.Core` first. If `EmbeddedData.g.cs` is missing, the stub still builds with the empty fallback. |
| Decrypt/load errors at runtime | Stub shows a MessageBox; verify key/IV and payload type match what the builder embedded. |
| GUI won’t start | Ensure 64-bit build and run from the repo root. |

---

## License

MIT. See [LICENSE](LICENSE).
