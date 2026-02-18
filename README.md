# NRE

.NET crypter: builder (encrypts/obfuscates payloads, produces a single stub exe) and stub (loads and runs the payload with optional evasion).

---

## Disclaimer

**This project was fully AI-coded. None of it was written by me.**

For refuds or support, contact **@noircodes** on Telegram.

---

## Repo layout

- **NRE.Builder** — CLI that encrypts a .NET or native payload, optionally obfuscates the stub, outputs one exe
- **NRE.Stub** — Loader stub (Costura single-file); runs the decrypted payload
- **NRE.Core** — Shared code (logging, evasion helpers, etc.)
- **NRE.TestPayload** / **NRE.NativeTestPayload** — Example payloads for testing
- **NRE.Tests** — Unit tests
- **Tools** — Helper scripts (e.g. payload prep)

## Requirements

- .NET Framework 4.8
- Windows (stub uses Win32 APIs and optional evasion)
- Visual Studio 2022 or `dotnet` CLI

## Build

- Open the solution in Visual Studio or build from CLI: `dotnet build -c Release`
- **Stub:** `NRE.Stub` builds as a single exe (Costura). If `Embedded\EmbeddedData.g.cs` is missing (e.g. fresh clone), the stub still compiles using `EmbeddedData.Default.cs` (empty payload). Run the builder with `-c` to embed a real payload and overwrite `EmbeddedData.g.cs`.
- **Builder:** `NRE.Builder` — use this to crypt a payload into the stub and write the output exe.

## Usage (builder)

```text
NRE.Builder.exe -i <input.exe> -o <output.exe> [-c] [--specific] [--wldp] [--scriptblock-log] ...
```

- `-i` / `-o`: input payload and output stub exe  
- `-c`: crypt (encrypt payload into stub)  
- `--specific`: AV-specific bypass options  
- `--wldp`: WLDP policy  
- `--scriptblock-log`: scriptblock logging bypass  

See builder help for full options.

## Payload types

- **.NET assembly** — in-memory load and entry-point invoke
- **Native EXE/DLL** — manual map and run
- **Raw shellcode** — VirtualAlloc + execute (or thread-pool option)

## Troubleshooting

- **Stub build fails:** Ensure `NRE.Core` is built first. If `EmbeddedData.g.cs` is missing, the project uses the fallback (empty payload) so the stub still builds.
- **Decrypt/load errors at runtime:** Stub shows a MessageBox with the error; check key/IV and payload type match what the builder embedded.

## License

MIT. See [LICENSE](LICENSE).
