# NRE

.NET crypter: builder (encrypts/obfuscates payloads, produces a single stub exe) and stub (loads and runs the payload with optional evasion).

---

## Disclaimer

**This project was fully AI-coded. None of it was written by me.**

For refunds or support, contact **@noircodes** on Telegram.

---

## Repo layout

- **NRE.Builder** — CLI that encrypts a .NET or native payload, optionally obfuscates the stub, outputs one exe
- **NRE.Stub** — Loader stub (Costura single-file); runs the decrypted payload
- **NRE.Core** — Shared code (logging, evasion helpers, etc.)
- **NRE.TestPayload** / **NRE.NativeTestPayload** — Example payloads for testing
- **Tools** — Helper scripts (e.g. payload prep)

## Build

- .NET Framework 4.8. Open the solution in Visual Studio or build from CLI:
  - `dotnet build -c Release`
- Stub: `NRE.Stub` (single exe via Costura). Builder: `NRE.Builder`.

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

## License

MIT. See [LICENSE](LICENSE).
