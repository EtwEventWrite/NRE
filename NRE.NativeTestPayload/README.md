# NRE Native Test Payload

Minimal native (C) exe that shows a MessageBox. Use it to test the stub with **NativeExe** payload type (non-.NET).

## Build

**Option A – Visual Studio (recommended)**  
Open "x64 Native Tools Command Prompt for VS 2022" (or run `vcvars64.bat`), then:

```bat
cd NRE.NativeTestPayload
build.bat
```

Output: `bin\Release\NRE.NativeTestPayload.exe`

**Option B – Manual**  
```bat
cl /nologo /O2 main.c /Fe:NRE.NativeTestPayload.exe user32.lib
```

## Crypt with NRE.Builder

```bat
NRE.Builder -i "C:\Users\miles\Downloads\NRE\NRE.NativeTestPayload\bin\Release\NRE.NativeTestPayload.exe" -o out_native.exe -c --specific --wldp --scriptblock-log
```

Run `out_native.exe`; you should see "Success! Native payload ran in memory."
