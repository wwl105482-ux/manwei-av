# ManweiAV (满唯杀毒)

A small, offline Windows risk scanner and startup auditor. Single executable, no installer required, no network access, no background service.

## What it does

- **File scan**: signature hashes, byte strings, filename/path rules, PE heuristics (packer, entropy, double extension), plus JSON-driven behavior rules for scripts (download-and-execute, shadow-copy deletion, defense evasion, persistence, credential theft, AMSI bypass).
- **Script decoding**: `-EncodedCommand` / `-enc` / base64 literals are decoded (one layer, max 2 MB) before behavior matching.
- **Office macro content**: reads `vbaProject.bin` and grades dangerous calls (Shell / CreateObject / URLDownloadToFile / AutoOpen...), instead of just flagging "has macro".
- **Startup audit**: Run/RunOnce/Winlogon/AppInit/IFEO/Startup folders, services, scheduled tasks, hosts file and browser extensions; shows signer and severity, and can delete an entry after a confirmation.
- **Defender second opinion** (optional): asks the local Windows Defender to re-check at most 20 suspicious files asynchronously; report only, never deletes.
- **Big-file cleanup**: lists large files and flags obvious junk.

## Build

Windows 10/11 with .NET Framework 4.x (the in-box `csc.exe`):

```powershell
powershell -ExecutionPolicy Bypass -File build.ps1
powershell -ExecutionPolicy Bypass -File build-installer.ps1
powershell -ExecutionPolicy Bypass -File release.ps1
```

Output goes to `dist\`. Run the self-test:

```powershell
.\dist\满唯杀毒.exe --selftest
```

## Design constraints

- C# 5 only (compiled with the legacy `csc.exe`), no NuGet packages, no external runtime.
- Everything is local: no uploads, no telemetry, no auto-update.
- Destructive actions require explicit confirmation; deleted files do not go to the Recycle Bin.

## License

MIT — see `LICENSE`.

## Security

See `SECURITY.md`. This is not an antivirus replacement; see the limitations section in the Chinese `README.md`.

## Code signing

We are applying for free open-source code signing via the [SignPath Foundation](https://signpath.org/foundation). See `docs/SIGNING.md` and `.github/workflows/signpath.yml`.
