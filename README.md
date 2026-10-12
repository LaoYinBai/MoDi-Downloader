# MoDi Downloader

MoDi Downloader is a Windows x64 desktop download manager. HTTP/HTTPS traffic is sent only through an SSH.NET-managed SOCKS5 forward on loopback; downloaded bytes are written directly to local files. The server is used only as an SSH network forwarder.

## Build and Test

```powershell
dotnet restore .\SshSpeedDownloader.sln
dotnet test .\tests\SshSpeedDownloader.Tests\SshSpeedDownloader.Tests.csproj
dotnet publish .\src\SshSpeedDownloader.Desktop\SshSpeedDownloader.Desktop.csproj -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true -o .\artifacts\publish\win-x64
```

The Release publish is self-contained and single-file. It does not require a machine-installed .NET runtime or OpenSSH. No SSH key, password, passphrase, or fixed credential is embedded in the executable.

Private-only builds are opt-in with `MoDiPrivateBuild=true` and a local `MoDiPrivateIdentityPath` (or `MODI_PRIVATE_IDENTITY_PATH`) supplied at build time. The resulting private executable contains an encrypted, extractable SSH identity resource and is marked `Private`; never publish it, add it to version control, or distribute it. The passphrase remains in Windows Credential Manager and is not bundled. The normal Release configuration does not include the identity resource.

## Safety and Performance

- SSH server, port, username, and private key are configured in the UI. Unknown or changed SSH host fingerprints stop connection until explicitly trusted.
- Private-key passphrases are memory-only by default. The optional remember setting uses Windows Credential Manager; settings and task manifests never contain passphrases or private-key contents.
- The SSH SOCKS5 listener binds to `127.0.0.1`; HTTP has no direct-connect fallback and keeps normal TLS certificate validation.
- Windows startup resolves the user's real Downloads path through `SHGetKnownFolderPath(FOLDERID_Downloads)`. A task can select a separate path; custom default locations are persisted without rewriting existing task manifest paths.
- Successful task completion may play a generated short PCM chime through WinMM and show a Windows tray balloon. Completion IDs are de-duplicated, simultaneous sounds/toasts are rate-limited, and the sound can be disabled or previewed with adjustable volume.
- Range downloads use a lazy queue of 1 MiB chunks, 64 KiB I/O buffers, exact `Content-Range` checks, and local random-access writes. Non-Range sources use one sequential stream.
- Adaptive concurrency starts at 8 by default, is adjustable from 1 to 64, and samples useful throughput, response-header p95 latency, and request error rate every 5 seconds. It increases only after measured improvement and backs off under errors or latency pressure.
- A second independent SSH tunnel is considered only with queued work, at least 16 HTTP connections, low error rate, and repeated throughput plateaus. It is retained only if the two-window comparison improves throughput by at least 15%.
- Resource ceilings: 64 total HTTP connections, 4 active tasks, 2 SSH tunnels, 5 attempts per request/chunk, and 1,000,000 tracked chunks per task. There is no bandwidth throttle. These limits reduce runaway load but cannot guarantee that another server workload is unaffected; validate server responsiveness during real transfers.
- Manifests are atomically saved, with periodic checkpointing and forced saves on pause/completion. Range resume requires matching length plus a stable ETag or Last-Modified validator.

## Structure

- `SshSpeedDownloader.Core`: range planning, adaptive policy, task contracts, URL/name validation, resume identity, and local task manifests.
- `SshSpeedDownloader.Transport`: SSH.NET session lifecycle, loopback SOCKS5, tunneled HTTP, retry/resume, and local file transfer.
- `SshSpeedDownloader.Desktop`: Avalonia UI, Windows credential storage, and user settings.
- `SshSpeedDownloader.Tests`: focused scheduler, transfer, resume, input-safety, SOCKS5, and tunnel-policy tests.

See [AUTH_ARCHITECTURE.md](AUTH_ARCHITECTURE.md) for the private/cloud identity-provider boundary and future approval contract.

## PCL2 UI Reference

The task summary hierarchy and scrollable task-management area were informed by PCL2's public download pages: [PageSpeedLeft.xaml](https://github.com/Meloong-Git/PCL/blob/main/Plain%20Craft%20Launcher%202/Pages/PageSpeedLeft.xaml) and [PageSpeedRight.xaml](https://github.com/Meloong-Git/PCL/blob/main/Plain%20Craft%20Launcher%202/Pages/PageSpeedRight.xaml). The implementation uses independent Avalonia controls and original styling; no PCL2 source, icons, or art assets are copied. PCL2's [license](https://github.com/Meloong-Git/PCL/blob/main/LICENCE) was reviewed for reference.
