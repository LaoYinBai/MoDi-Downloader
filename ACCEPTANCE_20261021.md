# Windows Shared MVP Acceptance - 2026-10-21

## Actual End-to-End Evidence

1. The production HTTPS control API responded with protocolVersion 1 and administratorConfigured true. The real Android Keystore public key was registered server-side; no administrator private key or signing secret was transferred.
2. This Windows host generated a protected P-256 device identity and submitted an actual request through the shipped client workflow. The owner reported receiving the Monitor notification and clicking Approve. Subsequent signed queries from new Windows processes returned Approved. Read-only production SQLite inspection showed one Approved row and one signed approval audit entry.
3. The device authenticated as `modi-relay`, using pinned server host keys. A tunneled HTTPS trace returned the Aliyun public address, not the Windows ISP address. A remote shell command was denied.
4. Loopback Stronghold, the SSH host's own public address, cloud metadata, RFC1918, and IPv6 loopback requests were rejected. Dedicated relay UID nftables counters corroborated local/private-destination rejection and public egress. Existing administrator effective SSH settings compared identical before/after installation.
5. The single-file Windows UI auto-connected with the approved device and downloaded `node-v24.21.0-headers.tar.gz` (10,291,794 bytes) into the real Windows Downloads folder. SHA-256 was `57c6bee2e30bbbee5bd51d6cc343eb992e174b56a2a1d0eab7a7510771c20ea2`, matching the official Node.js checksums file obtained through the same tunnel.

## Real Public Download Comparison

Source: `https://nodejs.org/dist/v24.21.0/node-v24.21.0-linux-x64.tar.xz`, 31,890,184 bytes, 31 queued 1 MiB chunks. Concurrency was fixed for comparison; no bandwidth limit was applied. Each row was one sequential run, not a sustained stress test. Times include resource probing and finalization but exclude initial SSH connection setup; they are end-to-end averages rather than peak line rates.

| HTTP connections | Seconds | Average MiB/s | Retries | Final SHA-256 |
| --- | ---: | ---: | ---: | --- |
| 1 | 48.641 | 0.625 | 0 | matches official |
| 4 | 20.980 | 1.450 | 0 | matches official |
| 8 | 13.402 | 2.269 | 0 | matches official |
| 16 | 12.590 | 2.416 | 0 | matches official |

All four digests were `fd8e59d5a511510f6a298afb548f18c7d2b1be404d8b4a27d94fbe49f56cb2d6`. Sixteen connections improved only about 6% over eight. These measurements do not establish a benefit from 32/64 connections or multiple SSH tunnels, so no larger traffic test was run. Automatic policies retain the existing bounded, measurement-based scaling logic.

## Pause, Restart, and Recovery

- A transfer was paused after 1,089,549 received bytes, its manager disposed, and the verification process exited. A new process loaded the persisted manifest and completed only outstanding work. Final size and official SHA-256 matched; no chunk retries were needed after reopening.
- During a separate real transfer, a verification-only fault injector closed its own underlying SSH TCP socket. The real tunnel manager reconnected and the transfer completed after eight chunk-level retries. Final size and digest matched. The injector did not kill any server service or alter the production client's code paths.
- A first attempt at fault injection called SSH.NET's graceful Disconnect concurrently with forwarding cleanup and failed inside the verification helper. It was not treated as an application success; the test was rerun by closing the test socket, which correctly simulates transport loss.
- Tests cover resource identity/Range validation, non-Range fallback, queued range ownership, manifest persistence, immutable local identity, invalid signatures, unavailable authorization, unapproved states, revocation, and missing-tunnel fail-closed behavior. Approved credentials do not inherit the Pending request's expiry.

## Sound and UI

The successful-completion sound is Kenney Interface Sounds `confirmation_003`, CC0, converted to mono PCM16 and reduced by 3 dB. It lasts 0.322018 seconds and adds 28,446 bytes. WinMM playback remains asynchronous with respect to the UI, requires no runtime codec dependency or network access, and cannot fail a download. Per-task deduplication and short completion cooldowns remain in place. Tests cover zero/half/full/clamped volume, immutable source bytes, invalid assets, duplicate events, and disabled sound. Actual UI automation invoked Preview, disabled sound and observed Preview disabled, then restored the setting. Audibility on other machines depends on their audio devices and system settings.

The original bridge/download-arrow icon and light paper theme are applied. The task hierarchy, progress, and expandable details reference PCL2 interaction patterns without copying its code/assets. Actual screenshots were taken at normal and minimum supported sizes. No overlapping URL/directory controls were observed. A stale nonzero speed on completed cards found in the first visual pass was reproduced by six failing tests, fixed in snapshot generation, and verified with additional active-rate coverage.

## Resource Measurements and Portability

- Windows UI, SSH.NET, and download engine share one process; there is no separate ssh.exe process.
- During the real UI transfer: working set 212.9 MiB, private bytes 154.1 MiB; normalized whole-machine CPU averaged 1.99% over a five-second interval.
- Warm idle after UI resize and task completion: working set 211.7 MiB, private bytes 171.9 MiB; normalized CPU 0.022% over five seconds. These are snapshots, not long-duration memory-leak measurements.
- Cloud authorization API cgroup memory was about 15.7 MiB. Short vmstat samples showed 85-97% CPU idle on the server and about 707 MiB available RAM; these are sampled observations, not a claimed full-run peak. Stronghold stayed healthy with the same PID and was not restarted.
- The self-contained single-file executable was actually launched with PATH containing only Windows System32, an invalid DOTNET_ROOT, multilevel lookup disabled, and a HOME with no SSH config. It connected and completed the UI download. Fresh identity persistence is separately covered by Windows DPAPI tests. This is a process-environment simulation, not an independent clean Windows VM or second physical computer; system-wide .NET was not uninstalled.
- A second launch exited successfully and left exactly one application window.

## Verification and Limits

97 .NET tests passed with zero failures/skips after the sound and stale-speed fixes. The backend ran all 68 tests successfully on Ubuntu; local Windows execution passed with one POSIX-only test skipped. Publish/install safety checks are run before packaging. The server stores approval and public keys in SQLite, not the downloaded content.

This is the first unsigned Windows MVP. No claim is made that concurrency can exceed upstream or cloud bandwidth. Long-duration soak testing, independent-device installation, and performance at 32/64 connections remain unmeasured. The per-task concurrency target is currently chosen when adding a task; adaptive tuning adjusts it while running. HTTPS control API errors do not enable direct file downloads.

Revocation immediately blocks new SSH authentication. An honest connected downloader checks every 15 seconds and closes its own channels when revoked. A modified already-connected client would require server-side session termination; removing a key alone does not forcibly disconnect it. No such forced-termination guarantee is claimed.
