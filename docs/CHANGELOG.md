# Changelog

All notable changes to the ID-Spoofer project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Persistent NFQUEUE rewriter** — `apply --netident` now spawns a detached helper process (`idspoof __rewriter`, its own session, PID tracked in `rewriter.pid` in the state dir) that outlives the CLI. Re-applying with the same persona reuses the running daemon; a different persona replaces it. `restore --netident` stops it.
- `idspoof status` (and the TUI Status tab) now report real rewriter liveness (pid file + process check) and flag the **STALE** state: iptables rule present but no live rewriter — the condition where queued SYNs get dropped and new TCP connections time out.
- **`idspoof serve`** — new foreground "managed" mode: applies the selected operations (all three by default, like `apply`; individual flags to narrow, e.g. `--netident` for persona + rewriter only), runs the NFQUEUE rewriter in-process, and restores everything on SIGTERM/SIGINT. `--owner <user>` scopes the mangle chain to specific users' traffic — one `iptables -m owner` jump per user, repeatable or comma-separated (`--owner obscura,searxng`), removed on restore. Meant to run under systemd: a crash or SIGKILL is safe (the supervisor restarts it and re-apply is idempotent), and a clean stop leaves the machine in its original state.

### Fixed

- **Network outage after `apply`** — the rewriter's NFQUEUE netlink messages didn't match the running kernel's UAPI, so the kernel rejected every verdict with `EINVAL (errno 22)` and the queue-lifetime timer then dropped every queued SYN:
  - `NFQA_VERDICT_HDR` was emitted as attribute type 1; this kernel's `nfqnl_attr_type` makes it type **2**, so the kernel's `nla_find_attr()` found no verdict header and bailed with `EINVAL`
  - `nfqnl_msg_verdict_hdr` is `{verdict, id}` (verdict first, 8 bytes), not the legacy `{id, verdict, data}` the code encoded
  - `nfqnl_msg_config_cmd` is `{command, _pad, pf}` with no queue field (the queue comes from `nfgenmsg.res_id`); the address family was being written into `res_id` instead
  - `nfqnl_msg_config_params` is a packed 5-byte `{copy_range, copy_mode}`, not 8
  - the socket bound without joining the queue multicast group `1<<NFNL_SUBSYS_QUEUE`
- `idspoof status` reported "NFQUEUE rewriter: Active" from the presence of the iptables rule alone, and dumped the legacy `IDSPOOF_WINEMU` chain instead of `IDSPOOF_NETEMU`
- **`restore --netident` left the system fingerprinted** — every `apply` re-captured the *current* live sysctls and overwrote the saved `ORIG_*` originals. Re-applying without a restore in between therefore recorded the persona's own values (TTL=128, timestamps=0, …) as the "originals", so a later `restore` "restored" to those values and the host stayed fingerprinted. The baseline is now captured on the first apply only and cleared on a successful `restore`, so each cycle re-captures a clean original. Also, `net.ipv4.tcp_rfc1337` was written on apply/restore but never saved, so `restore` forced it to 0 even when the host default was 1.
- The `[spoofed]` MAC markers in `status` now key off the values recorded as spoofed (`SPOOFED_MACS`) instead of comparing against the `ORIG_MACS` baseline, so a docker bridge that rotated its own MAC can no longer masquerade as active spoofing; the marker is cleared on restore. The MAC baseline is also captured on the first apply only (the same first-apply-only rule the netident sysctl baselines got), so re-applying can no longer re-baseline rotated live values.
- **Crashed `serve --owner` left stale scoped jumps** — a plain apply or re-scope would install its jumps next to the owner-scoped jumps a crashed session left in POSTROUTING, double-diverting the old owner's traffic through the chain; apply and re-scoping now sweep every owner-scoped jump first, so a global apply leaves exactly one global jump and a scoped one leaves exactly its users' jumps. `serve` apply failures now report which operation(s) failed instead of a bare "apply failed".

---

## [2.0.5] - 2026-02-28

### Added

- Go module badge on README for `pkg.go.dev` registration
- `CHANGELOG.md` linked from goreleaser release notes

### Fixed

- **TUI interface flickering** on Dashboard and Traffic tabs — spinner tick messages were broadcast to all tabs at ~10Hz causing rapid re-renders; now routed only to the active tab
- Interface display order sorted alphabetically for stable rendering across refreshes

### Changed

- Go module path updated to `github.com/NubleX/ID-Spoofer/idspoof` for proper `pkg.go.dev` registration
- CI Go version bumped from 1.22 to 1.24 to match `go.mod`
- Installation URLs in README fixed to match actual repo name (`ID-Spoofer`)
- Phase 7 (GitHub Actions CI + goreleaser) marked complete in roadmap

### Infrastructure

- Dual tag scheme: `v2.0.5` (goreleaser) + `idspoof/v2.0.5` (Go module subdirectory convention)
- goreleaser builds Linux (amd64/arm64), macOS (amd64/arm64), and Windows (amd64) binaries

---

## [2.0.4] - 2026-02-27

### Added

- **Android network persona** — Projects an Android 12+ phone/tablet identity at the wire level
  - TTL=64, ECN=0, WScale=8, mobile-tuned buffers (87380/6291456), Linux kernel TCP options order
  - DHCP hostnames in Android style: `android-a3f9kl2d7b8e1c4f`, `samsung-...`, `pixel-...`, `oneplus-...`, `xiaomi-...`
  - p0f signature: `*:64:0:*:65535,8:mss,sackOK,ts,nop,ws:df,id+:0`
  - `--persona android` CLI flag; radio button in TUI Identity tab
- **macOS native platform support** (Phase 5)
  - MAC spoofing via `ifconfig <iface> ether <mac>` — no macchanger required
  - TTL control via `sysctl -w net.inet.ip.ttl=<val>`
  - DHCP hostname via `networksetup -setcomputername` + `scutil --set LocalHostName`
  - Platform wiring: `mac_darwin.go`, `netident_darwin.go`, `platform_darwin.go`
- **Windows native platform support** (Phase 6)
  - MAC spoofing via registry `NetworkAddress` key under adapter class GUID + adapter bounce
  - TTL and TCP options via `Tcpip\Parameters` registry (`DefaultTTL`, `Tcp1323Opts` bitmask)
  - Platform wiring: `mac_windows.go`, `netident_windows.go`, `platform_windows.go`
- **Traffic tab** — Live network traffic monitoring in the TUI (inspired by [pythops/oryx](https://github.com/pythops/oryx))
  - Per-interface bandwidth: RX/s, TX/s, total RX, total TX with human-readable sizes
  - Connection summary by TCP state (ESTABLISHED, TIME_WAIT, CLOSE_WAIT, etc.)
  - Active connections table (protocol, local, remote, state) with 2-second auto-refresh
  - Pure Go implementation: `/proc/net/dev` + `/proc/net/tcp` on Linux, `netstat -ib` on macOS, `netsh` on Windows
  - Tab navigation: Tab 4 (Traffic), Tab 5 (Status)

### Changed

- TUI tabs: Dashboard | Identity | Tunnel | **Traffic** | Status (5 tabs, up from 4)
- `platform_other.go` build tag narrowed to `!darwin && !windows` — real implementations for macOS and Windows
- `DetectPlatform()` now calls native factory functions on Darwin and Windows instead of returning errors

---

## [2.0.2] - 2026-02-27

### Added

- **Multi-OS network personas** — Windows 10/11, macOS (Sonoma+), Linux (Ubuntu/Arch/Fedora), iOS 17+
  - `--persona windows|macos|linux|ios` CLI flag; persona radio selector in TUI
  - Each persona projects the correct TTL, TCP timestamps, TCP options order, DHCP hostname style, and mDNS behaviour
  - Linux persona: TTL=64, timestamps=1, TCP options in kernel order (`MSS,SACK,TS,NOP,WScale`), WScale=7, distro-style DHCP hostnames
  - macOS persona: TTL=64, timestamps=1, TCP options `MSS,NOP,WS,NOP,NOP,TS,SOK`, no DHCP vendor class, Avahi left running
  - iOS persona: same as macOS with WScale=16
- **Protocol encapsulation** — 8 tunnel protocols managed via `--tunnel` flag or TUI
  - `tor` — onion routing, transparent or SOCKS5 mode; torrc generated on the fly; bootstrap polling
  - `wireguard` — wg-quick wrapper, transparent routing via WireGuard interface
  - `lwo` — WireGuard with Lightweight Obfuscation (ObfuscateKey config option, Mullvad-compatible)
  - `i2p` — i2pd garlic routing, SOCKS5 :4447 / HTTP :4444 / transparent via outproxy
  - `shadowsocks` — sslocal/ss-local AEAD proxy, redir mode or SOCKS5 :1080
  - `quic` — Hysteria2 UDP tunnel, transparent tproxy or SOCKS5 :1080
  - `tor-over-vpn` — WireGuard up first, Tor routed through VPN
  - `vpn-over-tor` — Tor up first (SOCKS), WireGuard routed through Tor
  - `--tunnel-mode transparent|socks`, `--tunnel-config PATH`
- **Granular apply flags** — `--mac`, `--netident`, `--sysinfo` (combinable); no-flag default runs all three
- **TUI sections** — Network Persona radio group + Traffic Encapsulation radio group with per-item descriptions
- **Tor distro portability** — auto-detects tor daemon user (`debian-tor` / `tor` / `_tor`) from `/etc/passwd` to prevent routing loops on non-Debian systems; polls SOCKS port for bootstrap readiness (up to 90s) instead of blind sleep

### Changed

- iptables chain renamed `IDSPOOF_WINEMU` → `IDSPOOF_NETEMU` (generic, backward-compat cleanup on restore)
- DHCP dropin renamed `90-idspoof-windows.conf` → `90-idspoof-persona.conf`; vendor class (Option 60) only injected for Windows persona
- Avahi suppression is now conditional: stopped for Windows, left running for macOS/Linux/iOS
- `apply --mac-only` / `--netident-only` replaced with composable `--mac`, `--netident`, `--sysinfo` flags matching `restore` syntax
- NFQUEUE rewriter now persona-aware via `activePersona atomic.Value`; wscale extracted from persona (7/8/16) rather than hardcoded

---

## [2.0.0] - 2026-02-27

### Changed

- **Full Go rewrite** — replaced ~890-line Bash toolkit with a structured Go binary (`github.com/NubleX/idspoof`)
- **System hostname never modified** — Windows identity is now projected at the wire level only; internal hostname and config files are untouched
- **Network persona layer** replaces naive hostname/fingerprint spoofing:
  - sysctl tuning: TTL=128, tcp_timestamps=0, tcp_sack=1, tcp_ecn=0, window buffers for wscale=8
  - iptables `IDSPOOF_WINEMU` mangle chain: TTL-set + MSS=1460 clamp on SYN packets
  - NFQUEUE (queue 42): pure-Go packet rewriter — rewrites IP ID (0→incrementing) and TCP options to Windows order (`MSS,NOP,WScale,NOP,NOP,SACKPermitted`)
  - DHCP Option 12 (hostname) + Option 60 (`MSFT 5.0` vendor class) via NetworkManager dropin or dhclient.conf
  - mDNS: Avahi daemon stopped to suppress real hostname broadcast
- **Cross-platform architecture** — Go build tags (`//go:build linux`) with macOS and Windows stubs ready for Phase 4–5
- **Cobra CLI** with subcommands: `apply`, `restore`, `status`, `menu`, `version`
- **Atomic state file** at `/var/log/idspoof/state.env` — backward-compatible with Bash v1 format
- Legacy Bash scripts preserved in `idspoof/legacy/` for reference

### Added

- `idspoof apply --netident-only` — apply Windows network persona without touching MACs
- `idspoof apply --dry-run` — preview changes without applying
- `idspoof restore --netident` — roll back only network persona
- `--debug` and `--log FILE` global flags
- Screenshots in `assets/images/`

### Removed

- `emergency-uninstall.sh` — superseded by `idspoof restore`
- `CODE_REVIEW.md` — all issues resolved by the Go rewrite
- GUI/zenity support — CLI-only in v2 (TUI menu via `idspoof menu`)

---

## [1.0.0] - 2025-06-06

### Added

- **Initial stable release** of ID-Spoofer
- **Complete MAC address spoofing** functionality with support for all network interfaces
- **Hostname randomization** with Windows-like naming patterns
- **OS fingerprint obfuscation** by modifying TCP/IP stack parameters
- **GUI support** with zenity integration for user-friendly operation
- **Desktop notifications** using libnotify for status updates
- **Interactive menu system** (`idspoof-menu.sh`) for easy operation
- **Comprehensive logging** capabilities with timestamps
- **Quiet mode** for automated/scripted operations
- **Progress indicators** for long-running operations
- **Modular operation modes** (full, MAC-only, hostname-only)
- **Enhanced command-line interface** with multiple options
- **Desktop integration** with application menu entries
- **Smart installer** with multi-distribution support
- **Uninstaller utility** for clean removal
- **Systemd service** for MAC address restoration (optional)
- **System information spoofing** with realistic hardware profiles
- **Multi-distribution support** (Ubuntu, Debian, Kali, Fedora, RHEL, Arch, openSUSE)

### Technical Improvements

- **Enhanced error handling** with proper exit codes and error messages
- **Automatic cleanup** of temporary files using trap handlers
- **Dependency verification** before execution
- **Temporary directory management** for secure file operations
- **Modular code structure** with separate functions for each operation
- **Input validation** for command-line arguments
- **Smart interface detection** using modern ip commands
- **Original settings backup** for potential restoration
- **Privilege checking** with informative error messages
- **Comprehensive help system** with examples and usage information

### Security Features

- **Locally administered MAC addresses** to avoid vendor conflicts
- **Root privilege verification** for security operations
- **Windows-like TCP/IP fingerprinting** to evade detection
- **Safe interface management** with proper up/down sequencing
- **Audit logging** for security compliance
- **Non-destructive operations** with backup capabilities

### User Experience

- **Modern CLI interface** with colored output and progress bars
- **Interactive confirmations** with clear explanations
- **GUI mode** with dialog boxes and notifications
- **Desktop integration** for easy access
- **Menu-driven interface** for beginners
- **Comprehensive documentation** with examples
- **Version information** and help commands
- **Multiple execution modes** for different use cases

### Installation & Distribution

- **Smart installer script** with distribution detection
- **Automatic dependency installation** for major Linux distributions
- **Clean uninstaller** with complete removal
- **Symbolic link creation** for easy command access
- **Desktop file installation** with application menu integration
- **Multi-distribution packaging** support
- **Proper file permissions** and directory structure

### Documentation

- **Comprehensive README** with badges, features, and usage examples
- **Project logo** in SVG format
- **Detailed installation instructions** for multiple distributions
- **Use case documentation** with legal disclaimers
- **Troubleshooting guide** for common issues
- **Command examples** and technical details
- **License information** (GPL v3.0)
- **Version badges** and project metadata

### Known Issues

- ⚠️ Network connectivity may be temporarily disrupted during MAC address changes
- ⚠️ Some network managers may interfere with MAC address spoofing
- ⚠️ GUI components require X11/Wayland display server
- ⚠️ Some enterprise networks may detect spoofed identifiers

### Dependencies

- **Required**: macchanger, net-tools, iproute2, bash
- **Optional**: zenity (GUI), libnotify-bin (notifications)
- **System**: Linux kernel 3.0+, systemd (optional)

---

## Release Notes

### Version 1.0.0 Highlights

This is the first stable release of ID-Spoofer, representing a complete rewrite and enhancement of the original concept. The tool now provides enterprise-grade functionality with comprehensive error handling, multi-distribution support, and both CLI and GUI interfaces.

Key achievements in this release:

- **Production Ready**: Extensive testing and error handling
- **User Friendly**: Both technical and non-technical user support
- **Secure**: Proper privilege handling and safe operations
- **Portable**: Support for major Linux distributions
- **Maintainable**: Clean, documented, and modular code structure

### Upgrade Path

This is the initial release, so no upgrade path is necessary. Future versions will include migration scripts if needed.

### Breaking Changes

N/A - Initial release

### Deprecations

N/A - Initial release

---

**For support, bug reports, or feature requests, please visit our [GitHub repository](https://github.com/NubleX/ID-Spoofer).**
