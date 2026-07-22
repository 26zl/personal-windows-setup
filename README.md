# personal-windows-setup

[![lint](https://github.com/26zl/personal-windows-setup/actions/workflows/lint.yml/badge.svg)](https://github.com/26zl/personal-windows-setup/actions/workflows/lint.yml)
![Platform](https://img.shields.io/badge/platform-Windows%2011%20Pro-0078D6?logo=windows&logoColor=white)
![PowerShell](https://img.shields.io/badge/PowerShell-5.1%20%7C%207%2B-5391FE?logo=powershell&logoColor=white)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

Personal installer for a fresh **Windows 11 Pro** PC after a factory reset.
Installs everything with winget, plus a few official external installers.
It isn't meant to cover everything, just a solid starting point with the basics.

## Run

Open an **elevated** PowerShell (right-click → *Run as administrator*) and paste:

```powershell
irm https://github.com/26zl/personal-windows-setup/raw/main/setup.ps1 | iex
```

Re-running is fine: installed apps are skipped. It then asks (y/n) whether to run `winget upgrade --all`, which updates every winget app on the machine, not just the list here. Failures are listed at the end. Every run writes two files to `%LOCALAPPDATA%\windows-setup\logs` (kept out of `%TEMP%` so cleanup tools don't wipe them): a full console transcript (`transcript-*.log`) and a timestamped event log (`events-*.log`) showing exactly what was installed, skipped, or failed, and when.

> `irm | iex` downloads and runs this script as Administrator. Read [`setup.ps1`](setup.ps1) first if you don't trust it. If scripts are blocked, run `Set-ExecutionPolicy -Scope Process Bypass` in the same window first.

## Requirements

- **Windows 11 Pro, x64** (Sandbox and Hyper-V need Pro and won't enable on Home; ARM64 is untested).
- **winget** (ships as *App Installer*; install it from the Microsoft Store if missing).
- An **elevated** PowerShell session, with firmware virtualization enabled for Hyper-V and WSL2.

## What it installs

- **Languages:** Python, Node.js LTS, Go, Rust, Java (Temurin 21), .NET SDK, Ruby
- **Build tools:** VS Build Tools + MSVC C++ toolset (compiler, linker, CRT, Windows SDK — for Rust MSVC & native modules), LLVM/Clang, MSYS2 (gcc/make)
- **Package managers:** pnpm, Bun, Chocolatey, Scoop, pipx, uv, UniGetUI (GUI front-end) (npm/corepack come with Node; pipx via pip)
- **Dev tools:** Git, GitHub CLI, GitHub Desktop, VS Code, Neovim (+ my [nvim config](https://github.com/26zl/nvim)), Windows Terminal, PowerShell 7, 7-Zip, VC++ Redistributables, just, jq, ripgrep, fd, adb (platform-tools)
- **Fullstack:** Docker Desktop, VirtualBox, DBeaver, Bruno
- **AI:** Ollama (local LLM runtime)
- **Sysadmin / net:** PowerToys, Sysinternals Suite, WinSCP, PuTTY, MobaXterm, Tailscale, WireGuard, Mullvad VPN
- **Cybersec:** Wireshark, Nmap, Burp Suite Community, KeePassXC, ConfigureDefender (Defender settings GUI — installed & signature-verified only, never auto-configured)
- **Sysmon:** system activity logging to the event log — built-in Sysmon on Windows 11 24H2+ (enables the optional feature if needed), signature-checked Sysinternals download on older Windows, configured with a pinned [SwiftOnSecurity config](sysmon/sysmonconfig-export.xml) and a 512 MB log
- **Browser:** Google Chrome, Tor Browser
- **Cleanup / maintenance:** Malwarebytes, AdwCleaner, BleachBit, DriverStore Explorer
- **Utilities:** Rufus, balenaEtcher, Steam, Windows Notepad (Store)
- **Tweak / privacy:** O&O ShutUp10, Win11Debloat, Winhance, Harden System Security (Store)
- **Claude Code** via its official native installer
- **PowerShellPerfect** (my own profile)
- Enables Windows Sandbox, Hyper-V, and WSL2 with Debian as the default distro
- **System Restore points** at the start and end of the run, so the whole thing can be rolled back from Settings or WinRE (turns on System Protection first if it's off)
- **System integrity:** a DISM component-store check (auto-repairs with `/RestoreHealth` only if corruption is found) followed by `sfc /scannow`
- **Disk cleanup** (runs near the end, just before the external tweak tools): DISM component cleanup, the Windows Update download cache, temp folders, and the Recycle Bin
- **Dual-boot checks (opt-in, y/n):** reports boot entries, Fast Startup, hibernation, hardware-clock (UTC vs local), Secure Boot, and BitLocker, then offers to disable hibernation entirely (`powercfg /h off`, which also clears Fast Startup) and set the clock to UTC

## Customize

Open `setup.ps1` and edit the `$winget` list. Find any ID with:

```powershell
winget search <name>
```

VS Build Tools and VirtualBox are large; remove those lines if you don't need them.

## Notes

- **Reboot when it finishes** to complete Sandbox, Hyper-V, and WSL2 (`wsl -l -v` to verify).
- **Everything extra is opt-in (y/n):** the tweak tools (Win11Debloat, Winhance, PowerShellPerfect), GitHub sign-in, the Neovim-in-WSL step, and each dual-boot change. Tweak tools each run in their own process.
- **Most installers are fetched at run time** — review their URLs and contents before you opt in.
- **Kubernetes** runs inside Docker Desktop (enable it in Settings); no separate cluster tooling is installed.
- **Not installed here:** cloud/ops tooling (Ansible, Terraform) and Java build tools (Maven, Gradle) — use the Debian WSL, or Chocolatey/Scoop for the Java tools.
- **More cybersecurity tooling:** [cybersec-toolkit](https://github.com/26zl/cybersec-toolkit) (580+ Linux/Termux tools, runs from the Debian WSL).

<details>
<summary><strong>Security &amp; supply-chain</strong></summary>

- **`OfficeSetup.exe`** is Microsoft's signed stub; the script verifies its pinned SHA-256 and Authenticode signature before running it. Refresh `$officeSha256` (`Get-FileHash office\OfficeSetup.exe`) if you replace it.
- **ConfigureDefender** is downloaded from AndyFul's repo, verified (pinned SHA-256 + signature), and given a Desktop shortcut — but never launched. Open it and pick a level (Default / High / Max) yourself; refresh `$cdSha256` for new builds.
- **winget upgrade delay:** the script sets `installBehavior.upgradeDelayInDays = 7`, so upgrades skip packages released in the last 7 days — a supply-chain safeguard that keeps a compromised release off the machine until it's caught. Change the `7` in `setup.ps1`, or clear it with `winget settings`.
- **Sysmon on its own** (existing machine, no full run): from an elevated shell, `irm https://github.com/26zl/personal-windows-setup/raw/main/sysmon/install-sysmon.ps1 | iex`. Re-running only reapplies the config; refresh `$configSha256` in `install-sysmon.ps1` if you replace the XML.

</details>

<details>
<summary><strong>Opt-in steps: dual-boot, GitHub, Neovim</strong></summary>

- **Dual-boot** checks are read-only until you confirm each change. Turning hibernation off (`powercfg /h off`, also clears Fast Startup) is safe for any dual boot. Set the hardware clock to UTC **only** if the other OS is Linux/macOS — not for Windows + Windows. **If BitLocker is on, back up your recovery key** before touching Secure Boot or firmware.
- **GitHub sign-in** runs `gh auth login --web`, wires git to use `gh` for credentials, and sets your global git identity (login name, `@users.noreply.github.com` when your email is hidden) plus sensible `init.defaultBranch` / `pull.rebase` / `push.autoSetupRemote` defaults.
- **Neovim** installs my [nvim config](https://github.com/26zl/nvim) into `%LOCALAPPDATA%\nvim` (backs up any existing config; plugins install on first launch) — it needs the C compiler the MSVC toolset provides. It can also set up the same config in WSL Debian; a fresh WSL isn't ready until after a reboot, so re-run for that part.

</details>

## License

Project code is MIT licensed. The bundled Sysmon configuration is [SwiftOnSecurity's sysmon-config](https://github.com/SwiftOnSecurity/sysmon-config), licensed CC BY 4.0; its attribution and license notice are retained in the header of [`sysmon/sysmonconfig-export.xml`](sysmon/sysmonconfig-export.xml).
