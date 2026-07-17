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

Re-running is fine: installed apps are skipped. Note it also runs `winget upgrade --all`, which updates every winget app on the machine, not just the list here. Failures are listed at the end and logged to `%TEMP%`.

> `irm | iex` downloads and runs this script as Administrator. Read [`setup.ps1`](setup.ps1) first if you don't trust it. If scripts are blocked, run `Set-ExecutionPolicy -Scope Process Bypass` in the same window first.

## Requirements

- **Windows 11 Pro, x64** (Sandbox and Hyper-V need Pro and won't enable on Home; ARM64 is untested).
- **winget** (ships as *App Installer*; install it from the Microsoft Store if missing).
- An **elevated** PowerShell session, with firmware virtualization enabled for Hyper-V and WSL2.

## What it installs

- **Languages:** Python, Node.js LTS, Go, Rust, Java (Temurin 21), .NET SDK, Ruby, Perl
- **Build tools:** VS Build Tools + MSVC C++ toolset (compiler, linker, CRT, Windows SDK — for Rust MSVC & native modules), LLVM/Clang, MSYS2 (gcc/make)
- **Package managers:** pnpm, Bun, Chocolatey, Scoop, pipx, uv, UniGetUI (GUI front-end) (npm/corepack come with Node; pipx via pip)
- **Dev tools:** Git, GitHub CLI, GitHub Desktop, VS Code, Windows Terminal, PowerShell 7, 7-Zip, VC++ Redistributables, just, jq, adb (platform-tools)
- **Fullstack:** Docker Desktop, VirtualBox, DBeaver, Bruno
- **Sysadmin / net:** PowerToys, Sysinternals Suite, WinSCP, PuTTY, MobaXterm, Tailscale, WireGuard, Mullvad VPN
- **Cybersec:** Wireshark, Nmap, Burp Suite Community, KeePassXC
- **Browser:** Google Chrome, Tor Browser
- **Cleanup / maintenance:** AdwCleaner, BleachBit, DriverStore Explorer
- **Utilities:** Rufus, balenaEtcher, Steam, Windows Notepad (Store)
- **Tweak / privacy:** O&O ShutUp10, Win11Debloat, Winhance, Harden System Security (Store)
- **Claude Code** via its official native installer
- **PowerShellPerfect** (my own profile)
- Enables Windows Sandbox, Hyper-V, and WSL2 with Debian as the default distro

## Customize

Open `setup.ps1` and edit the `$winget` list. Find any ID with:

```powershell
winget search <name>
```

VS Build Tools and VirtualBox are large; remove those lines if you don't need them.

## Notes

- Reboot after running to finish Sandbox, Hyper-V, and WSL2 (`wsl -l -v` to verify).
- The external tweak tools (Win11Debloat, Winhance, PowerShellPerfect) only run if you explicitly type `y`, and each runs in its own process.
- Only official upstream URLs are used; they fetch the latest version on each run.
- The bundled `OfficeSetup.exe` is Microsoft's signed setup stub; the script verifies its Authenticode signature before running it.
- Kubernetes runs inside Docker Desktop (enable it in Settings); no separate cluster tooling is installed.
- Cloud and ops tooling (Ansible, Terraform, and similar) isn't installed by this script; install and run it inside the Debian WSL environment.
- Java build tools (Maven, Gradle) aren't on winget; install them via Chocolatey or Scoop in a normal shell, or from the Debian WSL.
- For advanced cybersecurity tooling, see [cybersec-toolkit](https://github.com/26zl/cybersec-toolkit) (580+ Linux/Termux tools; runs from the Debian WSL above).

## License

MIT. See [LICENSE](LICENSE).
