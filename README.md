# Minecraft Cheat Detection Tool

<div align="center">

![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-blue?logo=powershell)
![Windows](https://img.shields.io/badge/Windows-10%2F11-0078D6?logo=windows)
![License](https://img.shields.io/badge/License-MIT-green)

**Advanced forensic scanner for detecting Minecraft cheat artifacts on Windows systems**

</div>

---

## Features

- **Process Analysis** - Scans running `javaw.exe` processes for suspicious modules and window titles
- **Prefetch Forensics** - Analyzes Windows Prefetch files for recently executed cheat programs
- **ShimCache Analysis** - Parses Application Compatibility Cache for execution evidence
- **Multi-Launcher Support** - Scans 15+ Minecraft launchers including:
  - Minecraft Official, PrismLauncher, MultiMC, CurseForge, Modrinth
  - ATLauncher, Lunar Client, Badlion, Feather, TLauncher, and more
- **Log Analysis** - Searches game logs for cheat-related keywords
- **Recycle Bin Forensics** - Finds recently deleted suspicious files
- **JSON Export** - Outputs structured JSON for API integration

## Requirements

- Windows 10/11
- PowerShell 5.1 or higher
- **Administrator privileges** (required for Prefetch/ShimCache access)

## Installation

```powershell
# Clone the repository
git clone https://github.com/YOUR_USERNAME/MinecraftCheatDetector.git
cd MinecraftCheatDetector
```

## Usage

### Basic Scan (with API reporting)
```powershell
# Run as Administrator
.\MinecraftCheatDetector.ps1
```

### Test Mode (JSON output to console)
```powershell
.\MinecraftCheatDetector.ps1 -TestMode
```

### Automated Mode (skip disclaimer)
```powershell
.\MinecraftCheatDetector.ps1 -TestMode -SkipDisclaimer
```

## Configuration

Edit the script to configure your API endpoint:

```powershell
$script:ApiEndpoint = "https://your-api-endpoint.com/report"
```

### Adding Custom Cheat Hashes

```powershell
$script:KnownCheatHashes = @{
    "your_md5_hash_here" = "Cheat Name"
}
```

## Detection Patterns

The tool detects the following cheat clients and features:

| Category | Examples |
|----------|----------|
| **Clients** | Vape, Wurst, Aristois, LiquidBounce, Meteor, Doomsday, FDP |
| **Combat** | Killaura, TriggerBot, Aimbot, Reach, Velocity, Criticals |
| **Movement** | Fly, Speed, Spider, Jesus, Bunnyhop, NoFall |
| **World** | X-ray, Nuker, FastPlace, FastBreak, ChestStealer |
| **Utility** | AutoClicker, ESP, Tracers, FullBright, Freecam |

## JSON Output Example

```json
{
  "Metadata": {
    "ToolVersion": "1.0.0",
    "ScanTime": "2026-01-05T20:30:00+01:00",
    "Hostname": "DESKTOP-XYZ",
    "Username": "user"
  },
  "FileSystemArtifacts": [...],
  "PrefetchArtifacts": [...],
  "Summary": {
    "TotalFindings": 3
  }
}
```

## Legal Disclaimer

This tool is intended for:
- Server administrators investigating cheating reports
- Parents monitoring their children's Minecraft installations
- Security researchers studying game modification detection

**Use responsibly and in compliance with local laws.**

## License

MIT License - See [LICENSE](LICENSE) for details.

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/new-detection`)
3. Commit your changes (`git commit -am 'Add new detection pattern'`)
4. Push to the branch (`git push origin feature/new-detection`)
5. Open a Pull Request

---

<div align="center">
Made with ❤️ for fair Minecraft gameplay
</div>
