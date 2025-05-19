# 🖥️ System Utility Client (Go Version)

![Go Version](https://img.shields.io/badge/Go-1.18%2B-blue.svg)
![Platforms](https://img.shields.io/badge/platform-macOS%20%7C%20Windows%20%7C%20Linux-lightgrey)
![License](https://img.shields.io/badge/license-MIT-green)

A lightweight, cross-platform system monitoring utility built in Go. It periodically checks for important system parameters and reports any changes to a configured API endpoint — designed to be efficient and low-overhead.

---

## 📋 Table of Contents

- [Features](#-features)
- [Requirements](#-requirements)
- [Installation](#-installation)
- [Configuration](#-configuration)
- [Usage](#-usage)
- [Running as a Service](#-running-as-a-service)
- [Troubleshooting](#-troubleshooting)

---

## ✅ Features

- 🧠 Smart change detection (reports only when state changes)
- 🔄 Periodic checks (default: every 30 minutes)
- ⚙️ Parameters monitored:
  - Disk encryption
  - OS update status
  - Antivirus presence
  - Inactivity sleep (≤ 10 minutes)
- ☁️ Sends updates to a configurable API endpoint
- 🪶 Minimal CPU/memory footprint
- 🧍 Runs in foreground (backgrounding possible via OS tools)

---

## 📦 Requirements

### Pre-compiled Binaries:
- No installation required. Just download and run the appropriate binary for your OS.

### Building from Source:
- [Go](https://golang.org/dl/) version 1.18 or higher

---

## 📥 Installation

### Option 1: Pre-built Binary (Recommended)

1. Download the correct binary for your system:
   - macOS: `system_monitor_macos_amd64` or `system_monitor_macos_arm64`
   - Windows: `system_monitor_windows_amd64.exe`
   - Linux: `system_monitor_linux_amd64`
2. Place it in a preferred directory (e.g., `/usr/local/bin`, `C:\Program Files`)
3. On macOS/Linux, make it executable:
   ```bash
   chmod +x ./system_monitor_binary
   ```

### Option 2: Build from Source

```bash
# Build for your system
go build system_monitor.go

# Cross-compile examples
GOOS=windows GOARCH=amd64 go build -o system_monitor_windows_amd64.exe system_monitor.go
GOOS=linux GOARCH=amd64 go build -o system_monitor_linux_amd64 system_monitor.go
GOOS=darwin GOARCH=amd64 go build -o system_monitor_macos_amd64 system_monitor.go
GOOS=darwin GOARCH=arm64 go build -o system_monitor_macos_arm64 system_monitor.go
```

---

## ⚙️ Configuration

Before first run, set the API endpoint in the source file:

```go
const (
    apiEndpoint = "https://your-api-endpoint.com/report"
)
```

> After editing, rebuild the binary if you made changes to the source.

_Future versions may support external config files or environment variables._

---

## ▶️ Usage

Some checks may require elevated privileges (Admin/root).

### macOS/Linux

```bash
# Without root
./system_monitor_macos_amd64

# With root (recommended)
sudo ./system_monitor_macos_amd64
```

### Windows

```cmd
.\system_monitor_windows_amd64.exe
```

> For full access, run as Administrator (right-click > "Run as administrator")

**Behavior on launch:**
- Initial scan
- Repeats every 30 minutes
- Logs to `system_monitor.log`
- Tracks last known state in `system_monitor_last_state.json`

Stop the tool using `Ctrl + C`.

---

## 🛠 Running as a Service

To run continuously in the background as a service:

- **macOS:** Use `launchd` with a `.plist` in `~/Library/LaunchAgents`
- **Linux:** Create a `systemd` service in `/etc/systemd/system`
- **Windows:** Use Task Scheduler or [NSSM](https://nssm.cc/)

_Setting these up is beyond this README’s scope._

---

## ❗ Troubleshooting

| Problem | Solution |
|--------|----------|
| **Permission denied** | Make executable (`chmod +x`) or run with `sudo` |
| **Unknown results** | Run as admin/root to access system APIs |
| **API errors** | Check API URL, network, or review `system_monitor.log` |
| **No logs/output** | Ensure the tool is launched from the correct directory |

---

## 📄 License

This project is licensed under the [MIT License](LICENSE).

---

