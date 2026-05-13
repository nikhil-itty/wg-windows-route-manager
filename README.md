# wg-route-manager

Interactive PowerShell script for managing WireGuard-based traffic gates on Windows. Controls which local services (Docker containers, native apps, VSCode-forwarded WSL ports) are exposed through a WireGuard tunnel to a remote VPS.

## Requirements

- Windows 10/11
- PowerShell 5.1+, run as **Administrator**
- WireGuard for Windows (connected to VPS)

## Setup

Copy `wg-route-manager.ps1` to a permanent folder. The config file (`wg-route-manager.config.json`) is created automatically in the same directory on first run.

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\wg-route-manager.ps1
```

No parameters required. Defaults: server WG IP `10.10.0.1`, docker gate `10.10.0.3`, winapp gate `10.10.0.4`.

---

## Architecture

```
VPS (10.10.0.1)
  │
  │  WireGuard tunnel
  ▼
Windows
  ├── 10.10.0.3  →  Docker gate   →  portproxy  →  127.0.0.1:<port>  →  Docker container
  └── 10.10.0.4  →  WinApp gate   →  portproxy  →  127.0.0.1:<port>  →  Windows app / WSL (via VSCode forward)
```

Each gate is a dedicated WireGuard IP on the Windows interface. Traffic arrives from the VPS, hits the portproxy listener on that IP, and is forwarded to a local service on loopback.

**Important:** services must bind to `127.0.0.1`, not `0.0.0.0`. If a service binds to all interfaces it will be reachable on the WireGuard IP directly, bypassing the gate entirely.

Docker example:
```
# correct — loopback only
docker run -p 127.0.0.1:18081:80 nginx:alpine

# wrong — bypasses gate
docker run -p 18081:80 nginx:alpine
```

---

## Menu Reference

```
[V]iew routes      show complete mappings for all gates
[T]oggle gate      activate / deactivate a gate
[L]oad rules       re-apply all active gates (use after reboot or WG reconnect)
[P]ort rules       add / remove Windows Firewall rules for a gate port
[X] Portproxy      map a WireGuard IP:port to a local service
[I]P mapping       change which WireGuard IP is assigned to a gate
[R]eset all        wipe all rules, proxies, and saved config
[Q]uit
```

---

## Options in Detail

### [V] View routes
Displays the full configuration for every gate: portproxy path, firewall rules, enabled/disabled state. Read-only.

### [T] Toggle gate
Activates or deactivates a gate. On **activate**:
- Creates live portproxy listeners (`netsh interface portproxy add`) for all entries saved for that gate.
- Enables the gate's Windows Firewall rules.

On **deactivate**:
- Removes live portproxy listeners (config entries are kept, not deleted).
- Disables the firewall rules.

Portproxy is the primary traffic gate — removing the listener is what actually blocks access.

### [L] Load rules
Re-applies all gates currently marked active in config (toggle off then on). Use this after a reboot or WireGuard reconnect, when live portproxy state has been lost but the config still shows gates as active.

### [P] Port rules
Adds or removes a Windows Firewall inbound Allow rule for a specific protocol/port on a gate's WireGuard IP. Rules are created **disabled** and only become active when the gate is toggled on.

Showing current rules for the selected gate before prompting for action.

### [X] Portproxy
Manages portproxy entries — the mappings from `WireGuard IP:port` to `local address:port`. Entries are persisted in config and applied/removed automatically on toggle.

When adding an entry while the gate is already active, the listener is created immediately without needing a toggle cycle.

### [I] IP mapping
Changes the WireGuard IP assigned to a gate. Automatically rebinds existing firewall rules to the new IP. Remember to also update:
- Windows WireGuard client: `[Interface] Address`
- VPS WireGuard server: `[Peer] AllowedIPs`

### [R] Reset all
Removes all firewall rules in the `WG-DOCKER` / `WG-WINAPP` groups, runs `netsh interface portproxy reset`, and deletes the config file. Requires `Y` confirmation. The script remains running with a fresh default config after reset.

---

## Config File

`wg-route-manager.config.json` — created automatically, stored in the same directory as the script.

```json
{
  "ServerWgIp": "10.10.0.1",
  "GateClientIp": {
    "docker": "10.10.0.3",
    "winapp": "10.10.0.4"
  },
  "GateEnabled": {
    "docker": false,
    "winapp": false
  },
  "PortProxies": {
    "docker": [
      { "ListenPort": 18081, "ConnectAddress": "127.0.0.1", "ConnectPort": 18081 }
    ],
    "winapp": [
      { "ListenPort": 18080, "ConnectAddress": "127.0.0.1", "ConnectPort": 18080 }
    ]
  }
}
```

The config is the source of truth for gate state. Live portproxy state (from `netsh`) is ephemeral and is rebuilt from config on toggle-on or reload.

---

## Example: Exposing a Docker Container

1. Start the container bound to loopback:
   ```powershell
   docker run -d --name myapp -p 127.0.0.1:18081:80 nginx:alpine
   ```

2. In the script, add a portproxy entry: `[X]` → `[A]` → Docker → listen `18081`, connect `127.0.0.1:18081`

3. Add a firewall rule: `[P]` → Docker → `[A]` → TCP → `18081`

4. Activate the gate: `[T]` → Docker

5. Verify from the VPS:
   ```bash
   curl http://10.10.0.3:18081
   ```

## Example: Exposing a VSCode-forwarded WSL Port

VSCode automatically forwards WSL ports to Windows localhost. No manual portproxy inside WSL is needed.

1. Run a service in WSL (e.g. `python3 -m http.server 8080`). VSCode forwards it to `127.0.0.1:8080` on Windows automatically.

2. Add a portproxy entry: `[X]` → `[A]` → WinApp → listen `18080`, connect `127.0.0.1:8080`

3. Add a firewall rule: `[P]` → WinApp → `[A]` → TCP → `18080`

4. Activate the gate: `[T]` → WinApp

5. Verify from the VPS:
   ```bash
   curl http://10.10.0.4:18080
   ```

---

## After a Reboot

WireGuard reconnects automatically (if set to auto-start). Portproxy state is lost on reboot. Use `[L]oad rules` to restore all active gates from config without manually toggling each one.
