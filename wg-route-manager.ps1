param(
  [string]$ServerWgIp = "10.10.0.1"
)

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  Write-Host "Please run as Administrator." -ForegroundColor Red
  exit 1
}

$Gates        = @("docker", "winapp")
$GateGroup    = @{ docker = "WG-DOCKER"; winapp = "WG-WINAPP" }
$GateDefault  = @{ docker = "10.10.0.3"; winapp = "10.10.0.4" }
$ConfigPath   = Join-Path $PSScriptRoot "wg-route-manager.config.json"

# -- Config ------------------------------------------------------------------

function New-DefaultConfig {
  [PSCustomObject]@{
    ServerWgIp   = $ServerWgIp
    GateClientIp = [PSCustomObject]@{ docker = $GateDefault.docker; winapp = $GateDefault.winapp }
    GateEnabled  = [PSCustomObject]@{ docker = $false;              winapp = $false }
    PortProxies  = [PSCustomObject]@{ docker = @();                 winapp = @() }
  }
}

function Load-Config {
  if (-not (Test-Path $ConfigPath)) {
    $c = New-DefaultConfig
    $c | ConvertTo-Json -Depth 5 | Set-Content $ConfigPath
    return $c
  }
  try {
    $c = Get-Content $ConfigPath -Raw | ConvertFrom-Json
    if (-not $c.PortProxies) {
      $c | Add-Member -MemberType NoteProperty -Name PortProxies -Value ([PSCustomObject]@{})
    }
    foreach ($g in $Gates) {
      if (-not $c.GateClientIp.$g)     { $c.GateClientIp | Add-Member NoteProperty $g $GateDefault[$g] -Force }
      if ($null -eq $c.GateEnabled.$g) { $c.GateEnabled  | Add-Member NoteProperty $g $false            -Force }
      if ($null -eq $c.PortProxies.$g) { $c.PortProxies  | Add-Member NoteProperty $g @()               -Force }
    }
    return $c
  } catch {
    Write-Host "Config unreadable; rebuilding default." -ForegroundColor Yellow
    $c = New-DefaultConfig
    $c | ConvertTo-Json -Depth 5 | Set-Content $ConfigPath
    return $c
  }
}

function Save-Config { param($C); $C | ConvertTo-Json -Depth 5 | Set-Content $ConfigPath }

$Cfg = Load-Config

# -- Helpers -----------------------------------------------------------------

function Get-GateIp { param([string]$G); [string]$Cfg.GateClientIp.$G }

function Test-Ipv4 {
  param([string]$v)
  $ip = $null
  if (-not [System.Net.IPAddress]::TryParse($v, [ref]$ip)) { return $false }
  $ip.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork
}

function Read-Port {
  param([string]$Prompt)
  $n = 0
  $v = Read-Host $Prompt
  if (-not [int]::TryParse($v, [ref]$n) -or $n -lt 1 -or $n -gt 65535) { return $null }
  $n
}

function Ask-Gate {
  while ($true) {
    Write-Host "[D]ocker  [W]inapp"
    $g = (Read-Host "Gate").Trim().ToLower()
    if ($g -eq "d") { return "docker" }
    if ($g -eq "w") { return "winapp" }
    Write-Host "Invalid gate." -ForegroundColor Red
  }
}

# -- Conflict checks --------------------------------------------------------

function Get-GateConflicts {
  param([string]$Gate, [int[]]$FwPorts, $Proxies)
  $warnings   = @()
  $proxyPorts = @($Proxies | ForEach-Object { [int]$_.ListenPort })
  foreach ($p in $Proxies) {
    if ([int]$p.ListenPort -notin $FwPorts) {
      $warnings += "$Gate : portproxy :$($p.ListenPort) has no matching firewall rule (traffic will be blocked)"
    }
  }
  foreach ($port in $FwPorts) {
    if ($port -notin $proxyPorts) {
      $warnings += "$Gate : firewall rule for port $port has no matching portproxy entry (nothing will be listening)"
    }
  }
  return $warnings
}

function Show-GateConflictWarnings {
  param([string]$Gate)
  $group   = $GateGroup[$Gate]
  $proxies = @($Cfg.PortProxies.$Gate)
  $rules   = Get-NetFirewallRule -ErrorAction SilentlyContinue | Where-Object { $_.Group -eq $group }
  $fwPorts = @()
  foreach ($r in $rules) {
    $pf = $r | Get-NetFirewallPortFilter -ErrorAction SilentlyContinue
    if ($pf -and $pf.LocalPort -ne "Any") { $fwPorts += [int]$pf.LocalPort }
  }
  $warnings = Get-GateConflicts -Gate $Gate -FwPorts $fwPorts -Proxies $proxies

  # Cross-gate: detect connect-side duplicates (same ConnectAddress:ConnectPort used by another gate)
  foreach ($p in $proxies) {
    foreach ($other in @("docker","winapp") | Where-Object { $_ -ne $Gate }) {
      $clash = @($Cfg.PortProxies.$other) | Where-Object {
        $_.ConnectAddress -eq $p.ConnectAddress -and [int]$_.ConnectPort -eq [int]$p.ConnectPort
      }
      if ($clash) {
        $warnings += ("$Gate : portproxy :$($p.ListenPort) -> $($p.ConnectAddress):$($p.ConnectPort) " +
          "clashes with $other :$($clash[0].ListenPort) (both forward to the same local port)")
      }
    }
  }

  if ($warnings.Count -gt 0) {
    Write-Host "  Conflicts:" -ForegroundColor Yellow
    foreach ($w in $warnings) { Write-Host "    [!] $w" -ForegroundColor Yellow }
  }
}

# -- Status ------------------------------------------------------------------

function Show-Status {
  Write-Host ""
  Write-Host "Route status" -ForegroundColor Cyan
  Write-Host ("{0,-10} {1,-10} {2,-15} {3,-30} {4}" -f "gate", "status", "wg ip", "portproxies", "fw ports")
  Write-Host ("-" * 80)

  $allConflicts = @()

  foreach ($g in $Gates) {
    $ip     = Get-GateIp $g
    $active = [bool]$Cfg.GateEnabled.$g
    $status = if ($active) { "active" } else { "inactive" }

    $proxies  = @($Cfg.PortProxies.$g)
    $proxyTxt = if ($proxies.Count -eq 0) { "-" } else {
      ($proxies | ForEach-Object { "$($_.ListenPort)->$($_.ConnectPort)" }) -join ", "
    }

    $rules   = Get-NetFirewallRule -ErrorAction SilentlyContinue |
               Where-Object { $_.Group -eq $GateGroup[$g] }
    $fwPorts = @()
    $portTxt = if (-not $rules) { "-" } else {
      $pts = $rules | ForEach-Object {
        $pf = $_ | Get-NetFirewallPortFilter -ErrorAction SilentlyContinue
        if ($pf -and $pf.LocalPort -ne "Any") {
          $fwPorts += [int]$pf.LocalPort
          "$($pf.Protocol):$($pf.LocalPort)"
        }
      } | Sort-Object -Unique
      if ($pts) { $pts -join ", " } else { "-" }
    }

    Write-Host ("{0,-10} {1,-10} {2,-15} {3,-30} {4}" -f $g, $status, $ip, $proxyTxt, $portTxt)
    $allConflicts += Get-GateConflicts -Gate $g -FwPorts $fwPorts -Proxies $proxies

    # Cross-gate connect-side conflicts
    foreach ($p in $proxies) {
      foreach ($other in $Gates | Where-Object { $_ -ne $g }) {
        $clash = @($Cfg.PortProxies.$other) | Where-Object {
          $_.ConnectAddress -eq $p.ConnectAddress -and [int]$_.ConnectPort -eq [int]$p.ConnectPort
        }
        if ($clash) {
          $allConflicts += ("$g : portproxy :$($p.ListenPort) -> $($p.ConnectAddress):$($p.ConnectPort) " +
            "clashes with $other :$($clash[0].ListenPort) (both forward to the same local port)")
        }
      }
    }
  }

  Write-Host ("-" * 80)
  Write-Host "Server : $($Cfg.ServerWgIp)   Config : $ConfigPath"
  if ($allConflicts.Count -gt 0) {
    Write-Host ""
    foreach ($w in $allConflicts) { Write-Host "  [!] $w" -ForegroundColor Yellow }
  }
  Write-Host ""
}

# -- Toggle ------------------------------------------------------------------

function Toggle-Gate {
  Write-Host ""
  Write-Host "Toggle activates or deactivates a gate. When active, the portproxy listener" -ForegroundColor DarkGray
  Write-Host "opens on the gate's WireGuard IP so the VPS can reach your local service." -ForegroundColor DarkGray
  Write-Host "Note: services must be bound to 127.0.0.1 (loopback) only, not 0.0.0.0." -ForegroundColor DarkGray
  Write-Host "Docker example: -p 127.0.0.1:18081:80  (not -p 18081:80)" -ForegroundColor DarkGray
  $gate   = Ask-Gate
  $ip     = Get-GateIp $gate
  $enable = -not [bool]$Cfg.GateEnabled.$gate
  $val    = if ($enable) { "True" } else { "False" }

  $rules   = Get-NetFirewallRule -ErrorAction SilentlyContinue | Where-Object { $_.Group -eq $GateGroup[$gate] }
  $proxies = @($Cfg.PortProxies.$gate)

  if (-not $rules -and $proxies.Count -eq 0) {
    Write-Host "Nothing configured for $gate yet. Add port rules or portproxy entries first." -ForegroundColor Yellow
    return
  }

  # Print mappings
  Write-Host ""
  Write-Host "Mappings for $gate" -ForegroundColor Cyan
  if ($proxies.Count -gt 0) {
    Write-Host ("  {0,-25} {1,-25} {2}" -f "Windows (local)", "WireGuard ($ip)", "-> service")
    foreach ($e in $proxies) {
      Write-Host ("  {0,-25} {1,-25} {2}" -f "127.0.0.1:$($e.ConnectPort)", "${ip}:$($e.ListenPort)", "-> $($e.ConnectAddress):$($e.ConnectPort)")
    }
  } else {
    Write-Host "  No portproxy entries configured." -ForegroundColor DarkGray
  }
  Write-Host ""

  foreach ($r in $rules) {
    Set-NetFirewallRule -Name $r.Name -Enabled $val -ErrorAction SilentlyContinue | Out-Null
  }

  foreach ($e in $proxies) {
    if ($enable) {
      & netsh interface portproxy add v4tov4 `
        listenaddress=$ip listenport=$($e.ListenPort) `
        connectaddress=$($e.ConnectAddress) connectport=$($e.ConnectPort) | Out-Null
    } else {
      & netsh interface portproxy delete v4tov4 `
        listenaddress=$ip listenport=$($e.ListenPort) | Out-Null
    }
  }

  $Cfg.GateEnabled.$gate = $enable
  Save-Config $Cfg
  Write-Host "$gate is now $(if ($enable) { 'active' } else { 'inactive' })." -ForegroundColor Green
}

# -- Firewall port rules -----------------------------------------------------

function Show-GatePortRules {
  param([string]$Gate)
  $group = $GateGroup[$Gate]
  $rules = Get-NetFirewallRule -ErrorAction SilentlyContinue | Where-Object { $_.Group -eq $group }
  if (-not $rules) {
    Write-Host "  No rules configured for $Gate." -ForegroundColor DarkGray
  } else {
    Write-Host ("{0,-8} {1,-6} {2}" -f "proto", "port", "enabled")
    foreach ($r in $rules) {
      $pf = $r | Get-NetFirewallPortFilter -ErrorAction SilentlyContinue
      if ($pf -and $pf.LocalPort -ne "Any") {
        $en = ([string]$r.Enabled).Trim().ToLower() -eq "true"
        Write-Host ("  {0,-8} {1,-6} {2}" -f $pf.Protocol, $pf.LocalPort, $(if ($en) { "yes" } else { "no" }))
      }
    }
  }
  Write-Host ""
}

function Configure-Ports {
  Write-Host ""
  Write-Host "Port rules allow the VPS to reach this gate's WireGuard IP on a specific port." -ForegroundColor DarkGray
  Write-Host "They are disabled until the gate is toggled on." -ForegroundColor DarkGray
  $gate = Ask-Gate

  Write-Host ""
  Write-Host "Current rules for $gate" -ForegroundColor Cyan
  Show-GatePortRules -Gate $gate

  Write-Host "[A]dd  [R]emove"
  $a = (Read-Host "Action").Trim().ToUpper()
  if ($a -eq "A") { $action = "add" }
  elseif ($a -eq "R") { $action = "remove" }
  else { Write-Host "Invalid action." -ForegroundColor Red; return }

  Write-Host "[T]CP  [U]DP"
  $p = (Read-Host "Protocol").Trim().ToUpper()
  if ($p -eq "T") { $proto = "TCP" }
  elseif ($p -eq "U") { $proto = "UDP" }
  else { Write-Host "Invalid protocol." -ForegroundColor Red; return }

  $port = Read-Port "Port"
  if ($null -eq $port) { Write-Host "Invalid port." -ForegroundColor Red; return }

  $group = $GateGroup[$gate]
  $ip    = Get-GateIp $gate
  $name  = "WG $($gate.ToUpper()) $proto $port"

  if ($action -eq "add") {
    $exists = Get-NetFirewallRule -ErrorAction SilentlyContinue |
              Where-Object { $_.Group -eq $group -and $_.DisplayName -eq $name }
    if ($exists) { Write-Host "Rule already exists: $name" -ForegroundColor Yellow; return }

    New-NetFirewallRule `
      -DisplayName $name -Group $group `
      -Direction Inbound -Action Allow `
      -Protocol $proto -LocalAddress $ip `
      -RemoteAddress $Cfg.ServerWgIp `
      -LocalPort $port -Enabled False | Out-Null
    Write-Host "Added: $name" -ForegroundColor Green
    Show-GateConflictWarnings -Gate $gate
  } else {
    $matched = @(Get-NetFirewallRule -ErrorAction SilentlyContinue |
      Where-Object { $_.Group -eq $group } |
      Where-Object {
        $pf = $_ | Get-NetFirewallPortFilter -ErrorAction SilentlyContinue
        $pf -and $pf.Protocol -eq $proto -and $pf.LocalPort -eq "$port"
      })
    if ($matched.Count -eq 0) { Write-Host "Rule not found: $name" -ForegroundColor Yellow; return }
    $matched | Remove-NetFirewallRule
    Write-Host "Removed: $name" -ForegroundColor Green
  }
}

function Show-PortProxyTable {
  Write-Host ""
  Write-Host ("{0,-10} {1,-20} {2,-20} {3}" -f "gate", "listen (wg ip:port)", "connect (local)", "status")
  Write-Host ("-" * 70)
  foreach ($g in $Gates) {
    $ip      = Get-GateIp $g
    $status  = if ([bool]$Cfg.GateEnabled.$g) { "active" } else { "inactive" }
    $proxies = @($Cfg.PortProxies.$g)
    if ($proxies.Count -eq 0) {
      Write-Host ("{0,-10} {1,-20} {2,-20} {3}" -f $g, "-", "-", $status)
    } else {
      foreach ($e in $proxies) {
        Write-Host ("{0,-10} {1,-20} {2,-20} {3}" -f $g, "${ip}:$($e.ListenPort)", "$($e.ConnectAddress):$($e.ConnectPort)", $status)
      }
    }
  }
  Write-Host ("-" * 70)
  Write-Host ""
}

# -- Portproxy ---------------------------------------------------------------

function Manage-PortProxy {
  while ($true) {
    Write-Host ""
    Write-Host "Portproxy" -ForegroundColor Cyan
    Write-Host "Maps an external WireGuard IP:port to a local service address:port." -ForegroundColor DarkGray
    Write-Host "Example: 10.10.0.3:18081 -> 127.0.0.1:80 (Docker container on port 80)" -ForegroundColor DarkGray
    Show-PortProxyTable
    Write-Host "[A]dd   [R]emove   [B]ack"
    $choice = (Read-Host "Option").Trim().ToUpper()

    if ($choice -eq "B") { return }
    if ($choice -notin @("A","R")) { Write-Host "Invalid option." -ForegroundColor Red; continue }

    $gate = Ask-Gate
    $ip   = Get-GateIp $gate

    if ($choice -eq "A") {
      $lp = Read-Port "Listen port on $ip"
      if ($null -eq $lp) { Write-Host "Invalid port." -ForegroundColor Red; continue }

      $ca = (Read-Host "Connect address (default: 127.0.0.1)").Trim()
      if ([string]::IsNullOrWhiteSpace($ca)) { $ca = "127.0.0.1" }
      if (-not (Test-Ipv4 $ca)) { Write-Host "Invalid address." -ForegroundColor Red; continue }

      $cp = Read-Port "Connect port"
      if ($null -eq $cp) { Write-Host "Invalid port." -ForegroundColor Red; continue }

      $dup = @($Cfg.PortProxies.$gate) | Where-Object { $_.ListenPort -eq $lp }
      if ($dup) { Write-Host "Entry for :$lp already exists." -ForegroundColor Yellow; continue }

      # Cross-gate connect-side conflict: same ConnectAddress:ConnectPort already claimed
      foreach ($g in @("docker","winapp")) {
        $clash = @($Cfg.PortProxies.$g) | Where-Object {
          $_.ConnectAddress -eq $ca -and $_.ConnectPort -eq $cp
        }
        if ($clash) {
          Write-Host ("Conflict: {0}:{1} is already used by the {2} gate ({3}:{4} -> {5}:{6})." -f `
            $ca, $cp, $g, (Get-GateIp $g), $clash[0].ListenPort, $clash[0].ConnectAddress, $clash[0].ConnectPort) `
            -ForegroundColor Red
          Write-Host "Two gates cannot forward to the same local address:port." -ForegroundColor Red
          $ca = $null; break
        }
      }
      if ($null -eq $ca) { continue }

      $entry = [PSCustomObject]@{ ListenPort = $lp; ConnectAddress = $ca; ConnectPort = $cp }
      $Cfg.PortProxies.$gate = @($Cfg.PortProxies.$gate) + $entry
      Save-Config $Cfg

      if ([bool]$Cfg.GateEnabled.$gate) {
        & netsh interface portproxy add v4tov4 `
          listenaddress=$ip listenport=$lp `
          connectaddress=$ca connectport=$cp | Out-Null
      }
      Write-Host "Added: ${ip}:$lp -> ${ca}:$cp" -ForegroundColor Green
      Show-GateConflictWarnings -Gate $gate

    } else {
      $lp = Read-Port "Listen port to remove on $ip"
      if ($null -eq $lp) { Write-Host "Invalid port." -ForegroundColor Red; continue }

      $before = @($Cfg.PortProxies.$gate)
      $after  = @($before | Where-Object { $_.ListenPort -ne $lp })
      if ($after.Count -eq $before.Count) { Write-Host "Entry not found." -ForegroundColor Yellow; continue }

      $Cfg.PortProxies.$gate = $after
      Save-Config $Cfg
      & netsh interface portproxy delete v4tov4 listenaddress=$ip listenport=$lp | Out-Null
      Write-Host "Removed portproxy on ${ip}:$lp" -ForegroundColor Green
    }
  }
}

# -- IP mapping --------------------------------------------------------------

function Configure-IpMapping {
  Write-Host ""
  Write-Host "Each gate has a dedicated WireGuard IP that the VPS routes traffic to." -ForegroundColor DarkGray
  Write-Host "Change this if you've reassigned IPs in your WireGuard config." -ForegroundColor DarkGray
  $gate  = Ask-Gate
  $oldIp = Get-GateIp $gate
  Write-Host "Current IP for $gate : $oldIp"
  $newIp = (Read-Host "New IPv4").Trim()
  if (-not (Test-Ipv4 $newIp)) { Write-Host "Invalid IPv4." -ForegroundColor Red; return }

  $rules = Get-NetFirewallRule -ErrorAction SilentlyContinue | Where-Object { $_.Group -eq $GateGroup[$gate] }
  foreach ($r in $rules) {
    $af = $r | Get-NetFirewallAddressFilter -ErrorAction SilentlyContinue
    if ($af -and $af.LocalAddress -eq $oldIp) {
      Set-NetFirewallAddressFilter -InputObject $af -LocalAddress $newIp | Out-Null
    }
  }

  $Cfg.GateClientIp.$gate = $newIp
  Save-Config $Cfg
  Write-Host "Updated $gate to $newIp." -ForegroundColor Green
  Write-Host "Remember to update WireGuard [Interface] Address and server AllowedIPs." -ForegroundColor Yellow
}

# -- Reload -----------------------------------------------------------------

function Reload-Rules {
  Write-Host ""
  Write-Host "Reloading all active gates (toggle off then on)..." -ForegroundColor Cyan
  foreach ($gate in $Gates) {
    if (-not [bool]$Cfg.GateEnabled.$gate) { continue }
    $ip      = Get-GateIp $gate
    $val     = "False"
    $rules   = Get-NetFirewallRule -ErrorAction SilentlyContinue | Where-Object { $_.Group -eq $GateGroup[$gate] }
    $proxies = @($Cfg.PortProxies.$gate)

    foreach ($r in $rules) { Set-NetFirewallRule -Name $r.Name -Enabled $val -ErrorAction SilentlyContinue | Out-Null }
    foreach ($e in $proxies) {
      & netsh interface portproxy delete v4tov4 listenaddress=$ip listenport=$($e.ListenPort) | Out-Null
    }

    $val = "True"
    foreach ($r in $rules) { Set-NetFirewallRule -Name $r.Name -Enabled $val -ErrorAction SilentlyContinue | Out-Null }
    foreach ($e in $proxies) {
      & netsh interface portproxy add v4tov4 `
        listenaddress=$ip listenport=$($e.ListenPort) `
        connectaddress=$($e.ConnectAddress) connectport=$($e.ConnectPort) | Out-Null
    }
    Write-Host "  $gate reloaded." -ForegroundColor Green
  }
  Write-Host "Done." -ForegroundColor Green
}

# -- Reset -------------------------------------------------------------------

function Reset-All {
  Write-Host ""
  Write-Host "This will remove all firewall rules, portproxy entries, and the config file." -ForegroundColor Yellow
  Write-Host "[Y]es  [N]o"
  $confirm = (Read-Host "Confirm").Trim().ToUpper()
  if ($confirm -ne "Y") { Write-Host "Cancelled." -ForegroundColor Cyan; return }

  $groups = $GateGroup.Values
  $rules  = Get-NetFirewallRule -ErrorAction SilentlyContinue |
            Where-Object { $_.Group -in $groups }
  if ($rules) {
    $rules | Remove-NetFirewallRule
    Write-Host "Removed $($rules.Count) firewall rule(s)." -ForegroundColor Green
  } else {
    Write-Host "No firewall rules found." -ForegroundColor Cyan
  }

  & netsh interface portproxy reset | Out-Null
  Write-Host "Cleared all portproxy entries." -ForegroundColor Green

  if (Test-Path $ConfigPath) {
    Remove-Item $ConfigPath -Force
    Write-Host "Deleted config file." -ForegroundColor Green
  }

  $script:Cfg = New-DefaultConfig
  Write-Host "Reset complete." -ForegroundColor Green
}

# -- View all routes --------------------------------------------------------

function Show-AllRoutes {
  Write-Host ""
  Write-Host "Complete route mappings" -ForegroundColor Cyan

  foreach ($g in $Gates) {
    $ip     = Get-GateIp $g
    $status = if ([bool]$Cfg.GateEnabled.$g) { "active" } else { "inactive" }
    Write-Host ""
    Write-Host "  $g  ($status  |  WG IP: $ip)" -ForegroundColor White
    Write-Host ("  " + "-" * 60)

    # Portproxy
    Write-Host "  Portproxy (traffic path):" -ForegroundColor DarkGray
    $proxies = @($Cfg.PortProxies.$g)
    if ($proxies.Count -eq 0) {
      Write-Host "    none" -ForegroundColor DarkGray
    } else {
      foreach ($e in $proxies) {
        Write-Host ("    VPS -> {0,-20} -> {1}:{2}" -f "${ip}:$($e.ListenPort)", $e.ConnectAddress, $e.ConnectPort)
      }
    }

    # Firewall rules
    Write-Host "  Firewall rules:" -ForegroundColor DarkGray
    $rules = Get-NetFirewallRule -ErrorAction SilentlyContinue | Where-Object { $_.Group -eq $GateGroup[$g] }
    if (-not $rules) {
      Write-Host "    none" -ForegroundColor DarkGray
    } else {
      foreach ($r in $rules) {
        $pf = $r | Get-NetFirewallPortFilter -ErrorAction SilentlyContinue
        if ($pf -and $pf.LocalPort -ne "Any") {
          $en     = if (([string]$r.Enabled).Trim().ToLower() -eq "true") { "enabled" } else { "disabled" }
          $remote = ($r | Get-NetFirewallAddressFilter -ErrorAction SilentlyContinue).RemoteAddress
          Write-Host ("    {0,-5} {1,-8} from {2,-18} -> {3}:{4}  [{5}]" -f $pf.Protocol, $pf.LocalPort, $remote, $ip, $pf.LocalPort, $en)
        }
      }
    }

    Show-GateConflictWarnings -Gate $g
  }

  Write-Host ""
  Write-Host ("  Server WG IP : {0}" -f $Cfg.ServerWgIp)
  Write-Host ""
  Read-Host "Press Enter to return"
}

# -- Main loop ---------------------------------------------------------------

while ($true) {
  Show-Status
  Write-Host "[V]iew routes      show complete mappings for all gates"
  Write-Host "[T]oggle gate      activate / deactivate a gate (opens or closes portproxy listener)"
  Write-Host "[L]oad rules       re-apply all active gates (use after reboot or WG reconnect)"
  Write-Host "[P]ort rules       add / remove Windows Firewall rules for a gate port"
  Write-Host "[X] Portproxy      map a WireGuard IP:port to a local service"
  Write-Host "[I]P mapping       change which WireGuard IP is assigned to a gate"
  Write-Host "[R]eset all        wipe all rules, proxies, and saved config"
  Write-Host "[Q]uit"
  $choice = (Read-Host "Option").Trim().ToUpper()

  if     ($choice -eq "V") { Show-AllRoutes }
  elseif ($choice -eq "T") { Toggle-Gate }
  elseif ($choice -eq "L") { Reload-Rules }
  elseif ($choice -eq "P") { Configure-Ports }
  elseif ($choice -eq "X") { Manage-PortProxy }
  elseif ($choice -eq "I") { Configure-IpMapping }
  elseif ($choice -eq "R") { Reset-All }
  elseif ($choice -eq "Q") { Write-Host "Bye." -ForegroundColor Cyan; exit 0 }
  else                     { Write-Host "Invalid option." -ForegroundColor Red }
}
