<#
.SYNOPSIS
  A PowerShell script to manage Firewall rules for ports.
.DESCRIPTION
  This script allows you to add, remove, replace, and list firewall rules for WSL 2.
  The script uses the Windows Firewall to manage the firewall rules.
  The script requires administrative privileges to add or remove firewall rules.
.PARAMETER c
  The command to execute. Valid values are 'add', 'rm', 'replace', 'ls' and 'find'.
  add: Add firewall rules.
  rm: Remove firewall rules.
  replace: Replace the existing firewall rules with the new rules.
  ls: List the existing firewall rules.
  find: Find the existing firewall rules for the specified port(s).
.PARAMETER p
  The port(s) to add, remove, or replace. This parameter accepts an array of integers.
  Optional with 'rm' and 'ls' commands.
.PARAMETER a
  List all firewall rules for the specified port(s). Optional with 'ls', 'find' commands.
.EXAMPLE
  pfw.ps1 -c add -p 8080
  Add a firewall rule for port 8080.
.EXAMPLE
  pfw.ps1 -c add -p 8080,8081
  Add firewall rules for ports 8080 and 8081.
.EXAMPLE
  pfw.ps1 -c rm -p 8080
  Remove the firewall rule for port 8080.
.EXAMPLE
  pfw.ps1 -c rm
  Remove existing firewall rules for all ports created using this tool.
.EXAMPLE
  pfw.ps1 -c replace -p 8080,8081
  Replace the existing firewall rules with the new rules for ports 8080 and 8081.
.EXAMPLE
  pfw.ps1 -c ls
  List the existing firewall rules.
.EXAMPLE
  pfw.ps1 -c ls -a
  List all ports that have two-way firewall rules on the system (takes a while to execute).
.EXAMPLE
  pfw.ps1 -c find -p 8080,8081
  Find the existing firewall rules for ports 8080 and 8081.
.EXAMPLE
  pfw.ps1 -c find -p 8080,8081 -a
  List all firewall rules for ports 8080 and 8081.

.NOTES
  File Name      : pfw.ps1
  Author         : Esensats

  The script uses the Windows Firewall to manage the firewall rules.
  The script requires administrative privileges to add or remove firewall rules.
  The script is tested on Windows 10 with PowerShell 7.
  Recommended to check out the examples.
  Recommended to check out the existing firewall rules before adding or removing rules.
    For this you can use 'ls -a' or 'find -p <port> ...'.

  This script is provided as-is without any warranty. Use it at your own risk.

  Version        : 1.0
  Date           : 2024-04-20
#>

param(
  [Parameter(Mandatory = $true)]
  [ValidateSet('add', 'rm', 'replace', 'ls', 'find')]
  [string]$c,
  [UInt16[]]$p,
  [switch]$a
)

function Get-ExistingPorts {
  param (
    [Parameter(Mandatory = $true)]
    [string]$displayName
  )
  $fw = New-object -comObject HNetCfg.FwPolicy2
  # Find by pattern in the name - "displayName port" and remove duplicates
  return $fw.rules |
  Where-Object { $_.Name -match $displayName } |
  ForEach-Object { $_.LocalPorts } |
  Select-Object -Unique
}

# Returns all firewall port rules that are both inbound and outbound
function Get-FirewallTwowayPorts {
  # Create a new instance of the HNetCfg.FwPolicy2 COM object
  $fwPolicy = New-Object -ComObject HNetCfg.FwPolicy2

  # Get all inbound rules
  $inboundRules = $fwPolicy.Rules | Where-Object { $_.Direction -eq 1 }

  # Get all outbound rules
  $outboundRules = $fwPolicy.Rules | Where-Object { $_.Direction -eq 2 }

  # Create an empty hash map to store the outbound rules
  $outboundRuleMap = @{}

  # Populate the hash map with the outbound rules, using the local port and protocol as keys
  foreach ($outboundRule in $outboundRules) {
    # Split the LocalPorts string into an array of port numbers or ranges
    $localPorts = $outboundRule.LocalPorts -split ','

    # Loop through each port number or range
    foreach ($localPort in $localPorts) {
      # Check if the port number or range is a wildcard
      if ($localPort -eq '*') {
        # If the port number or range is a wildcard, add an entry for all ports to the hash map
        for ($i = 1; $i -le 65535; $i++) {
          $key = "$i-$($outboundRule.Protocol)"
          $outboundRuleMap[$key] = $outboundRule
        }
      }
      else {
        # If the port number or range is not a wildcard, add an entry for the port number or range to the hash map
        $key = "$localPort-$($outboundRule.Protocol)"
        $outboundRuleMap[$key] = $outboundRule
      }
    }
  }

  # Create an empty array to store the ports
  $ports = @()

  # Loop through each inbound rule
  foreach ($inboundRule in $inboundRules) {
    # Split the LocalPorts string into an array of port numbers or ranges
    $localPorts = $inboundRule.LocalPorts -split ','

    # Loop through each port number or range
    foreach ($localPort in $localPorts) {
      # Check if the port number or range is a wildcard
      if ($localPort -eq '*') {
        # If the port number or range is a wildcard, skip this iteration of the loop
        continue
      }
      else {
        # If the port number or range is not a wildcard, check if there is a matching outbound rule in the hash map
        $key = "$localPort-$($inboundRule.Protocol)"
        if ($outboundRuleMap.ContainsKey($key)) {
          # If a matching outbound rule is found, add the port to the array
          $ports += $localPort
        }
      }
    }
  }

  # Remove duplicates from the array of ports
  $ports = $ports | Select-Object -Unique

  # Return the array of ports
  return $ports
}

function FindRulesByPort {
  param (
    [Parameter(Mandatory = $true)]
    [UInt16]$port,
    [string]$displayName
  )
  $fwRules = Get-NetFirewallPortFilter | Where-Object LocalPort -eq $port | Get-NetFirewallRule;
  if (-not $displayName) {
    return $fwRules;
  }
  return $fwRules | Where-Object DisplayName -eq "$displayName $port";
}

function Get-AllFirewallPortRules {
  <#
  .SYNOPSIS
    Returns all firewall port rules (very slow, use Get-FirewallTwowayPorts instead if you need just ports)
  #>
  return Get-ExistingPorts | ForEach-Object { FindRulesByPort -port $_ };
}

function Add-PortForwardFirewallRule {
  param (
    [Parameter(Mandatory = $true)]
    [string]$displayName,
    [Parameter(Mandatory = $true)]
    [UInt16]$port,
    [Parameter(Mandatory = $true)]
    [string]$addr
  )

  $resultDisplayName = "$displayName $port";
  try { 
    New-NetFireWallRule -DisplayName $resultDisplayName -Direction Outbound -LocalPort $port -Action Allow -Protocol TCP -ErrorAction stop | Out-Null;
    New-NetFireWallRule -DisplayName $resultDisplayName -Direction Inbound -LocalPort $port -Action Allow -Protocol TCP -ErrorAction stop | Out-Null;
  }
  catch {
    Write-Error "Failed to create firewall rules"
    $PSCmdlet.ThrowTerminatingError($_)
  }
  return "+$resultDisplayName";
}

function Remove-PortForwardFirewallRule {
  param (
    [Parameter(Mandatory = $true)]
    [string]$displayName,
    [Parameter(Mandatory = $true)]
    [UInt16]$port,
    [Parameter(Mandatory = $true)]
    [string]$addr
  )

  $resultDisplayName = "$displayName $port";
  
  try { 
    Remove-NetFireWallRule -DisplayName $resultDisplayName -ErrorAction SilentlyContinue;
  }
  catch {
    Write-Error "Failed to remove firewall rules"
    $PSCmdlet.ThrowTerminatingError($_)
  }

  return "-$resultDisplayName";
}

function CheckElevated {
  if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    $PSCmdlet.ThrowTerminatingError([System.Management.Automation.ErrorRecord]::new([System.InvalidOperationException]::new("The Script Exited, Please run the script as an administrator."), "ScriptRequiresElevation", [System.Management.Automation.ErrorCategory]::InvalidOperation, $null))
  }
}

# You can change the addr to your ip config to listen to a specific address
$addr = '0.0.0.0';
$firewallRuleName = 'PFW Firewall Rule';

switch ($c) {
  'add' {
    CheckElevated;
    $existing_ports = Get-ExistingPorts -displayName $firewallRuleName
    $intersection = $p | Where-Object { $existing_ports -contains $_ }
    $ports_to_add = $p | Where-Object { $_ -notin $intersection }

    foreach ($port in $ports_to_add) {
      Add-PortForwardFirewallRule -displayName $firewallRuleName -port $port -addr $addr
    }
  }
  'rm' {
    CheckElevated;
    if ($p) {
      foreach ($port in $p) {
        Remove-PortForwardFirewallRule -displayName $firewallRuleName -port $port -addr $addr
      }
    }
    else {
      $ports_to_remove = Get-ExistingPorts -displayName $firewallRuleName
        
      if ($ports_to_remove) {
        foreach ($port in $ports_to_remove) {
          Remove-PortForwardFirewallRule -displayName $firewallRuleName -port $port -addr $addr
        }
      }
    }
  }
  'replace' {
    CheckElevated;
    $ports_to_remove = Get-ExistingPorts -displayName $firewallRuleName
    if ($ports_to_remove) {
      foreach ($port in $ports_to_remove) {
        if ($p -notcontains $port) {
          Remove-PortForwardFirewallRule -displayName $firewallRuleName -port $port -addr $addr
        }
      }
    }
    $intersection = $p | Where-Object { $ports_to_remove -contains $_ }
    $ports_to_add = $p | Where-Object { $_ -notin $intersection }

    foreach ($port in $ports_to_add) {
      Add-PortForwardFirewallRule -displayName $firewallRuleName -port $port -addr $addr
    }
  }
  'ls' {
    # : List all ports that have PFW specific firewall rules
    if (-not $a) {
      return Get-ExistingPorts -displayName $firewallRuleName
    }
    # -a: List all ports that have firewall rules
    return Get-FirewallTwowayPorts
  }
  'find' {
    CheckElevated;
    # -p: List all PFW specific firewall rules for the specified port(s)
    if (-not $a) {
      foreach ($port in $p) {
        FindRulesByPort -port $port -displayName $firewallRuleName
      }
      return
    }
    # -p -a: List all firewall rules for the specified port(s)
    foreach ($port in $p) {
      FindRulesByPort -port $port
    }
  }
  default {
    $PSCmdlet.ThrowTerminatingError([System.Management.Automation.ErrorRecord]::new([System.InvalidOperationException]::new("Invalid command. Run `Get-Help $($PSCommandPath)` for more information."), "InvalidCommand", [System.Management.Automation.ErrorCategory]::InvalidOperation, $null))
  }
}
return
