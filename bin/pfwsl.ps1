<#
.SYNOPSIS
  A PowerShell script to manage port forwarding rules for WSL 2.
.DESCRIPTION
  This script allows you to add, remove, replace, and list port forwarding rules for WSL 2.
  It uses the Windows Firewall and netsh to manage the port forwarding rules.
  It requires administrator privileges to add or remove port forwarding rules.

  SYNTAX:
  pfwsl [-c] {add|replace} [-p] <port>[,<port>]... [-WslIp <WSL_IP_Address>]
  pfwsl [-c] {find} [-p] <port>[,<port>]... [-a]
  pfwsl [-c] {rm} [-p] [<port>[,<port>]...]
  pfwsl [-c] {ls} [-a]
  pfwsl [-c] {ip|iprm}
  pfwsl [-c] {ipset} -WslIp <WSL_IP_Address>
.PARAMETER c
  The command to execute. Valid values are `add`, `rm`, `replace`, `ls`, `find`, `ip`, `ipset` and `iprm`.
  add: Add port forwarding rules.
  rm: Remove port forwarding rules.
  replace: Replace the existing port forwarding rules with the new rules.
  ls: List the existing port forwarding rules.
  find: Find the existing port forwarding rules for the specified port(s).
  ip: Get the WSL IP address the script is using ($env or automatic).
  ipset: Set the WSL IP address manually (persistent) (useful when the script cannot detect the needed IP address or if it's too slow).
  iprm: Remove the manually set WSL IP address from `$env`. 
.PARAMETER p
  The port(s) to add, remove, or replace. This parameter accepts an array of integers.
  Optional with 'rm' and 'ls' commands.
.PARAMETER a
  List all firewall rules for the specified port(s). Optional with 'ls', 'find' commands.
.EXAMPLE
  pfwsl.ps1 -c add -p 8080
  Add a port forwarding rule for port 8080.
.EXAMPLE
  pfwsl.ps1 -c add -p 8080,8081
  Add port forwarding rules for ports 8080 and 8081.
.EXAMPLE
  pfwsl.ps1 -c rm -p 8080
  Remove the port forwarding rule for port 8080.
.EXAMPLE
  pfwsl.ps1 -c rm
  Remove all port forwarding rules.
.EXAMPLE
  pfwsl.ps1 -c replace -p 8080,8081
  Replace the existing port forwarding rules with the new rules for ports 8080 and 8081.
.EXAMPLE
  pfwsl.ps1 -c ls
  List the existing port forwarding rules.
.EXAMPLE
  pfwsl.ps1 -c ls -a
  List all ports that have two-way firewall rules (takes a while to execute).
.EXAMPLE
  pfwsl.ps1 -c find -p 8080,8081
  Find the existing port forwarding rules for ports 8080 and 8081.
.EXAMPLE
  pfwsl.ps1 -c find -p 8080,8081 -a
  List all firewall rules for ports 8080 and 8081.

.NOTES
  File Name      : pfwsl.ps1
  Author         : Esensats
  Prerequisite   : Windows 10, Windows Subsystem for Linux 2 (WSL 2)

  The script uses the Windows Firewall and netsh to manage the port forwarding rules.
  The script requires administrative privileges to add or remove port forwarding rules.
  The script is tested on Windows 10 with PowerShell 7 and Windows Subsystem for Linux 2 (WSL 2).
  Recommended to check out the examples.
  Recommended to check out the existing port forwarding rules before adding or removing rules.
    For this you can use 'ls -a' or 'find -p <port> ...'.

  This script is provided as-is without any warranty. Use it at your own risk.

  Version        : 1.0
  Date           : 2024-04-17
#>

param(
  [Parameter(Mandatory = $true)]
  [ValidateSet('add', 'rm', 'replace', 'ls', 'find', 'ip', 'ipset', 'iprm')]
  [Alias('Command')]
  [string]$c,
  [Parameter(ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
  [Alias('Port')]
  [UInt16[]]$p,
  [Alias('All')]
  [switch]$a,
  [string]$WslIp
)
begin {
  function Get-ExistingPorts {
    param (
      [Parameter(Mandatory = $true)]
      [string]$displayName
    )
    try { 
      $fw = New-object -comObject HNetCfg.FwPolicy2
    }
    catch {
      throw "Failed to create firewall object: $_"
    }
    # Find by pattern in the name - "displayName port" and remove duplicates
    return $fw.rules |
    Where-Object { $_.Name -match $displayName } |
    ForEach-Object { $_.LocalPorts } |
    Select-Object -Unique
  }

  # Returns all firewall port rules that are both inbound and outbound
  function Get-FirewallTwowayPorts {
    # Create a new instance of the HNetCfg.FwPolicy2 COM object
    try {
      $fwPolicy = New-Object -ComObject HNetCfg.FwPolicy2
      Write-Debug "Created firewall object"
    }
    catch {
      throw "Failed to create firewall object: $_"
    }

    # Get all inbound rules
    $inboundRules = $fwPolicy.Rules | Where-Object { $_.Direction -eq 1 }
    Write-Debug "Got inbound rules"
    
    # Get all outbound rules
    $outboundRules = $fwPolicy.Rules | Where-Object { $_.Direction -eq 2 }
    Write-Debug "Got outbound rules"

    # Create an empty hash map to store the outbound rules
    $outboundRuleMap = @{}

    $outboundRulesLength = $outboundRules.Length
  
    $index = 0
    # Populate the hash map with the outbound rules, using the local port and protocol as keys
    foreach ($outboundRule in $outboundRules) {
      # Display progress
      $index++;
      Write-Progress -Activity "Populating outbound rule map" -Status "$($index)/$outboundRulesLength" -PercentComplete ($index / $outboundRulesLength * 100)
      # Split the LocalPorts string into an array of port numbers or ranges
      $localPorts = $outboundRule.LocalPorts -split ','

      # Loop through each port number or range
      foreach ($localPort in $localPorts) {
        # Check if the port number or range is a wildcard
        if ($localPort -eq '*') {
          # If the port number or range is a wildcard, add an entry for all ports to the hash map
          $key = "ALLPORTS-$($outboundRule.Protocol)"
          $outboundRuleMap[$key] = $outboundRule
        }
        else {
          # If the port number or range is not a wildcard, add an entry for the port number or range to the hash map
          $key = "$localPort-$($outboundRule.Protocol)"
          $outboundRuleMap[$key] = $outboundRule
        }
      }
    }
    Write-Progress -Activity "Populating outbound rule map" -Completed
    Write-Debug "Populated outbound rule map"

    # Create an empty array to store the ports
    $ports = New-Object System.Collections.Generic.HashSet[UInt16]

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
          $wildcardKey = "ALLPORTS-$($inboundRule.Protocol)"

          if ($outboundRuleMap.ContainsKey($key) -or $outboundRuleMap.ContainsKey($wildcardKey)) {
            # If a matching outbound rule is found, add the port to the array
            if ('' -ne $localPort.Trim() -and $null -ne ($localPort -as [UInt16])) {
              $null = $ports.Add([UInt16]$localPort)
            }
          }
        }
      }
    }
    # Return the array of ports
    return $ports
  }

  function FindRulesByPort {
    param (
      [Parameter(Mandatory = $true)]
      [UInt16[]]$ports,
      [Parameter(Mandatory = $true)]
      [Microsoft.Management.Infrastructure.CimInstance[]]
      $portFilter,
      [string]$displayName
    )
    # $portFilter1 = if ($portFilter) { $portFilter } else { Get-NetFirewallPortFilter };
    $filteredFwRules = $portFilter | Where-Object { $ports -Contains $_.LocalPort } | Get-NetFirewallRule;
    if (-not $displayName) {
      return $filteredFwRules;
    }
    $ruleNames = $ports | ForEach-Object { "$displayName $_" };
    return $filteredFwRules | Where-Object { $ruleNames -Contains $_.DisplayName };
  }

  # function Get-AllFirewallPortRules {
  #   return Get-ExistingPorts | ForEach-Object { FindRulesByPort -port $_ };
  # }

  function Add-PortForwardFirewallRule {
    param (
      [Parameter(Mandatory = $true)]
      [string]$displayName,
      [Parameter(Mandatory = $true)]
      [UInt16]$port,
      [Parameter(Mandatory = $true)]
      [string]$addr,
      [Parameter(Mandatory = $true)]
      [string]$remoteport
    )

    try { 
      $resultDisplayName = "$displayName $port";
      $output = New-NetFireWallRule -DisplayName $resultDisplayName -Direction Outbound -LocalPort $port -Action Allow -Protocol TCP -ErrorAction stop;
      Write-Verbose ("Created outbound firewall rule:`n" + ($output | Format-List | Out-String));
      $output = New-NetFireWallRule -DisplayName $resultDisplayName -Direction Inbound -LocalPort $port -Action Allow -Protocol TCP -ErrorAction stop;
      Write-Verbose ("Created inbound firewall rule:`n" + ($output | Format-List | Out-String));
    }
    catch {
      throw "Failed to create firewall rules: $_"
    }
    try { 
      $null = netsh interface portproxy delete v4tov4 listenport=$port listenaddress=$addr;
      if ($LASTEXITCODE -eq 0) {
        Write-Verbose ("Deleted portproxy rule for port " + $port);
      }
      else {
        Write-Verbose ("No portproxy rule to delete for port " + $port);
      }
      $output = netsh interface portproxy add v4tov4 listenport=$port listenaddress=$addr connectport=$port connectaddress=$remoteport;
      if ($LASTEXITCODE -eq 0) {
        Write-Verbose ("Added portproxy rule for port " + $port);
      }
      else {
        throw "Failed to add portproxy rule for port $port. $output"
      }
    }
    catch {
      throw "Failed to configure port forwarding: $_"
    }
    Write-Host "+$resultDisplayName";
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

    $success = $false;
  
    try { 
      Remove-NetFireWallRule -DisplayName $resultDisplayName -ErrorAction Stop;
      $success = $true;
    }
    catch {
      Write-Verbose "Firewall rules could not be removed: $_"
    }
    $null = netsh interface portproxy delete v4tov4 listenport=$port listenaddress=$addr;
    if ($LASTEXITCODE -eq 0) {
      Write-Verbose ("Deleted portproxy rule for port " + $port);
      $success = $true;
    }
    else {
      Write-Verbose ("No portproxy rule to delete for port " + $port);
    }
    if ($success) {
      Write-Host "-$resultDisplayName";
    }
    else {
      Write-Warning "Could not remove port forwarding rule for port $port. It may not exist.";
    }
  }

  function CheckElevated {
    if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
      $PSCmdlet.ThrowTerminatingError([System.Management.Automation.ErrorRecord]::new([System.InvalidOperationException]::new("The script exited, please run the script as an administrator."), "ScriptRequiresElevation", [System.Management.Automation.ErrorCategory]::PermissionDenied, $null))
    }
  }

  #You can change the addr to your ip config to listen to a specific address
  $addr = '0.0.0.0';
  $firewallRuleName = 'WSL 2 Firewall Unlock';

  if (@('add', 'replace', 'ip', 'ipset') -contains $c) {
    if ($WslIp) {
      $remoteport = $WslIp;
    }
    elseif ($env:WslIp) {
      $remoteport = $env:WslIp;
      if ($c -ne 'iprm') {
        Write-Host "Using WSL IP from `$env:WslIp = $remoteport";
        Write-Information "You can remove it with the iprm command.";
      }
    }
    else {
      try {
        Write-Verbose "Getting the ip address of WSL...";
        # $remoteport = bash.exe -c "ip addr show eth0 | grep 'inet '"
        $remoteport = wsl.exe -e bash -noprofile -norc -c "ip addr show eth0 | sed -nr 's/^.*inet\s+(([0-9]{1,3}\.){3}[0-9]{1,3}).*$/\1/p'"
        if (-not $remoteport) {
          throw "Failed to get the ip address of WSL"
        }
      }
      catch {
        throw "Failed to get the ip address of WSL: $_"
      }
      finally {
        Write-Verbose "Got the ip address from WSL: $remoteport";
      }
      # $found = $remoteport -match '\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}';
      
      # if ($found) {
      #   $remoteport = $matches[0];
      # }
      # else {
      #   class NoWslIpException : System.Management.Automation.ErrorRecord {
      #     NoWslIpException() : base("Failed to match the ip address of WSL 2", "NoWslIpException", [System.Management.Automation.ErrorCategory]::NotSpecified, $null) {}
      #   }
      #   $PSCmdlet.ThrowTerminatingError([NoWslIpException]::new());
      # }
    }
  }
  if ($c -eq 'find') {
    $portFilter = Get-NetFirewallPortFilter;
  }
}
process {
  switch ($c) {
    'add' {
      CheckElevated;
      $existing_ports = Get-ExistingPorts -displayName $firewallRuleName
      $intersection = $p | Where-Object { $existing_ports -contains $_ }
      $ports_to_add = $p | Where-Object { $_ -notin $intersection }

      foreach ($port in $ports_to_add) {
        Add-PortForwardFirewallRule -displayName $firewallRuleName -port $port -addr $addr -remoteport $remoteport
      }
      return
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
      return
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
        Add-PortForwardFirewallRule -displayName $firewallRuleName -port $port -addr $addr -remoteport $remoteport
      }
      return
    }
    'ls' {
      # : List all forwarded WSL ports
      if (-not $a) {
        return Get-ExistingPorts -displayName $firewallRuleName
      }
      # -a: List all ports that have firewall rules
      return Get-FirewallTwowayPorts
    }
    'find' {
      CheckElevated;
      # -p: List all PFWSL specific firewall rules for the specified port(s)
      $output = @()
      if (-not $a) {
        return FindRulesByPort -ports $p -portFilter $portFilter -displayName $firewallRuleName
      }
      # -p -a: List all firewall rules for the specified port(s)
      return FindRulesByPort -ports $p -portFilter $portFilter
    }
    'ip' {
      return $remoteport
    }
    'ipset' {
      $env:WslIp = $remoteport
      Write-Host "Set WSL IP to `$env:WslIp = $remoteport"
      return
    }
    'iprm' {
      if (-not $env:WslIp) {
        Write-Host "WSL IP is not set in `$env:WslIp"
        return
      }
      Remove-Item Env:\WslIp
      Write-Host "Removed WSL IP from `$env:WslIp"
      return
    }
    default {
      $PSCmdlet.ThrowTerminatingError([System.Management.Automation.ErrorRecord]::new([System.InvalidOperationException]::new("Invalid command. Run `Get-Help $($PSCommandPath)` for more information."), "InvalidCommand", [System.Management.Automation.ErrorCategory]::InvalidOperation, $null))
    }
  }
}
end {
  return
}
