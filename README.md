# PFWSL & PFW

[**PFWSL**](./bin/pfwsl.ps1) (_Port Forward + FireWall + WSL_) is a tool that helps you manage portproxy and firewall rules when working with WSL.

[**PFW**](./bin/pfw.ps1) (_Port Forward + FireWall_) is the same tool but without portproxy rules. It helps when you just want to manage your Firewall.

## Installation

Clone the repo to a suitable location and add the [`bin/`](./bin) folder to PATH.

## Usage

Launch a terminal as administrator (or use something like [`gsudo`](https://github.com/gerardog/gsudo)) and use `pfwsl` like this:

```powershell
pfwsl ls -a # List all ports that have two-way firewall rules.
pfwsl add 3000 # Add firewall two-way rules and netsh
               # portproxy rules for ports 8080 and 8081.
pfw add 8080,8081 # Add firewall two-way rules for ports 8080 and 8081.

Get-Help pfwsl # Get help with pfwsl
Get-Help pfwsl -Examples # Check out usage examples
```

## PFWSL

This script allows you to add, remove, replace, and list port forwarding rules for WSL 2.
It uses the Windows Firewall and `netsh` to manage the port forwarding rules.
It requires administrator privileges to add or remove port forwarding rules.

```powershell
<#
  SYNTAX:
  pfwsl [-c] {add|replace|find} [-p] <port>[,<port>]...
  pfwsl [-c] {rm} [-p] [<port>[,<port>]...]
  pfwsl [-c] {ls} [-a]
  pfwsl [-c] {ip|iprm}
  pfwsl [-c] {ipset} [-WslIp] <WSL_IP_Address>
#>
```

### Commands

Parameter `-c` is the command to execute. Valid commands are `add`, `rm`, `replace`, `ls`, `find`, `ip`, `ipset` and `iprm`.
- `add [-p] <port>[,<port>]...`: Add port forwarding rules.
  - `-p` - the port(s) to add.
- `rm [[-p] <port>[,<port>]...]`: Remove port forwarding rules.
  - `-p` - the ports to remove. If empty, all ports that were added with `pfwsl` will be removed.
- `replace [-p] <port>[,<port>]...`: Replace all of the existing port forwarding rules with the new rules.
  - `-p` - the new ports in question
- `ls [-a]`:
  - `ls` - List all ports that have two-way firewall rules *created by `pfwsl`*.
  - `ls -a` - List all ports that have two-way firewall rules.
- `find`: Find the existing port forwarding rules for the specified port(s).

### Usage examples

```powershell
<#
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
#>
```

## Contribution

PowerShell is an interpreted language so it's trivially simple to contribute.
I welcome all contribution so as always, just make a PR or an issue and I'll review it as soon as I have time.
