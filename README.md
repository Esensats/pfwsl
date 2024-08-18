# PFWSL & PFW <!-- omit in toc -->

![image](https://github.com/user-attachments/assets/7d247f36-a301-426d-a14f-aed618dd476e)

[**PFWSL**](./bin/pfwsl.ps1) (_Port Forward + FireWall + WSL_) is a tool that helps you manage portproxy and firewall rules when working with WSL.

[**PFW**](./bin/pfw.ps1) (_Port Forward + FireWall_) is the same tool but without portproxy rules. It helps when you just want to manage two-way port forwarding rules without touching Windows horrible firewall settings GUI.

One example use case of `pfwsl` is working on web services inside WSL. If you want to access the web service from other hosts in the network you'll have to port forward the used ports. Without this tool, you'd need to find the needed WSL IP address, write `netsh` commands and finally add Firewall rules using `wf.msc` GUI. With `pfwsl` you can just write `pfwsl add 3000` and it'll do all of that for you.

It also has multiple bonus features, like searching for all ports that have two-way (both inbound and outbound) firewall rules within your system. It is impossible to do so using the standard Windows tooling.

## Table Of Contents <!-- omit in toc -->

- [Installation](#installation)
- [Usage](#usage)
- [PFWSL](#pfwsl)
  - [Commands](#commands)
  - [Usage examples](#usage-examples)
- [PFW](#pfw)
- [Screenshots](#screenshots)
- [Contribution](#contribution)
- [Credits](#credits)

## Installation

Clone the repo to a suitable location and add the [`bin/`](./bin) folder to PATH.

## Usage

Launch a terminal as administrator (or use something like [`gsudo`](https://github.com/gerardog/gsudo)) and use `pfwsl` like this:

```powershell
pfwsl ls -a # List all ports that have two-way firewall rules.
pfwsl add 3000 # Add firewall two-way rules and netsh
               # portproxy rules for ports 8080 and 8081.
pfwsl rm 3000 # Remove the rule
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
  pfwsl [-c] {add|replace} [-p] <port>[,<port>]... [-WslIp <WSL_IP_Address>]
  pfwsl [-c] {find} [-p] <port>[,<port>]... [-a]
  pfwsl [-c] {rm} [-p] [<port>[,<port>]...]
  pfwsl [-c] {ls} [-a]
  pfwsl [-c] {ip|iprm}
  pfwsl [-c] {ipset} -WslIp <WSL_IP_Address>
#>
```

### Commands

Parameter `-c` is the command to execute. Valid commands are `add`, `rm`, `replace`, `ls`, `find`, `ip`, `ipset` and `iprm`.
- `add [-p] <port>[,<port>]...`: Add port forwarding rules.
  - `-p` - the port(s) to add.
- `rm [[-p] <port>[,<port>]...]`: Remove port forwarding rules.
  - `-p` - the ports to remove. If empty, all ports that were added with `pfwsl` will be removed.
- `replace [-p] <port>[,<port>]...`: Replace all of the existing port forwarding rules with the new rules.
  - `-p` - the new ports in question.
- `ls [-a]`:
  - `ls` - List all ports that have two-way firewall rules *created by `pfwsl`*.
  - `ls -a` - List all ports that have two-way firewall rules. Takes a while.
- `find [-p] <port>[,<port>]... [-a]`: Find existing port forwarding rules for the specified port(s).
  - `-p` - the ports in question
  - `-a` - if the flag is supplied, it will find all rules related to specified ports. If it's not supplied, it will only search within rules that were created by `pfwsl`.
- `ip`: Get the WSL IP address the script is using ($env or automatic).
- `ipset -WslIp <WSL_IP_Address>`: Set the WSL IP address manually (persistent, added to `$env`). Useful when the script cannot detect the needed IP address or if it's too slow.
- `iprm`: Remove the manually set WSL IP address from `$env`. 

### Usage examples

See [#screenshots](#screenshots) for examples.

```powershell
<#
.EXAMPLE
  pfwsl -c add -p 8080
  Add a port forwarding rule for port 8080.
.EXAMPLE
  pfwsl -c add -p 8080,8081
  Add port forwarding rules for ports 8080 and 8081.
.EXAMPLE
  pfwsl -c rm -p 8080
  Remove the port forwarding rule for port 8080.
.EXAMPLE
  pfwsl -c rm
  Remove all port forwarding rules.
.EXAMPLE
  pfwsl -c replace -p 8080,8081
  Replace the existing port forwarding rules with the new rules for ports 8080 and 8081.
.EXAMPLE
  pfwsl -c ls
  List the existing port forwarding rules.
.EXAMPLE
  pfwsl -c ls -a
  List all ports that have two-way firewall rules (takes a while to execute).
.EXAMPLE
  pfwsl -c find -p 8080,8081
  Find the existing port forwarding rules for ports 8080 and 8081.
.EXAMPLE
  pfwsl -c find -p 8080,8081 -a
  List all firewall rules for ports 8080 and 8081.
.EXAMPLE
  pfwsl -c ip
  List all firewall rules for ports 8080 and 8081.
#>
```

## PFW

I use it to forward ports to the outside of the host machine. It frees me from the burden of using Windows horrible GUI every time I want to forward a port. It differs from `pfwsl` by not using `netsh` and not adding `portproxy` rules, meaning it doesn't affect WSL at all.

Usage is almost the same as `pfwsl`. Use `Get-Help pfw` and `Get-Help pfw -Examples` for more info or just check [`pfw.ps1`](./bin/pfw.ps1) source.

## Screenshots

![image](https://github.com/user-attachments/assets/68ea333e-a1ad-452e-ac1b-cde9216c7b1c)

## Contribution

PowerShell is an interpreted language so it's trivially simple to contribute.
I welcome all contribution so as always, just make a PR or an issue and I'll review it as soon as I have time.

## Credits

Original idea from [@edwindijas](https://github.com/edwindijas) from [this WSL issue](https://github.com/microsoft/WSL/issues/4150#issuecomment-504209723)
