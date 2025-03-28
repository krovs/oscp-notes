# 📃 Password Attacks

## Detect hash type

```shell
hashid <hash>
```

## Hashcat

> [Hashcat module numbers](https://hashcat.net/wiki/doku.php?id=example_hashes)

```shell
# find hash module number
hashcat -h | grep Kerberos

hashcat -m <id> <hash> <wordlist> --force
# use a rule
hashcat -m <id> <hash> <wordlist> -r /usr/share/hashcat/rules/rockyou-3000.rule --force
# show mutated list of password using a rule
hashcat -r demo.rule --stdout <wordlist>
```

### Hashcat rule set

```shell
$X   # Append character X
^X   # Prepend character X
iNX  # Insert character X at position N
DN   # Delete character at position N
rXY  # Replace character X with Y
TN   # Truncate password to length N
tN   # Toggle case of character at position N
u    # Convert entire password to uppercase
l    # Convert entire password to lowercase
d    # Duplicate the password
r    # Reverse the password
sXY  # Swap character X with Y
X    # Remove last character
$    # Append a space
^    # Prepend a space
```

## John

> [John extractors](https://github.com/openwall/john/tree/bleeding-jumbo/run)

```shell
john <hash> --wordlist=<wordlist>

# to use rules add them to /etc/john/john.conf with a header
[List.Rules:sshRules]
c $1 $3 $7 $!
c $1 $3 $7 $@
c $1 $3 $7 $#

# use it like
john <hash> --wordlist=<wordlist> --rules=sshRules

# extract hashes from encrypted files
keepass2john file.kdbx > keepass.hash
ssh2john id_rsa > ssh.hash
```

## Zip files

```shell
fcrackzip -u -D -p <wordlist> <file>.zip
```
