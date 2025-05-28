# 📃 Password Attacks

## Detect hash type

```shell
hashid <hash>
```

## Cracking Hashes

### Hashcat

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

#### Hashcat rule set

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

### John

> [John extractors](https://github.com/openwall/john/tree/bleeding-jumbo/run)

```shell
john <hash> --wordlist=<wordlist>

# show subformats
john --list=subformats

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

### Zip files

```shell
fcrackzip -u -D -p <wordlist> <file>.zip
```

## Common Password Guessing Tactics

| **Tactic**                               | **Example**                                                               |
| ---------------------------------------- | ------------------------------------------------------------------------- |
| Year/Number Iteration                    | Change years (`Pass2023` -> `Pass2024`) or numbers (`Pass1` -> `Pass2`).  |
| Username as Password                     | `username:username` or variations (`Username123`, `username!`)            |
| Company/Service Name + Seasons/Suffix    | `CompanySpring24`, `Servicewinter`, `PasswordSummer25`                    |
| Company/Service Name + Year/Suffix       | `CompanyName2024`, `ServiceName!`, `Acme123`                              |
| Common Suffixes/Prefixes                 | Add `!`, `@`, `#`, `123` to known words/usernames                         |
| Default Credentials                      | Always check for software/appliance defaults (`admin:admin`, `root:toor`) |
| Simple/Common Passwords                  | `password`, `welcome`, `test`, `123456`, `secret`                         |
| Credential Reuse                         | Try compromised credentials on other services                             |
| Blank Passwords                          | Attempt login with just the username                                      |
| Keyboard Patterns                        | `qwerty`, `12345`                                                         |
| Leetspeak                                | Simple substitutions (`p@$$w0rd`)                                         |

## Wordlist Generator

### Cewl

Create a wordlist from a website.

```shell
cewl <url> -w <wordlist>
```

### Cupp

> <https://github.com/Mebus/cupp>

```shell
cupp -i
```
