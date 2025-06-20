# ⚔️ OSCP & eCPPTv3 Exam Notes

**🍕 Web version**: [https://krovs.github.io/oscp-notes](https://krovs.github.io/oscp-notes/)

**🤖 Writeups**: [https://krovs.github.io/oscp-writeups](https://krovs.github.io/oscp-writeups/)

<div align="center">
    <img src=docs/assets/banner.png>
</div>

## 🦩 Notes

- [🦩 Home](docs/index.md)
- [🔍 Information Gathering](docs/10_information_gathering.md)
- [🕷️ Web Application Attacks](docs/11_web_attacks.md)
- [🎣 Client-Side Attacks](docs/12_client-side_attacks.md)
- [💣 Exploitation](docs/13_exploitation.md)
- [📃 Password Attacks](docs/14_passwords_attacks.md)
- [📎 Windows Privilege Escalation](docs/15_windows_privesc.md)
- [🐧 Linux Privilege Escalation](docs/16_linux_privesc.md)
- [🚢 Port Redirection and Tunneling](docs/17_port_redirection_tunneling.md)
- [🔭 AD Enumeration](docs/18_ad_enum.md)
- [⚔️ AD Exploitation](docs/19_ad_exploitation.md)
- [🏹 AD Lateral Movement](docs/20_ad_lateral_mov.md)

## 📚 Study Resources

- [PWK Course](https://portal.offsec.com/courses/pen-200-44065/overview)
- Hackthebox Academy:
  - [Pivoting, Tunneling and Port Forwarding](https://academy.hackthebox.com/module/details/158)
  - [Introduction to AD](https://academy.hackthebox.com/module/details/74)
  - [Active Directory Enumeration and Attacks](https://academy.hackthebox.com/module/details/143)
- PortSwigger Academy:
  - [Error-Based and Union-Based SQL Injection](https://portswigger.net/web-security/sql-injection)
  - [Stored, Reflected and DOM-Based Cross-Site Scripting](https://portswigger.net/web-security/cross-site-scripting)
  - [Command Injection](https://portswigger.net/web-security/command-injection)
- TryHackme:
  - [Linux PrivEsc Room](https://tryhackme.com/r/room/linuxprivesc)
  - [Windows PrivEsc Room](https://tryhackme.com/r/room/windows10privesc)

## 🤖 Machines

- [PWK Challenges](https://portal.offsec.com/courses/pen-200-44065/labs)
- [LainKusanagi's List of OSCP-like Machines](https://docs.google.com/spreadsheets/d/18weuz_Eeynr6sXFQ87Cd5F0slOj9Z6rt)
  - [Proving Grounds Practice](https://portal.offsec.com/labs/practice)
  - [HackTheBox](https://app.hackthebox.com)
  - [TryHackMe](https://tryhackme.com)

## 📝 Reporting

### Sysreptor

#### Free Online version

<https://docs.sysreptor.com/offsec-reporting-with-sysreptor/>

#### Self-Hosted

<https://docs.sysreptor.com/setup/installation/>

```shell
# downloads and deploys the containers
bash <(curl -s https://docs.sysreptor.com/install.sh)
```

Adding offsec templates to sysreptor:

```shell
cd sysreptor/deploy
url="https://docs.sysreptor.com/assets/offsec-designs.tar.gz"
curl -s "$url" | docker compose exec --no-TTY app python3 manage.py importdemodata --type=design
```

-----------------------

**Note**:
🔒 All content is for educational purposes only. Always hack responsibly and with permission.
