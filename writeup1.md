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
