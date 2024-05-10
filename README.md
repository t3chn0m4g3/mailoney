![image](https://github.com/referefref/mailoney/assets/56499429/7ffe5426-61f2-4dba-ba86-df75ec8b1a54)


# About Mailoney-ng
- Mailoney is a modular STMP honeypot written by [***Brandon E***](https://github.com/phin3has) in Python.
- The original version relied upon several libraries and functions that are no longer provided by modern Python3 which required significant code refactoring to make operational.
- There exists some bugs still with shellcode emulation which are being ironed out, and some regression testing is required to ensure no features were lost in the refactoring - particularly within the schizo_open_relay module originally written by [***@botnet_hunter***](https://twitter.com/botnet_hunter)
- This is maintained as a fork for now due to it's significant divergence from the original

# Installation
This has only been tested with docker
```
git clone https://github.com/referefref/mailoney.git
cd mailoney
docker compose up -d
```

# Usage

```
usage: mailoney.py [-h] [-i IP] [-p PORT] [-s SERVERNAME] -t {open_relay,postfix_creds,schizo_open_relay} [-logpath LOGPATH]
                   [-hpfserver HPFSERVER] [-hpfport HPFPORT] [-hpfident HPFIDENT] [-hpfsecret HPFSECRET]
                   [-hpfchannelprefix HPFCHANNELPREFIX]

Configure the SMTP Honeypot settings

options:
  -h, --help            show this help message and exit
  -i IP, --ip IP        IP address to listen on
  -p PORT, --port PORT  Port to listen on
  -s SERVERNAME, --servername SERVERNAME
                        Mail server name
  -t {open_relay,postfix_creds,schizo_open_relay}, --type {open_relay,postfix_creds,schizo_open_relay}
                        Type of honeypot to deploy
  -logpath LOGPATH      Path for logging
  -hpfserver HPFSERVER  HPFeeds server address
  -hpfport HPFPORT      HPFeeds server port
  -hpfident HPFIDENT    HPFeeds identifier
  -hpfsecret HPFSECRET  HPFeeds secret
  -hpfchannelprefix HPFCHANNELPREFIX
                        Prefix for HPFeeds channels
```
---
---

# The following are original notes from the core repo

### Types
Right now there are three types of Modules for Mailoney. 
- open_relay - Just a generic open relay, will attempt to log full text emails attempted to be sent. 
- postfix_creds - This module simply logs credentials from logon attempts. 
- schizo_open_relay - This module logs everything, developed by [@botnet_hunter](https://twitter.com/botnet_hunter)

# Running 
SMTP ports 25, 465, 587 are privileged ports and therefore require elevated permissions (i.e. Sudo). It is probaby not a good idea to run your honeypot with elevated permissions. As such, I **strongly** encourage you to use port forwarding. 

Setting this up is easy, lets say we want to run Mailoney on port 2525 (a nice non-priveleged port). 
#### IPTables example
We can redirect port 25 to port 2525 with IPtables:
`$ sudo iptables -t nat -A PREROUTING -p tcp --dport 25 -j REDIRECT --to-port 2525`

#### UFW example
If you are using UFW, you can edit *before.rules* (`/etc/ufw/before.rules`) by adding the following to the beginning:
```
*nat
-F
:PREROUTING ACCEPT [0:0]
-A PREROUTING -p tcp --dport 25 -j REDIRECT --to-port 2525
COMMIT
```
Then run `ufw reload` and you are all set. 

# ToDo 
 - [ ] Add modules for EXIM, Microsoft, others
 - [X] Build in Error Handling
 - [X] ~~Add a Daemon flag to background process.~~
 - [X] ~~Secure this by not requiring elevated perms, port forward from port 25.~~
 - [ ] Database logging
 - [ ] Possible relay for test emails. 
 - [X] ~~Make honeypot detection more difficult~~
