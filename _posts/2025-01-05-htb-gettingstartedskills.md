---
title: "HTB-Getting Started"
categories: 
  - hackthebox
  - pentesting
  - CPTS
tags:
  - pentesting
toc: true
---

# 개요

- CPTS 자격증 준비 첫단계의 단원 마무리 박스

# nmap

- ssh, http 포트가 오픈된 것으로 확인됨

![img](/assets/images/htb/gettingstarted/nmap.png)

# web access

- http 접속 시 gettingstarted.htb 라는 도메인이 보임

![img](/assets/images/htb/gettingstarted/start.png)

# /etc/hosts 파일 수정

> sudo nano /etc/hosts

![img](/assets/images/htb/gettingstarted/hosts.png)

# 해당 도메인에 대해 ffuf 수행

> ffuf -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt:FUZZ -u hxxp://gettingstarted.htb/FUZZ

![img](/assets/images/htb/gettingstarted/ffuf.png)

- ffuf로 열거된 디렉터리 접속시 해당 사이트에 admin에 대한 접속 정보가 존재

![img](/assets/images/htb/gettingstarted/adminxml.png)

# 해당 비밀번호의 해시 정보 확인

![img](/assets/images/htb/gettingstarted/hashid.png)

# 해당 해시 알고리즘으로 패스워드 사전 공격 진행

> hashcat -a 0 -m 100 hash.txt /usr/share/wordlists/rockyou.txt

![img](/assets/images/htb/gettingstarted/hashcat.png)

# 사이트 접속 후 revsere shell 실행 및 연결

![img](/assets/images/htb/gettingstarted/phprevshell.png)

- 브라우저로 template.php 접속

![img](/assets/images/htb/gettingstarted/nc.png)

# sudo 권한 확인

- php를 root 권한으로 실행 가능한 것을 알 수 있음
- gtfobins의 php sudo 사용
- root 권한의 쉘 획득

![img](/assets/images/htb/gettingstarted/sudophp.png)
