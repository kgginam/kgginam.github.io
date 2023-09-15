---
title: "Lord of SQLInjection - VAMPIRE"
categories: 
  - SQLi
tags:
  - SQLi
  - 웹해킹
toc: true
---

# VAMPIRE
## 문제 
![img](/assets/images/los/vampire1.png)

- id값을 소문자로 변경한 후 admin 문자를 빈 문자로 치환하는 문제다.

## 정답
![img](/assets/images/los/vampire2.png)

- admadmin와 같이 입력하면 str_replace 함수를 거치면서 중간의 admin이 빈 문자열로 치환되면서 adm(admin)in의 괄호 안의 admin이 제거되고 admin이 남는다.
