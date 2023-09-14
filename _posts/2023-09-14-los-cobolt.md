---
title: "Lord of SQLInjection - COBOLT"
categories: 
  - SQLi
tags:
  - SQLi
  - 웹해킹
toc: true
---

# COBOLT
## 문제
![img](/assets/images/los/cobolt1.png)
- admin이 조회되도록 하는 문제다.
- id에 admin을 입력하고 뒷부분을 주석처리하면 풀린다.
## 정답
![img](/assets/images/los/cobolt2.png)
- id=admin'%23&pw= 입력
- 주의할 점은 #은 %23으로 입력해야 한다.
