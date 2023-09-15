---
title: "Lord of SQLInjection - DARKELF"
categories: 
  - SQLi
tags:
  - SQLi
  - 웹해킹
toc: true
---

# DARKELF
## 문제
![img](/assets/images/los/darkelf1.png)

- 이 문제는 or 와 and를 필터링 하는 문제다.
- or는 ||, and는 &&으로 우회할 수 있다.

## 정답
![img](/assets/images/los/darkelf2.png)

- pw=' || id='admin'%23 입력
