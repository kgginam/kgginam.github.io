---
title: "Lord of SQLInjection - GREMLIN"
categories: 
  - SQLi
tags:
  - SQLi
  - 웹해킹
toc: true
---

# GREMLIN
## 문제 
![img](/assets/images/los/gremlin1.png)
- GET 요청으로 들어온 id, pw로 db에 존재하는 id를 조회하는 쉬운 문제다.
- 어떤 id라도 조회하면 되기 때문에 or 1=1을 사용해서 풀어보자

## 정답
![img](/assets/images/los/gremlin2.png)
- 쿼리 스트링 부분을 url decoding하면 id='or'1'='1&pw='or'1'='1이 된다.
