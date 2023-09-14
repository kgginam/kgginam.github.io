---
title: "Lord of SQLInjection - GOBLIN"
categories: 
  - SQLi
tags:
  - SQLi
  - 웹해킹
toc: true
---

# GOBLIN
## 문제 
![img](/assets/images/los/goblin1.png)
- id 가 guest로 고정된 쿼리에서 admin을 조회하는 문제다.
- 따옴표(', ", \`)를 필터링 하고 있다.
- id로 정렬해서 풀 수 있다.

## 정답
![img](/assets/images/los/goblin2.png)
- no=1 or 1=1 order by 1 입력
- no의 조건을 1=1로 전체 조회 한 후 order by 1을 통해 id컬럼으로 정렬한다.
