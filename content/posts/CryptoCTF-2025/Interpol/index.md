---
title: "Interpol - CryptoCTF"
date: 2025-12-24
hero: /images/posts/writing-posts/code.svg
menu:
  sidebar:
    name: Interpol
    identifier: cryptoctf-2025-interpol
    parent: cryptoctf-2025
    weight: 2
---

In this challenge, we are given two files: `interpol.sage` and `output.raw`. This is the challenge's code:

```sage
from Crypto.Util.number import *
from flag import flag

def randpos(n):
	if randint(0, 1):
		return True, [(-(1 + (19*n - 14) % len(flag)), ord(flag[(63 * n - 40) % len(flag)]))]
	else:
		return False, [(randint(0, 313), (-1) ** randint(0, 1) * Rational(str(getPrime(32)) + '/' + str(getPrime(32))))]

c, n, DATA = 0, 0, []
while True:
	_b, _d = randpos(n)
	H = [d[0] for d in DATA]
	if _b:
		n += 1
		DATA += _d
	else:
		if _d[0][0] in H: continue
		else:
			DATA += _d
			c += 1
	if n >= len(flag): break

A = [DATA[_][0] for _ in range(len(DATA))]
poly = QQ['x'].lagrange_polynomial(DATA).dumps()
f = open('output.raw', 'wb')
f.write(poly)
f.close()
```

The challenge creates an array whose entries are the `(x,y)` coordinates of rational points. Every time a new point is added to the array, there are two possibilities:

- A new point encoding a character of the flag is added to the array 
- A new random point is added to the array

After all the characters of the flags have been added to the array, the lagrange polynomial interpolating the points is created and saved in `output.raw`. We need to be able to disntiguish between flag points and random points. 

The most straightforward way to do this is to guess the flag's length and reverse the `randpos` function. This is the code to solve the challenge:

```python
pol = loads(open('output.raw', 'rb').read())
for l in range(1, pol.degree()):
    flag = ["*"] * l
    for n in range(l):
        try:
            flag[(63 * n - 40) % l] = chr(int(pol(-(1 + (19*n - 14) % l))))
            candidate_flag = ''.join(flag)
            if candidate_flag.startswith('CCTF{') and candidate_flag.endswith('}'):
                print(candidate_flag)
                break
        except:
            break

```

Flag: `CCTF{7h3_!nTeRn4t10naL_Cr!Min41_pOlIc3_0r9An!Zati0n!}`