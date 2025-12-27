---
title: "Sobata - CryptoCTF"
date: 2025-12-27
hero: /images/posts/writing-posts/code.svg
menu:
  sidebar:
    name: Sobata
    identifier: cryptoctf-2025-sobata
    parent: cryptoctf-2025
    weight: 7
---

For this challenge, we are given the file `sobata.sage` and a remote instance that runs this script. First, the challenge creates a set of parameters:

```python
nbit = 512
parameters = gen_params(nbit)
E = parameters[1]
m = bytes_to_long(FLAG)
assert m < parameters[0]
```

and this is the `gen_params` function:

```python
def gen_params(nbit):
	while True:
		p = getPrime(nbit)
		if p % 6 == 1:
			F = GF(p)
			R = [F.random_element() for _ in '01']
			a, b = [R[_] ** ((p - 1) // (3 - _)) for _ in [0, 1]]
			if a != 1 and b != 1:
				c, d = [F.random_element() for _ in '01']
				E = EllipticCurve(GF(p), [0, d])
				return (p, E, a, b, c)
```

So the challenge computes a random prime numer $p$ that satisifes $p \equiv 1 \ (mod \ p)$, a random number $c$, an elliptic curve $E: y^2 = x^3 + d$ over $\mathbb{Z}_p$ and two non-trivial numbers $a$ and $b$ such that $a^3 \equiv 1 \ (mod \ p)$ and $b^2 \equiv 1 \ (mod \ p)$. That is, $a$ is a cubic root of unity and $b$, a square root of unity.

Then, the flag is encoded as a point in the curve:

```python
while True:
  try:
    P = E.lift_x(m)
    break
  except:
    m += 1
```

Then, there is this interactive menu (skipping validity checks):

```python
while True:
    pr("| Options: \n|\t[E]ncrypted FLAG \n|\t[W]alking with P \n|\t[J]umping over P \n|\t[Q]uit")
    if ans == 'e':
        _P = walk(P, parameters)
        pr(border, f'The encrypted flag is: {_P.xy()}')
    elif ans == 'w':
        pr(border, 'Please send your desired point over E: ')
        Q = sc().decode().strip().split(',')
        Q = [int(_) for _ in Q]
        if Q in E:
            pr(border, f'The result of the walk is: {walk(E(Q), parameters).xy()}')
    elif ans == 'j':
        pr(border, 'Send your desired point over E: ')
        Q = sc().decode().strip().split(',')
        pr(border, 'Let me know how many times you would like to jump over the given point: ')
        n = sc().decode().strip()
        if Q in E:
            pr(border, f'The result of the jump is: {jump(E(Q), n, parameters).xy()}')
```

And these are the `walk` and `jump` functions:

```python
def walk(P, parameters):
	p, E, a, b, c = parameters
	x, y = P.xy()
	Q = (a * x, b * y)
	assert Q in E
	return int(c) * E(Q)

def jump(P, n, parameters):
	_parameters = list(parameters)
	_parameters[-1] = pow(int(_parameters[-1]), n, _parameters[1].order())
	return walk(P, _parameters)
```

Expressed in mathematical terms, the challenge defines a map $\phi : E \rightarrow E$ such that $\phi(P) = (aP_x, bP_y)$. It is trivial to check that this map is well defined and also, it maps the origin to itself. Taking this into account and that $\phi$ is a rational map, we can conclude that $\phi$ is an endomorphism.

The `walk` function computes $c\cdot\phi(P)$ for a given $P \in E$. The `jump` function computes $c^n \cdot \phi(P)$, for a given $n \in \mathbb{Z}_p$ and $P \in E$. Besides, the flag is encrypted as the result of the `walk` function.

The fact that $\phi$ is an endomorphism is key for this challenge, as it lets us take out $c$ from consecutive applications of `walk` or `jump`. For instace, if we apply twice the `walk` function on a point $P$, we get:
$$\text{walk}(\text{walk}(P)) = c \cdot \phi(c\cdot \phi(P))$$
If $\phi$ wasn't an endomorphism, this would be a hard expression to work with. Thankfully, this expression can be simplified to:
$$\text{walk}(\text{walk}(P)) = c^2 \phi(\phi(P)) = c^2 (a^2 P_x, P_y)$$

Taking all of this into account, we could recover the flag (equivalently, the encoded point of the curve) by doing this set of operations:

- Get the encrypted flag: $c \cdot\phi(P)$
- Jump using $n = -1$: $c^{-1} \cdot \phi(c \cdot \phi(P)) = \phi(\phi(P))$
- Jump using $n = 0$: $c^0 \cdot \phi(\phi(\phi(P))) = \phi(\phi(\phi(P))) = (a^3P_x, b^3P_y) = (P_x, bP_y)$

And the flag is the value $P_x$. We can automate this using this script:

```python
from sage.all import *
from pwn import *
from Crypto.Util.number import *

r = process("./sobata.sage")

r.sendlineafter(b"[Q]uit\n", b"E")
r.recvuntil(b"The encrypted flag is: (")
enc_flag = list(map(int, r.recvuntil(b")")[:-1].decode().split(",")))

r.sendlineafter(b"[Q]uit\n", b"J")
r.recvline()
r.sendline(",".join(map(str, enc_flag)).encode())
r.recvline()
r.sendline(b"-1")
r.recvuntil(b"jump is: (")
jump = list(map(int, r.recvuntil(b")")[:-1].decode().split(",")))

r.sendlineafter(b"[Q]uit\n", b"J")
r.recvline()
r.sendline(",".join(map(str, jump)).encode())
r.recvline()
r.sendline(b"0")
r.recvuntil(b"jump is: (")
flag = list(map(int, r.recvuntil(b")")[:-1].decode().split(",")))

print(long_to_bytes(flag[0]))
```
Flag: `CCTF{L1n3Ari7y_iN_w4lkIn9_ECC!}`