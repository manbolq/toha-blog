---
title: "Ikkyu San - CryptoCTF"
date: 2025-12-27
hero: /images/posts/writing-posts/code.svg
menu:
  sidebar:
    name: Ikkyu San
    identifier: cryptoctf-2025-ikkyu-san
    parent: cryptoctf-2025
    weight: 11
---

For this challenge, we are given the file `Ikkyu_san.sage`. First, it generates some parameters:

```python
def Ikkyu(nbit):
	p = getPrime(nbit)
	while True:
		a, b = [randint(1, p - 1) for _ in range(2)]
		E = EllipticCurve(GF(p), [a, b])
		G, H = [E.random_point() for _ in range(2)]
		try:
			I = E.lift_x(1)
		except:
			if legendre_symbol(b - a - 1, p) < 0:
				return p, E, G, H

nbit = 256
pr(border, f'Generating parameters, please wait... ')
p, E, G, H = Ikkyu(nbit)
F = GF(p)
```

Then, the main loop goes as follows:

```python
while True:
    pr(f"{border} Options: \n{border}\t[E]ncrypted flag!\n{border}\t[R]andom point\n{border}\t[G]et Ikkyu-san point!\n{border}\t[Q]uit")
    ans = sc().decode().strip().lower()
    if ans == 'g':
        pr(border, f"Please provide your desired point `P` on elliptic curve E like x, y: ")
        xy = sc().decode()
        try:
            x, y = [F(int(_)) for _ in xy.split(',')]
            P = E(x, y)
        except:
            pr(border, f"The input you provided is not valid!")
            P = E.random_point()
        pr(border, f'{fongi(G, H, P) = }')
    elif ans == 'r':
        pr(border, f'{E.random_point() = }')
    elif ans == 'e':
        m = bytes_to_long(flag)
        assert m < p
        pr(border, f'{m * G.xy()[0] * H.xy()[1] = }')
    elif ans == 'q':
        die(border, "Quitting...")
    else:
        die(border, "Bye...")
```

First, note the "R" option. Using this options several times in a row, we can recover the elliptic curve $E$ and the prime number $p$. Let's do that first. Let $E : y^2 = x^3 + ax + b$ be the elliptic curve and $P, Q, R \in E$ distinct points on the curve. In the following, keep in mind that operations are performed modulo $p$, but it is ommitted for clarity:

$$P_y^2 - P_x^3 - a P_x = b$$
$$Q_y^2 - Q_x^3 - a Q_x = b$$
$$R_y^2 - R_x^3 - a R_x = b$$

Therefore,

$$P_y^2 - P_x^3 - a P_x = Q_y^2 - Q_x^3 - a Q_x \implies (P_y^2 - P_x^3) - (Q_y^2 - Q_x^3) = a(P_x - Q_x)$$
$$P_y^2 - P_x^3 - a P_x = R_y^2 - R_x^3 - a R_x \implies (P_y^2 - P_x^3) - (R_y^2 - R_x^3) = a(P_x - R_x)$$

Thus,

$$[(P_y^2 - P_x^3) - (Q_y^2 - Q_x^3)] (P_x - Q_x)^{-1} = [(P_y^2 - P_x^3) - (R_y^2 - R_x^3)] (P_x - R_x)^{-1}$$

And finally,

$$[(P_y^2 - P_x^3) - (Q_y^2 - Q_x^3)] (P_x - R_x) = [(P_y^2 - P_x^3) - (R_y^2 - R_x^3)] (P_x - Q_x)$$

Recall that this equality is modulo $p$, meaning that the difference of both sides is a multiple of $p$. Taking many triplets of random points and taking the GCD on that difference, we can recover the prime $p$:

```python
def get_random_point(r):
    r.sendlineafter(b"[Q]uit\n", b"R")
    r.recvuntil(b"E.random_point() = ")
    line = r.recvline().decode().strip()
    x = int(line.split()[0][1:])
    y = int(line.split()[2])
    return x, y

def recover_p(r):
    ts = []
    for _ in range(7):
        points = []
        for _ in range(3):
            x, y = get_random_point(r)
            points.append((x, y))
        s = [p[1]**2 - p[0]**3 for p in points]
        ti = (points[0][0] - points[2][0])*(s[0] - s[1]) - (points[0][0]-points[1][0])*(s[0] - s[2])
        ts.append(ti)
    
    p = gcd(ts)
    assert isPrime(p), "Recovered p is not prime!"
    return p
```

Once we have $p$, we need two points on $E$ to fully recover both $a$ and $b$, doing a similar math process:

```python
def recover_params(p, x1, y1, x2, y2):
    a = pow(x1 - x2, -1, p) * (pow(y1, 2, p) - pow(y2, 2, p) - (pow(x1, 3, p) - pow(x2, 3, p))) % p
    b = (pow(y1, 2, p) - pow(x1, 3, p) - a * x1) % p
    return int(a), int(b)

def get_elliptic_curve(r, p):
    P = get_random_point(r)
    Q = get_random_point(r)
    params = recover_params(p, P[0], P[1], Q[0], Q[1])
    a, b = params
    F = GF(p)
    E = EllipticCurve(F, [a, b])
    return E
```

The next step is to find the points $G$ and $H$, so that we can recover the flag from the value obtained from the "E" option. This is the `fongi` function:

```python
def fongi(G, H, P):
	try:
		xG, xP, yP = G.xy()[0], P.xy()[0], P.xy()[1]
	except:
		xP = 1337
	return int(xP) * G + int(yP) * H + int(xG) * P
```

When the server calls this function, we control the point $P$. Let's pick a point $P \in E$ of order 2. A point $P$ has order 2 (i.e. $2P = \mathcal{O}$) if and only if $P = -P \iff (x, y) = (x, -y) \iff y = 0$, and this is why we are interested in these points. However, not all the curves have a point of order 2, so, if the curve used in the challenge happens to not have such a point, the server is restarted until such a point exists. In sagemath, we can easily get a point of order 2 by doing this:

```python
assert len(E(0).division_points(2)) > 1, "not cool enough curve"
P = E(0).division_points(2)[1]
```

Furthermore, what is interesting about choosing this point is that in the `fongi` function, it gets multiplied by `int(xG)`. As the order of $P$ is 2, `int(xG)*P` is either $\mathcal{O}$ or $P$ itself. So, the only possible outputs of the `fongi` function using this point $P$ are $P_x\cdot G + P$ or $P_x\cdot G$.

This way, we can have two candidates for the point $G$:

```python
def get_ikkyu_point(r, E, P=None):
    r.sendlineafter(b"[Q]uit\n", b"G")
    r.recvline()
    if P is None:
        P = E.random_point()
    r.sendline(f"{P.xy()[0]},{P.xy()[1]}".encode())
    r.recvline()
    r.recvuntil(b"fongi(G, H, P) = ")
    line = r.recvline().decode().strip()
    x = int(line.split()[0][1:])
    y = int(line.split()[2])
    return P, x, y

Pu, *U = get_ikkyu_point(r, E, P=P)
U = E(U)
Gs = [U * int(pow(int(P.x()) % U.order(), -1, U.order())), (U-P)*pow(int(P.x()) % U.order(), -1, U.order())]
```

Once we have all the possible $G$ values, we can send another random point and recover all the possible $H$ values:

```python

P = E.random_point()
Pv, *V = get_ikkyu_point(r, E, P=P)
V = E(V)
Xs = [V - G.x()*P - P.x()*G for G in Gs]
while True:
    try:
        Hs = [ X * pow(int(P.y()) % X.order(), -1, X.order()) for X in Xs]
        break
    except:
        pass
```

Now, we query the encrypted flag and try every possible combination of $G$ and $H$ and recover the flag:

```python
r.sendlineafter(b"[Q]uit\n", b"E")
r.recvuntil(b"m * G.xy()[0] * H.xy()[1] = ")
result = int(r.recvline().decode().strip())

for G in Gs:
    for H in Hs:
        m = result * pow(G.xy()[0] * H.xy()[1], -1, p)
        flag = long_to_bytes(int(m))
        print(b"Possible flag:", flag)
```

```python
$ python get_flag.py
[+] Starting local process './Ikkyu_san.py': pid 602527
b'Possible flag:' b'CCTF{this_is_a_flag_for_testing}'
b'Possible flag:' b'\x13A\xb2\xf8\\\xca\x1c\xee\xaa\x9b-\xc5\xce\xb8\xcb\xea0p\x01\xb5\x89\x86\t\x15\xdc\xc0\xe6*\x98\x1b\xc0\xaa'
b'Possible flag:' b'N\xa6k\x98}\xbf\x05\xb3s\x1f\xb2\xa7k\xf3\xc3\xb5\xc36\xdb\xe4\x1c\x8f\x13\t}\xea\xb54/\x90R\xa4'
b'Possible flag:' b'\xe6\xa8C\x03\xc6\x8c\x84UX\xc1\n\x10\n\xd1]\xcc\x91\xe6\x8f\xb1&j_\xf9K\xb5\x14\xd6\x97\xa73I'
```
