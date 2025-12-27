---
title: "Toffee - CryptoCTF"
date: 2025-12-27
hero: /images/posts/writing-posts/code.svg
menu:
  sidebar:
    name: Toffee
    identifier: cryptoctf-2025-toffee
    parent: cryptoctf-2025
    weight: 10
---

In this challenge, we are given the file `Toffee.sage`, which implements a custom signature scheme using elliptic curves. First, it generates some parameters:

```python
global flag, u, v, k, _n, G
skey = bytes_to_long(flag)
p = 0xaeaf714c13bfbff63dd6c4f07dd366674ebe93f6ec6ea51ac8584d9982c41882ebea6f6e7b0e959d2c36ba5e27705daffacd9a49b39d5beedc74976b30a260c9
a, b = -7, 0xd3f1356a42265cb4aec98a80b713fb724f44e747fe73d907bdc598557e0d96c5
_n = 0xaeaf714c13bfbff63dd6c4f07dd366674ebe93f6ec6ea51ac8584d9982c41881d942f0dddae61b0641e2a2cf144534c42bf8a9c3cb7bdc2a4392fcb2cc01ef87
x = 0xa0e29c8968e02582d98219ce07dd043270b27e06568cb309131701b3b61c5c374d0dda5ad341baa9d533c17c8a8227df3f7e613447f01e17abbc2645fe5465b0
y = 0x5ee57d33874773dd18f22f9a81b615976a9687222c392801ed9ad96aa6ed364e973edda16c6a3b64760ca74390bb44088bf7156595f5b39bfee3c5cef31c45e1
F = FiniteField(p)
E = EllipticCurve(F, [a, b])
G = E(x, y)
u, v, k = [randint(1, _n) for _ in ';-)']
```

Then, we have the main challenge's loop:

```python
while True:
    pr(f"{border} Options: \n{border}\t[G]et toffee! \n{border}\t[S]ign message! \n{border}\t[Q]uit")
    ans = sc().decode().strip().lower()
    if ans == 'g':
        pr(border, f'Please let me know your seed: ')
        _k = sc().decode().strip()
        try:
            _k = int(_k)
        except:
            die(border, 'Your seed is not valid! Bye!!')
        pr(f'{toffee(u, v, _k) = }')
    elif ans == 's':
        pr(border, f'Please send your message: ')
        msg = sc().strip()
        r, s = sign(msg, skey)
        pr(border, f'{r = }')
        pr(border, f'{s = }')
    elif ans == 'q':
        die(border, "Quitting...")
    else:
        die(border, "Bye...")
```

The secret key used to sign the messages is the flag. We can:

- Query the `toffee` function using our own `k` value
- Get the signature of any message we would like

From these, we need to recover the secret key. This is the `toffee` function:

```python
def toffee(u, v, k):
	return (u * k + v) % _n
```

By using the "G" option twice, we can recover the `u` and `v` values solving a simple system of linear equations. Even easier, we can first send `k = 0` to directly get the value of `v`. Then, send `k = 1` and recover `u` just by subtracting `v` to the output:

```python
r = process("./Toffee.sage")

r.sendlineafter(b"[Q]uit\n", b"G")
r.sendlineafter(b"seed: \n", b"0")
r.recvuntil(b"toffee(u, v, _k) = ")
v = int(r.recvline().strip())

r.sendlineafter(b"[Q]uit\n", b"G")
r.sendlineafter(b"seed: \n", b"1")
r.recvuntil(b"toffee(u, v, _k) = ")
u = (int(r.recvline().strip()) - v) % _n
```

The `sign` function that the challenge implements is the following:

```python
def sign(msg, skey):
	global k
	h = bytes_to_long(sha512(msg).digest())
	k = toffee(u, v, k)
	P = k * G
	r = int(P.xy()[0]) % _n
	s = inverse(k, _n) * (h + r * skey) % _n
	return (r, s)
```

So, given a message $m$ and denoting the private key as $d$ and the hash function as $H$, the signature of $m$ is the tuple $(r, s)$ where:

$$r = ((uk + v) \cdot G)_x \ (mod \ n)$$
$$s = k^{-1} (H(m) + r \cdot d) \ (mod \ n)$$

Also, note that the $k$ value changes to $uk + v$ for the next message to sign. Say we have two messages, $m_1$ and $m_2$, and let us write $h_1 = H(m_1), h_2 = H(m_2)$. Let us denote the signatures $(r_1, s_1)$ and $(r_2, s_2)$, respectively. 

Let's focus on the $s$ component of the signature of both messages:

$$s_1 (uk + v) \equiv h_1 + r_1 d \ (mod \ n)$$
$$s_2 (u(uk+v)+v) \equiv h_2 + r_2 d \ (mod \ n)$$

Reordering a bit:

$$r_1d - (s_1 u) k \equiv s_1 v - h_1 \ (mod \ n)$$
$$r_2d - (s_2 u^2) k \equiv s_2 v + v - h_2 \ (mod \ n)$$

which turns out to be a system of linear equations over $\mathbb{Z}_n$ on the variables $d$ and $k$. We can easily solve for $d$ and $k$ using this sagemath piece of code:

```python
msg1 = b"Message 1"
msg2 = b"Message 2"
h1 = bytes_to_long(sha512(msg1).digest())
h2 = bytes_to_long(sha512(msg2).digest())

r.sendlineafter(b"[Q]uit\n", b"S")
r.sendlineafter(b"message: \n", msg1)
r.recvuntil(b"r = ")
r1 = int(r.recvline().strip())
r.recvuntil(b"s = ")
s1 = int(r.recvline().strip())

r.sendlineafter(b"[Q]uit\n", b"S")
r.sendlineafter(b"message: \n", msg2)
r.recvuntil(b"r = ")
r2 = int(r.recvline().strip())
r.recvuntil(b"s = ")
s2 = int(r.recvline().strip())

A = Matrix(GF(_n), [[r1, -(s1*u)], [r2, -(u**2 * s2)]])
B = Matrix(GF(_n), [[(s1 * v - h1) % _n], [( (v*u + v) * s2 - h2) % _n]])

sk = (A.inverse() * B)[0][0]
print(long_to_bytes(int(sk)))
```

And the flag will be printed!

