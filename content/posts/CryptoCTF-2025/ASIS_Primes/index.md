---
title: "ASIS Primes - CryptoCTF"
date: 2025-12-27
hero: /images/posts/writing-posts/code.svg
menu:
  sidebar:
    name: ASIS Primes
    identifier: cryptoctf-2025-asis-primes
    parent: cryptoctf-2025
    weight: 8
---

This challenge is a RSA-style challenge, in which we can provide the prime numbers used for encryption as long as they satisfy specific conditions.

First, standard parameters are generated:

```python
global flag
nbit = 512
p, q = [getPrime(nbit) for _ in range(2)]
e = 65537
```

Then, the main challenge's logic goes into this loop:

```python
while True:
    pr(f"{border} Options: \n{border}\t[E]ncrypted the flag! \n{border}\t[S]ubmit primes! \n{border}\t[Q]uit")
    ans = sc().decode().strip().lower()
    if ans == 'e':
        m = bytes_to_long(flag)
        c = pow(m, e ^ 1, p * q)
        pr(f'{c = }')
    elif ans == 's':
        pinit = f'CCTF{{7H!S_iZ_th3_f1RSt_pRim3__P_f0R_oUr_{nbit}-bit_m0DulU5_{rand_str(randint(5, 40))}'.encode()
        qinit = f'CCTF{{7H!S_iZ_th3_s3c0Nd_pRim3_Q_f0R_oUr_{nbit}-bit_m0DulU5_{rand_str(randint(5, 40))}'.encode()
        pr(border, f'the condition for the first  prime is: {pinit}')
        pr(border, f'the condition for the second prime is: {qinit}')
        pr(border, f'Please submit the primes p, q: ')
        inp = sc().decode().strip()
        try:
            _p, _q = [int(_) for _ in inp.split(',')]
            _pbytes, _qbytes = [long_to_bytes(_) for _ in (_p, _q)]
            if (
                isPrime(_p) and isPrime(_q) 
                and _pbytes.startswith(pinit) and _qbytes.startswith(qinit) 
                and _pbytes.endswith(b'}') and _qbytes.endswith(b'}') 
                and is_valid(_pbytes) and is_valid(_qbytes)
                and (9 * _p * _q).bit_length() == 2 * nbit
                ):
                    p, q = _p, _q
        except:
            pr(border, f'The input you provided is not valid! Try again!!')
            nbit += 1¡
```

And the `is_valid` and `rand_str` functions are:

```python
def is_valid(msg):
	msg, charset = msg.decode(), string.printable[:63] + '_{-}'
	return all(_ in charset for _ in msg)

def rand_str(l):
	charset = string.printable[:63] + '_'
	return ''.join([charset[randint(0, 63)] for _ in range(l)])
```

All in all, we can:

1. Encrypt the flag
2. Submit new primes

Before retreiving the encrypted flag, we need to change the primes used so that we can later decrypt it. Also, note that the exponent used is not 65537. Instead, it is $65535 = 2^{16}$, so decryption won't be that straightforward, but we'll get to it later.

First, we need to generate valid primes. We need to generate prime numbers $p$ and $q$ such that:

1. Their bytes representation starts with a specific string
2. They end with a closing bracket
3. Be printable characters
4. The bit length of $9pq$ must be $2\cdot \text{nbit}$, where $\text{nbit}$ is increased every round.

If we manage to satisfy all those conditions, we are good to go.

The easiest way to do so is to bruteforce the prime numbers until they match the conditions:

```python
charset = string.printable[:63] + '_{-}'
def get_asis_primes(init, bits_lim=1000, lim=1):
    for num_bytes in range(1, 75):
        primes = []
        for combination in product(charset, repeat=int(num_bytes)):
            comb = ''.join(combination)
            poss_p = bytes_to_long(init.encode())*(256**(len(comb)+1)) + bytes_to_long(comb.encode())*256 + ord("}")
            if isPrime(poss_p):
                primes.append(poss_p)
                if len(primes) >= lim:
                    return primes
            elif poss_p.bit_length() > bits_lim:
                return primes
    return primes
```

This function generates prime numbers that satisfy the three first conditions. In the `main` function of the solve script, there is this loop, which takes care of generating different prime numbers until they satisfy the bit length condition:

```python
while True:
    submit_trash = True
    r.sendlineafter(b"[Q]uit\n", b"S")
    r.recvuntil(b"is: b'")
    pinit = r.recvline().strip().decode()[:-1]
    r.recvuntil(b"is: b'")
    qinit = r.recvline().strip().decode()[:-1]

    ps = get_asis_primes(pinit)
    qs = get_asis_primes(qinit)
    nbits = int(pinit.split("-")[0].split("_")[-1])

    for p in ps:
        for q in qs:
            if (9*p*q).bit_length() == 2 * nbits:
                submit_trash = False
                break
    if submit_trash:
        r.sendlineafter(b"Please submit the primes p, q: \n", b"afibasfpif")
    else:
        r.sendlineafter(b"Please submit the primes p, q: \n", f"{p},{q}".encode())
        break
```

Eventually, that piece of code will generate valid prime numbers and will submit them. Then, we can get the encrypted flag, that is computed like `pow(m, 2**16, p*q)`. Here, $2^{16}$ doesn't have an inverse modulo $\varphi(n)$, so to recover the flag, successive square roots have to be applied, until we recover the flag. This function does so:

```python
def iterated_roots(a, p, iterations=18):
    results = [[a]]

    for _ in range(iterations):
        new_level = []
        for value in results[-1]:
            try:
                roots = nthroot_mod(value % p, 2, p, all_roots=True)
                new_level.extend(roots)
            except ValueError:
                pass
        if not new_level:
            break
        results.append(new_level)
    return results
```

So we only need to do this in the main function, once we submit the primes:

```python
r.sendlineafter(b"[Q]uit\n", b"E")
r.recvuntil(b'c = ')
c = int(r.recvline().strip())

it_roots = iterated_roots(c % p, p)
print(it_roots)
for ir in it_roots:
    for jr in ir:
        if long_to_bytes(jr).startswith(b"CCTF"):
            print("Found potential flag:", long_to_bytes(jr))
            break
```

And just like this, we get the flag!