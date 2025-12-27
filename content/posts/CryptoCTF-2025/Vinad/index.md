---
title: "Vinad - CryptoCTF"
date: 2025-12-23
hero: /images/posts/writing-posts/code.svg
menu:
  sidebar:
    name: Vinad
    identifier: cryptoctf-2025-vinad
    parent: cryptoctf-2025
    weight: 1
---

This challenge is an RSA-type challenge in which we need to factor `n`. We are given a file `vinad.py` and its output in `output.txt`. This is the RSA key generation method implemented in `vinad.py`:

```python
def parinad(n):
    return bin(n)[2:].count('1') % 2

def vinad(x, R):
    return int(''.join(str(parinad(x ^ r)) for r in R), 2)

def genkey(nbit):
    while True:
        R = [getRandomNBitInteger(nbit) for _ in range(nbit)]
        r = getRandomNBitInteger(nbit)
        p, q = vinad(r, R), getPrime(nbit)
        if isPrime(p):
            e = vinad(r + 0x10001, R)
            if GCD(e, (p - 1) * (q - 1)) == 1:
                return (e, R, p * q), (p, q)

```

The `parinad` function computes the parity of the hamming wright of a given number. The `vinad` function takes a number `x` and an array `R` and computes a number by applying the `parinad` function to all the pairs.

Now, note the following for the `vinad` function: when we flip a bit in `x`, the parity of the hamming weight changes for every `x^r`. This implies that if we fliip a bit in `x`, the number returned by `vinad` will be the bitwise opposite. We can quickly verify that with this code:

```python
>>> R = [getRandomNBitInteger(nbit) for _ in range(nbit)]
>>> r = getRandomNBitInteger(nbit)
>>> vinad(r, R) + vinad(r ^ (1<<20), R) == (1<<512) - 1
True
```

where we flipped the 20th bit. This overall implies that there are only two possible outputs to the `vinad` function given a specific `R`.

The rest of the challenge code is the key generation and encryption of the flag:

```python
def encrypt(message, pubkey):
    e, R, n = pubkey
    return pow(message + sum(R), e, n)

nbit = 512
pubkey, _ = genkey(nbit)
m = bytes_to_long(flag)
assert m < pubkey[2]
c = encrypt(m, pubkey)

print(f'R = {pubkey[1]}')
print(f'n = {pubkey[2]}')
print(f'c = {c}')
```

To solve the challenge, we can compute the possible outputs of the `vinad` function, recover `p` and decrypt the flag:

```python
lines = open("output.txt", "r").readlines()
R = eval(lines[0].split('=')[1].strip())
n = int(lines[1].split('=')[1].strip())
c = int(lines[2].split('=')[1].strip())

outputs = [vinad(0, R), vinad(1, R)]
p = outputs[0] if isPrime(outputs[0]) else outputs[1]
q = n // p
for e in outputs:
    try:
        d = pow(e, -1, (p-1)*(q-1))
        pt = pow(c, d, n) - sum(R)
        print(long_to_bytes(pt))
    except:
        pass
```

Flag: `CCTF{s0lV1n9_4_Syst3m_0f_L1n3Ar_3qUaTi0n5_0vEr_7H3_F!3lD_F(2)!}`