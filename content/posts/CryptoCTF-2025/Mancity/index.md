---
title: "Mancity - CryptoCTF"
date: 2025-12-24
hero: /images/posts/writing-posts/code.svg
menu:
  sidebar:
    name: Mancity
    identifier: cryptoctf-2025-mancity
    parent: cryptoctf-2025
    weight: 4
---

This challenge is another RSA-style challenge, in which we need to factor `n`. We are given the files `mancity.py` and `output.txt`. This is the main code:

```python
nbit = 256
p, q = keygen(nbit)
m = bytes_to_long(flag)
assert m < n
e, n = 1234567891, p * q
c = pow(m, e, n)

print(f'n = {n}')
print(f'c = {c}')
```

And these, the functions used to generate the prime numbers:

```python
def man(n):
    B = bin(n)[2:]
    M = ''
    for b in B:
        if b == '0':
            M += '01'
        else:
            M += '11'
    return int(M, 2)

def keygen(nbit):
    while True:
        p = getPrime(nbit)
        r = man(p)
        B = bin(p)[2:] + '1' * nbit
        q = int(B, 2)
        if isPrime(q) and isPrime(r):
                return q, r
```

In the `keygen` function, a prime `p` is generated, and these two primes are generated from it:

- `r`. This prime is generated through the `man` function, which places a "1" in between of every bit of `p`. 
- `q`. This is the prime `p` followed by `nbit` 1's in its binary representation.

Therefore, we know beforehand half of the bits of the primes used for RSA. Besides, we also know that the rest of the unkown bits are the same for `r` and `q` (the bits from `p`). All of this should give us enough relationships between `r` and `q` so that a sat-solver like `z3` can recover them. To do so, we can use this code:

```python
from z3 import *

n = 147170819334030469053514652921356515888015711942553338463409772437981228515273287953989706666936875524451626901247038180594875568558137526484665015890594045767912340169965961750130156341999306808017498374501001042628249176543370525803456692022546235595791111819909503496986338431136130272043196908119165239297

nbit = 256
p = BitVec('p', nbit)

ones = (1 << nbit) - 1
q = (ZeroExt(nbit, p) << nbit) | ones

r = BitVecVal(0, 2*nbit)
for i in range(nbit):
    bit = Extract(i, i, p)
    r = r | (ZeroExt(2*nbit-1, bit) << (2*i+1))
    r = r | (BitVecVal(1, 2*nbit) << (2*i))

solver = Solver()
solver.add(q * r == n)

assert solver.check() == sat
p_val = solver.model()[p].as_long()

r = man(p_val)
q = (p_val << 256) + (1<<256) - 1
assert r*q == n

print(f"{r = }")
print(f"{q = }")
```

After executing that, we recover the primes:

```python
r = 12980118888329561114281969993876754607095981711712555303794390136908262799373065828981224786253414810629276321980181325279687977358689569061320321526136831
q = 11338171907373815456673959643144436595447931742489890636387744547510799292993536478217233829945109394705560885589911191303642301888677829052802222509785087
```

And we just need to decrypt the flag using standard RSA:

```python
c = 77151713996168344370880352082934801122524956107256445231326053049976568087412199358725058612262271922128984783428798480191211811217854076875727477848490840660333035334309193217618178091153472265093622822195960145852562781183839474868269109313543427082414220136748700364027714272845969723750108397300867408537

e = 1234567891
d = pow(e, -1, (r-1)*(q-1))
m = pow(c, d, r*q)
print(long_to_bytes(m))
```

Flag: `CCTF{M4nch3sReR_c0D!ng_wI7H_RSA}`