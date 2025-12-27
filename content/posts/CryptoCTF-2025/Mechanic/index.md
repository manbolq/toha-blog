---
title: "Mechanic - CryptoCTF"
date: 2025-12-24
hero: /images/posts/writing-posts/code.svg
menu:
  sidebar:
    name: Mechanic
    identifier: cryptoctf-2025-mechanic
    parent: cryptoctf-2025
    weight: 3
---

For this challenge, we are given three files: `mechanic.py`, `output.raw` and `flag_22.enc`. This is the challenge's code:

```python
from quantcrypt.kem import MLKEM_1024
from quantcrypt.cipher import KryptonKEM
from random import randint
from pathlib import *
from os import urandom
from flag import flag

kem = MLKEM_1024()
kry = KryptonKEM(MLKEM_1024)
pt = Path('/Mechanic/flag.png')
f = open('output.raw', 'wb')
m = randint(2 ** 39, 2 ** 40)
B, c = bin(m)[2:], 0
for b in B:
    if b == '1':
        pkey, skey = kem.keygen()
        ct = Path(f'/flag_{c}.enc')
        kry.encrypt(pkey, pt, ct)
        pt = ct
        c += 1
    else:
        pkey, skey = urandom(kem.param_sizes.pk_size), urandom(kem.param_sizes.sk_size)
    f.write(skey)
f.close()
```

The challenge uses MLKEM-1024 to create keys and then encrypt the flag several times. Randomly, these two things may happen:

- A new key is generated and the last ciphertext is encrypted again
- A random string of bytes (that looks like a key) is generated and never used

All the secret keys used (both valid and invalid ones) are written to the file `output.raw`. Another thing to note is that MLKEM can distinguish between valid and invalid ciphertext. It is not like AES (which will happily decrypt anything), so we can distinguish a valid key from an invalid one just by trying to decrypt some ciphertext. 

Putting all of this together, we can run this code to recover the flag (which is an image):

```python
kem = MLKEM_1024()
all_skeys = open("output.raw", "rb").read()
skeys = [all_skeys[i:i+kem.param_sizes.sk_size] for i in range(0, len(all_skeys), kem.param_sizes.sk_size)]

kry = KryptonKEM(MLKEM_1024)
c = 22
while c >= 0:
    for k in skeys:
        try:
            output_filename = f"./flag_{c-1}.enc" if c > 0 else "flag.png"
            kry.decrypt_to_file(k, f"./flag_{c}.enc", output_filename)
            c -= 1
        except:
            pass
```

And the flag:

{{< img src="images/flag.png" align="center" alt="Flag">}}