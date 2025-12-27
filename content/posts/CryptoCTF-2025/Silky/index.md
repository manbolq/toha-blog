---
title: "Silky - CryptoCTF"
date: 2025-12-27
hero: /images/posts/writing-posts/code.svg
menu:
  sidebar:
    name: Silky
    identifier: cryptoctf-2025-silky
    parent: cryptoctf-2025
    weight: 9
---

In this challenge, we are given the file `Silky.sage`. It starts by generating some parameters:

```python
def randroad(B):
	return vector(ZZ,[randint(-B, B) for _ in range(n)])

def main():
    global flag, B, n, D, t
    B, n = 5, 19
    D, t = 110, 128
    l = int(4 * D * B / t)
    c, key = 0, randroad(B)
```

In particular, it generates a key that is a vector of length 19 with integer values in $[-5, 5]$.

Then, this is the main loop of the challenge:

```python
while True:
    c += 1
    if c >= 12:
        die(border, "My brain is fried, quitting...")
    pr(f"{border} Options: \n{border}\t[G]et flag! \n{border}\t[M]ake Silky! \n{border}\t[Q]uit")
    ans = sc().decode().strip().lower()
    if ans == 'm':
        R = [silky(key) for _ in range(int(l * t // 2))]
        for i in range(len(R) // 16):
            pr(border, f"{str(R[16 * i:16 * (i + 1)]).replace(',', '')}")
    elif ans == 'g':
        pr(border, f'Please submit the secret key: ')
        inp = sc().decode().strip()
        try:
            _key = vector(ZZ, [int(_) for _ in inp.split(',')])
        except:
            die(border, f'The input you provided is not valid! Bye!!')
        if _key == key:
            die(border, f'Congrats! You got the flag: {flag}')
        else:
            die(border, f'Your key is incorrect!')
    elif ans == 'q':
        die(border, "Quitting...")
    else:
        die(border, "Bye...")
```

In order to get the flag, we need to recover the key from 11 rounds at most. By entering the "[M]ake Silly" option, we are given an array (R) consisting of the output of 1088 runs of the `silky` function on the key. THis is the `silky` function:

```python
def roadband():
	return randroad(B * (D + 1))

def silky(key):
	while True:
		R = roadband()
		_R = R - key
		if min(_R) >= - B * D and max(_R) <= B * D:
			return R
```

Let $K = [K_0, K_1, K_2, \dots, K_{18}]$ be the secret key. The `silky` function returns a random array $R = [R_0, R_1, \dots, R_{18}]$ that satisfies this property:

$$-550 \leq R_i - K_i \leq 550 ~ \forall i \in \{0, 1, \dots, 18\}$$

which is equivalent to:

$$R_i - 550 \leq K_i \leq R_i + 550 ~ \forall i \in \{0, 1, \dots, 18\}$$

These inequalities need to be satisfied for every $R$ givenin the array that the "M" option provides. In total, we will have $1088\times11 = 11968$ inequalities. This should be restrictive enough so that the individual components of the secret key can be recovered. This can be achieved with this piece of code (parsing the `R` array is pretty tedious):

```python
def parse_rows(R):
    parsed = []
    for row in R:
        row = row.strip()
        tuples = row.split(b') (')
        tuples[0] = tuples[0][2:]
        tuples[-1] = tuples[-1][:-1]
        parsed_row = []
        for t in tuples:
            nums = list(map(int, t.split()))
            parsed_row.append(vector(ZZ, nums))
        parsed.append(parsed_row)

    all_Rs = []
    for row in parsed:
        all_Rs.extend(row)

    return all_Rs

key = [-10] * n

while True:
    r.sendlineafter(b"[Q]uit\n", b"M")
    R = r.recvuntil(b" Options:", drop=True).strip().replace(b"\xe2\x94\x83", b"").replace(b"[", b"").replace(b"]", b"").splitlines()
    parsed_R = parse_rows(R)

    for j in range(len(key)):
        list_left = []
        list_right = []
        for i in range(len(parsed_R)):
            try:
                list_left.append(parsed_R[i][j] - 550)
                list_right.append(parsed_R[i][j] + 550)
            except:
                pass
        max_left = max(list_left)
        min_right = min(list_right)
        if min_right == max_left:
            key[j] = min_right
    
    if -10 not in key:
        break
```

Once the key is recovered, it is sent with the "G" option and we get the flag:

```python
r.sendlineafter(b"[Q]uit\n", b"G")
r.sendlineafter(b"key: \n", ",".join(map(str, key)).encode())

r.interactive()
```
