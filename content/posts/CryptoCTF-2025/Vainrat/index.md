---
title: "Vainrat - CryptoCTF"
date: 2025-12-24
hero: /images/posts/writing-posts/code.svg
menu:
  sidebar:
    name: Vainrat
    identifier: cryptoctf-2025-vainrat
    parent: cryptoctf-2025
    weight: 5
---

For this challenge, we are given a `vainrat.sage` file. Looking at the code, we see that we will be working with the field of real numbers with 440 bits o precision:

```python
nbit = 110
prec = 4 * nbit
R = RealField(prec)
```

The `main` function is the following:

```python
def main():
	m = bytes_to_long(flag)
	x0 = R(10 ** (-len(str(m))) * m)
	while True:
		y0 = abs(R.random_element())
		if y0 > x0: break
	assert len(str(x0)) == len(str(y0))
	c = 0
	pr(border, f'We know y0 = {y0}')
	while True:
		pr("| Options: \n|\t[C]atch the rat \n|\t[Q]uit")
		ans = sc().decode().strip().lower()
		if ans == 'c':
			x, y = rat(x0, y0)
			x0, y0 = x, y
			c += 1
			if c <= randint(12, 19):
				pr(border, f'Unfortunately, the rat got away :-(')
			else: pr(border, f'y = {y}')
		elif ans == 'q': die(border, "Quitting...")
		else: die(border, "Bye...")
```

And this is the `rat` function:

```python
def rat(x, y):
	x = R(x + y) * R(0.5)
	y = R((x * y) ** 0.5)
	return x, y
```

To recover the flag, we need to recover the `x0` value. This code computes two sequences. Namely:

$$x_{n+1} = \dfrac{x_n + y_n}{2}, \quad y_{n+1} = \sqrt{x_ny_n}$$

With a little bit of basic maths, we can see that the sequences $\{x_n\}$ and $\{y_n\}$ converge and their limits are the same. For a detailed explanation, see this [MathStackExchange question](https://math.stackexchange.com/questions/1940152/with-x-n1-sqrtx-ny-n-and-y-n1-x-ny-n-over-2-n-geq-2-show-t).

Using the "C" option in the main function of the challege a few times, we will eventually get the limit of the sequences. The main problem is: knowing the limit of the sequences and `y0`, recover `x0`. 

The first thing that comes to mind is expressing the limit in terms of `x0` and `y0`, but I found no easy way to do that, so we need to find another way.

The second thing that came to mind is doing binary search to find `x0`. This is because a smaller `x0` implies a smaller limit for the sequences (this can be easily proved using similar maths again). This way, we can know if some `x0` is smaller o bigger than the actual `x0`. The piece of code that performs the binary search and recovers the flag is this:

```python
def get_limit(x0, y0, steps=1000):
    x, y = x0, y0
    for _ in range(steps):
        x, y = rat(x, y)
    return x

nbit = 110
prec = 40 * nbit
R = RealField(prec)
ini = R(0)
end = R(1)

for _ in range(2000):
    mid = (ini + end) / 2
    lim = get_limit(mid, y0)
    if lim > limit:
        end = mid
    else:
        ini = mid

x0 = R((ini + end) / 2)
m = int(x0 * (10 ** 128))
print(long_to_bytes(m))
```

(The piece of code to get `y0` and the limit from the challenge's output is skipped because it is kind of long and boring). I had to increase the field's precision. Otherwise, I would not recover the full `x0` value. 