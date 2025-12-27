---
title: "Matemith - CryptoCTF"
date: 2025-12-24
hero: /images/posts/writing-posts/code.svg
menu:
  sidebar:
    name: Matemith
    identifier: cryptoctf-2025-matemith
    parent: cryptoctf-2025
    weight: 6
---

For this challenge, we are given a `matemith.sage` and a `output.txt`. The challenge starts by splitting the flag into 6 parts (the number of parts can be later seen in the code):

```python
l, flag = 14, flag.lstrip(b'CCTF{').rstrip(b'}')
FLAG = [flag[l * i:l * (i + 1)] for i in range(len(flag) // l)]
M = [bytes_to_long(_) for _ in FLAG]
```

Then, 6 polynomials in  $\mathbb{Q}[u, v, w, x, y, z]$ are generated:

```python
p = getPrime(313)
R.<u, v, w, x, y, z> = PolynomialRing(QQ)

COEFS = [getRandomRange(1, p - 1) for _ in range(21)]
f = COEFS[0] * u * v + COEFS[1] * u + COEFS[2] * v
g = COEFS[3] * u * x * y + COEFS[3] * x + COEFS[5] * y + COEFS[6] * v
h = COEFS[7] * u * w + COEFS[8] * w + COEFS[9] * u
i = COEFS[10] * v * y * z + COEFS[11] * y + COEFS[12] * z + COEFS[13] * w
j = COEFS[14] * v * w + COEFS[15] * v + COEFS[16] * w
k = COEFS[17] * w * z * x + COEFS[18] * z + COEFS[19] * x + COEFS[20] * u
f, g, h, i, j, k = R(f), R(g), R(h), R(i), R(j), R(k)
```

Then, they are evaluated in the flag parts and printed:

```python
CNST = [_(M[0], M[1], M[2], M[3], M[4], M[5]) for _ in [f, g, h, i, j, k]]
f, g, h, i, j, k = [[f, g, h, i, j, k][_] + (p - CNST[_]) % p for _ in range(6)]

print(f'{p = }')
print(f'{f = }')
print(f'{g = }')
print(f'{h = }')
print(f'{i = }')
print(f'{j = }')    
print(f'{k = }')
```

Given the modulus $p$, we can think of the polynomials as polynomials in $\mathbb{Z}_p[u, v, w, x, y, z]$ and the flag parts are roots of all 6 of them. Therefore, to solve the challenge, we need to find the roots of these polynomials.

Sadly, sagemath does not implement an algorithm to find roots of a polynomial with several variables, so we need to find a way around that. The analogue of Gauss elimination for multiple variables is [**Groebner basis**](https://en.wikipedia.org/wiki). 

In our case, given the ideal $I = \langle f,g,h,i,j,k\rangle$, its Groebner basis is a set of polynomials in $\mathbb{Z}_p[u, v, w, x, y, z]$ that generates the same ideal but are more simplified (for example, by eliminating unnecessary variables from specific polynomaials). This can be easily computed using sagemath as follows:

```python
I = Ideal(f,g,h,i,j,k)
I.groebner_basis()
```

However, although simplified, this basis won't help much, as none of the polynomials has reduced its number of variables. These are the polynomials of the basis:

$$
x^2 + c_{0,0}x + c_{0,1}y + c_{0,2}z + c_{0,3}
$$
$$
xy + c_{1,0}x + c_{1,1}y + c_{1,2}z + c_{1,3}
$$
$$
y^2 + c_{2,0}x + c_{2,1}y + c_{2,2}z + c_{2,3}
$$
$$
xz + c_{3,0}x + c_{3,1}y + c_{3,2}z + c_{3,3}
$$
$$
yz + c_{4,0}x + c_{4,1}y + c_{4,2}z + c_{4,3}
$$
$$
z^2 + c_{5,0}x + c_{5,1}y + c_{5,2}z + c_{5,3}
$$
$$
u + c_{6,0}x + c_{6,1}y + c_{6,2}z + c_{6,3}
$$
$$
v + c_{7,0}x + c_{7,1}y + c_{7,2}z + c_{7,3}
$$
$$
w + c_{8,0}x + c_{8,1}y + c_{8,2}z + c_{8,3}
$$

Taking a closer look at the original polynomaials, we can see that $f, h$ and $j$ only depend on $u, v$ and $w$. Having three polynomaials and three variables, maybe its Groebner basis is easier to work with:

```python
Ideal(f, h, j).groebner_basis()
```

In this case, we get these polynomials:

$$
w^2 + c_{0,0}w + c_{0,1}
$$
$$
u + c_{1,0} w + c_{1,1}
$$
$$
v + c_{2,0} w + c_{2,1}
$$

As we can see, the first polynomaial only depends on $w$! Now, we can easily solve that quadratic and get its root (and a piece of the flag). Substituting that root into the other two polynomaisl, we can solve for $u$ and $v$ as well:

```python
sage: P.<t> = PolynomialRing(GF(p))
sage: (t^2 + 1838780483526537670669971223042694990191740374788529490727942831699957148168306014862107088879*t + 16040354251667788946456560158449061985189516463376863162788188859483841719131
....: 560652698516872).roots()
[(8054203939274777448590340204671694418580665046517706304098973146788802185827285512547482193217,
  1),
 (1631639702310041336611888741434165, 1)]
sage: w_val = 1631639702310041336611888741434165
sage: (t + 717835615520492628019744448048211504698458324547891163411932826300796193274199496304652741529*w_val + 8316362813463767565343342338209357966926953572699141581797324225632193883538
....: 833572285529701246).roots()
[(1078804227986401794161149736863793, 1)]
sage: u_val = 1078804227986401794161149736863793
sage: (t + 4671268414742138490500447858772580176389757751934939545662171755874598391785373450926309272490*w_val + 535419711478343115882677735386315585335560583734235183062496790604614133985
....: 1511749766666300831).roots()
[(2033644392583863279506423899386719, 1)]
sage: v_val = 2033644392583863279506423899386719
sage: long_to_bytes(u_val)
b'50lv!n6_7H3_H1'
sage: long_to_bytes(v_val)
b'dD3n__num8Ers_'
sage: long_to_bytes(w_val)
b'Pr08l3m_f0r_C5'
```

Now, looking at the original polynomials, we can substitute these values in $g, i, k$ and get three polynomials in three variables ($x, y, z$). We can then apply the Groebner basis to that set of polynomials and find the missing roots following the exact same process:

```python
sage: new_g = g(u_val, v_val, w_val, x, y, z)
sage: new_i = i(u_val, v_val, w_val, x, y, z)
sage: new_k = k(u_val, v_val, w_val, x, y, z)
sage: Ideal(new_g, new_i, new_k).groebner_basis()
[z^2 + 5122531403475444213922375052363368147785589459467367184224257742494707975593870928375737474065*z + 4386459432536359459135451637284351095296403629320828117456720258004041066832702816419576970790, x + 7318623145998491237337546604849947345819804471287382719847111300917884223647662892428188131872*z + 5594334544454563947135067528371659341801387313513772601384114756773216827232506255097783334475, y + 4356636220864539143828368673609750070222006631515926830980020638074748855587897971323109328346*z + 7764802650115666230439885504986888771178356943915844442882242078210477457998482166324911523283]
sage: (t^2 + 5122531403475444213922375052363368147785589459467367184224257742494707975593870928375737474065*t + 43864594325363594591354516372843510952964036293208281174567202580040410668327
....: 02816419576970790).roots()
[(4770453019325870905337936375351021260986815961838868610602658504874560459357193877676598504213,
  1),
 (1362759193209085863333245994737983, 1)]
sage: z_val = 1362759193209085863333245994737983
sage: (t + 7318623145998491237337546604849947345819804471287382719847111300917884223647662892428188131872*z_val + 559433454445456394713506752837165934180138731351377260138411475677321682723
....: 2506255097783334475).roots()
[(1001783284846617716298242552129119, 1)]
sage: x_val = 1001783284846617716298242552129119
sage: (t + 4356636220864539143828368673609750070222006631515926830980020638074748855587897971323109328346*z_val + 776480265011566623043988550498688877117835694391584444288224207821047745799
....: 8482166324911523283).roots()
[(2397222721510287028535819259569247, 1)]
sage: y_val = 2397222721510287028535819259569247
sage: long_to_bytes(x_val)
b'1dH_4nd_C5uRf_'
sage: long_to_bytes(y_val)
b'v14_4uT0m473d_'
sage: long_to_bytes(z_val)
b'C0pp3r5m17h!!?'
```

And putting together all the pieces, we get the flag:

`CCTF{50lv!n6_7H3_H1dD3n__num8Ers_Pr08l3m_f0r_C51dH_4nd_C5uRf_v14_4uT0m473d_C0pp3r5m17h!!?}`

**Note**: looking at the flag's text and at the size of the roots (~112 bits against the 313 bits of the prime $p$), there may be another way to solve this challenge, using the Coppersmith method to find small roots. I did a quick test using [defund's multivariate coppersmith](https://github.com/defund/coppersmith) but did not find the roots. Maybe with a bit more of patience that would work out.
