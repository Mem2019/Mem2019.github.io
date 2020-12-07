---
layout: post
title:  "PBCTF 2020 Queensarah2"
date:   2020-12-07 00:00:00 +0000
categories: jekyll update
---

## 0x00 Overview

Last weekend I played PBCTF on my own, and instead of binary challenges that I am quite good at, I tried to play some cryptography challenges. This is actually my first non-trivial Crypto challenge that I solved in CTF. Thus I think it is quite worthy to write a writeup to record. Interestingly, the intended approach to solve the challenges is by using *slide attack*, but I actually didn't know this technique until I got the flag, which tells the technique I used is actually slide attack that has been a common cryptography technique.

## 0x01 Challenge

The encryption is a random one-to-one mapping within lowercase and `'_'` 2-letter domain (thus with size `27*27`). 

```python
def encrypt(message):
    if len(message) % 2:
        message += "_"

    message = list(message)
    rounds = int(2 * ceil(log(len(message), 2))) # The most secure amount of rounds

    for round in range(rounds):
        # Encrypt
        for i in range(0, len(message), 2):
            message[i:i+2] = S_box[''.join(message[i:i+2])]

        # Shuffle, but not in the final round
        if round < (rounds-1): # put all even indexes at front and all odd ones at end
            message = [message[i] for i in range(len(message)) if i%2 == 0] + [message[i] for i in range(len(message)) if i%2 == 1]

    return ''.join(message)
```

We can also encrypt arbitrary content for at most 1500 times, and the encrypted flag is given. If we can crack the unknown key `S_box`, the flag can be figured out.

## 0x02 Solution

Let's consider the case where `len(message) == 2`, in this case `rounds = 2`. The shuffle makes no effect because there is only 2 characters. Thus the overall effect of the encryption is just `S_box[S_box[message]]`, which is applying `S_box` for 2 times. Therefore, we can iterate over all `27*27` cases and get the box which represent `S_box` applied 2 times. Let's call it `double_box`. Note that this `double_box` must also be one-to-one. Therefore, the goal is just figuring out the `S_box` given `double_box`.

The problem can be illustrated below, what we need to do is to find `??` for each 2-letter token.

```
             S_box                          S_box
aa           ----->           ??            ----->              c1 (known)
ab           ----->           ??            ----->              c2 (known)
                              ...
__           ----->           ??            ----->              c2 (known)
```

The idea is that we can simply guess each token at each position, for example, we can guess `ab` at the first position.

```
             S_box                          S_box
aa           ----->           ab            ----->              c1 (known)
ab           ----->           ??            ----->              c2 (known)
```

The we can infer that `ab -> c1`:

```
             S_box                          S_box
aa           ----->           ab            ----->              c1 (known)
ab           ----->           c1            ----->              c2 (known)
```

We then know `c1 -> c2`, so we can do this iteratively, until we reach some place that we have already visited before. This process is similar to the idea of *slide attack*. If there is conflict (e.i. the known cypher text does not match the previous token on that position), the initial guess should be wrong; otherwise the initial guesses are possible to be correct. We try to guess all possible tokens (e.i. `27*27`) for one particular position, since we know there must be one correct guess, we can have: if there is only one non-conflict guess among `27*27` trials, it must be the correct `S_box` mapping; if there are multiple non-conflict guesses, we are not sure which one is correct but the correct one must be one of these multiple non-conflict guesses.

Thus, we do this for all positions, we can actually recover most of the `S_box`. However there are still some unknown mappings. Therefore, my approach is record these multiple guesses (there are 32 in total in my case) and corresponding inference, and then try all of them to decrypt the cypher text. If we brute-force all possible cases, there are `32!` possibilities which is too large. My approach is to only consider valid ones by merging the inference mapping and only recording those that change the mapping and do not cause conflict. The full solution is shown below:

```python
from string import ascii_lowercase
from itertools import product
from pwn import *
from math import log, ceil
context(log_level='debug')
ALPHABET = ascii_lowercase + "_"
bigrams = [''.join(bigram) for bigram in product(ALPHABET, repeat=2)]

def infer_given_map(double_box, first_map, idx):
	single_box = dict()
	single_box[bigrams[idx]] = first_map
	mid = first_map
	dst = double_box[bigrams[idx]]
	while True:
		if mid in single_box:
			if single_box[mid] == dst: # and len(set(single_box.keys())) == 27*27:
				return single_box
			else:
				return False
		single_box[mid] = dst
		old_mid = mid
		mid = dst
		dst = double_box[old_mid]

def merge_dict(dst, src):
	for k in src:
		if k in dst and src[k] != dst[k]:
			return False
		else:
			dst[k] = src[k]
	return True

def crack_double_map(double_box):
	certain_box = dict()
	possible_box = []
	for i in range(0, 27*27):
		guesses = []
		for first_map in bigrams:
			res = infer_given_map(double_box, first_map, i)
			if res:
				guesses.append(res)
		if len(guesses) == 1:
			r = merge_dict(certain_box, guesses[0])
			assert r
		else:
			possible_box.append(guesses)
	return certain_box, possible_box

def dump_data():
	# sh = process("nc -x 127.0.0.1:1080 -X 5 queensarah2.chal.perfect.blue 1".split(' '))
	sh = remote("queensarah2.chal.perfect.blue", 1)
	sh.recvuntil("{'")
	c_flag = sh.recvuntil("'}")[:-2]
	assert len(c_flag) == 58
	sh.recvuntil("> ")
	double_box = {}
	for x in bigrams:
		sh.sendline(x)
		sh.recvuntil("this:\n")
		res = sh.recvuntil('\n')[:-1]
		if len(res) != 2:
			sh.interactive()
		double_box[x] = res
		sh.recvuntil("> ")
	return double_box, c_flag


def shuffle_back(message):
	assert len(message) % 2 == 0
	ret = [None] * len(message)
	half_len = len(message)//2
	for i in range(0, half_len):
		ret[i*2] = message[i]
		ret[i*2+1] = message[half_len+i]
	return ret

def map_with_default(box, key):
	if key in box:
		return box[key]
	else:
		return "??"

def decrypt(message, box):
	assert len(message) % 2 == 0
	message = list(message)
	rounds = int(2 * ceil(log(len(message), 2)))

	inv_box = {}
	for k in box:
		inv_box[box[k]] = k
	# assert len(set(inv_box.keys())) == 27*27

	for r in range(0, rounds):
		if r != 0:
			message = shuffle_back(message)
		for i in range(0, len(message), 2):
			message[i:i+2] = map_with_default(inv_box, ''.join(message[i:i+2]))

	return ''.join(message)

def try_inc_boxes(certain_box, boxes):
	ret = []
	for box in boxes:
		inc_certain_box = dict(certain_box)
		r = merge_dict(inc_certain_box, box)
		if r and len(inc_certain_box.keys()) != len(certain_box.keys()):
			ret.append(inc_certain_box)
	return ret

def find_all(certain_box, possible_box):
	past_boxes = [certain_box]
	for boxes in possible_box:
		new_boxes = []
		for past_box in past_boxes:
			new_boxes += try_inc_boxes(past_box, boxes)
		past_boxes += new_boxes
		print(len(new_boxes))
	return [box for box in past_boxes if len(box.keys()) == 27*27]


# print(dump_data())
double_box, c_flag = ({'gw': 'sv', 'gv': 'gy', 'gu': 'tf', 'gt': 'gc', 'gs': 'nr', 'gr': 'wq', 'gq': 'mq', 'gp': 'qe', 'gz': '_k', 'gy': 'cf', 'gx': 'at', 'gg': 'cn', 'gf': 'og', 'ge': 'vj', 'gd': 'md', 'gc': 'fa', 'gb': 'uj', 'ga': 'ds', 'go': 'fe', 'gn': 'xk', 'gm': 'bz', 'gl': 'wg', 'gk': 'cx', 'gj': 'c_', 'gi': 'fw', 'gh': 'aw', 'tz': 'to', 'tx': 'da', 'ty': 'xj', 'g_': 'bs', 'tw': 'tt', 'tt': 'en', 'tu': 'fr', 'tr': 'pu', 'rf': 'gb', 'tp': 'lw', 'tq': 'lb', 'tn': 'iw', 'to': 'bd', 'tl': 'io', 'tm': 'jr', 'tj': 'nt', 'tk': 'fh', 'th': 'ce', 'ti': 'ab', 'tf': 'eg', 'tg': 'qh', 'td': 'ba', 'te': 'mc', 'tb': 'wi', 'tc': 'wk', 'ta': 'zt', 'vu': 'zm', 'zl': 'ou', 'zm': 'im', 'zn': 'fz', 'zo': 'qt', 'zh': 'cz', 'zi': 'xl', 'zj': 'zi', 'zk': 'hu', 'zd': 'lv', 'ze': '_c', 'zf': 'xy', 'zg': 'dz', 'za': 'ka', 'zb': 'pd', 'zc': 'rw', 'zx': 'vi', 'zy': 'tw', 'zz': 'bi', 'zt': 'ac', 'zu': 'jl', 'zv': 'ec', 'zw': 'ub', 'zp': 'hh', 'zq': 'wf', 'zr': 'rg', 'zs': 'de', 't_': 'bg', 'z_': 'sa', 'o_': 'jm', 'tv': 'jp', 'wl': 'zu', 'va': 'mn', 'ts': 'om', 'vc': 'pl', 'wk': 'b_', 'vh': 'oz', 'wj': 'kl', 'vi': 'ii', 'vj': 'j_', 'vk': 'bj', 'vl': 'mi', 'vm': 'bw', 'wi': 'vl', 'vn': 'zf', 'm_': 'yc', 'vo': 'ew', 'me': 'tj', 'md': 'qn', 'mg': 'ho', 'mf': '_p', 'ma': 'kh', 'mc': 'qa', 'mb': 'kf', 'mm': 'ix', 'ml': 'zz', 'mo': 'ij', 'mn': 'ye', 'mi': 'ap', 'mh': 'xb', 'mk': 'oo', 'mj': 'be', 'mu': 'ms', 'mt': 'yl', 'mw': 'pq', 'mv': 'es', 'mq': 'xr', 'mp': 'dr', 'ms': 'px', 'mr': 'lk', 'vt': 'mk', 'my': 'xp', 'mx': 'vu', 'mz': 'bu', 'vv': 'xz', 'vw': 'gj', 'vx': 'sb', 'vz': 'jv', 'fp': 'bn', 'fq': 'vh', 'fr': 'fq', 'fs': 'pm', 'ft': 'je', 'fu': 'hn', 'fv': 'le', 'fw': 'vr', 'fx': 'ut', 'fy': 'ma', 'fz': 'za', 'fa': 'fg', 'fb': 'uv', 'fc': 'bh', 'fd': 'k_', 'fe': 'jc', 'ff': 'oe', 'fg': 'is', 'fh': 'ic', 'fi': '_i', 'fj': 'ag', 'fk': 'dd', 'fl': 'gx', 'fm': 'oj', 'fn': 'li', 'fo': 'mt', 'sz': '_g', 'sy': 'dy', 'ot': 'ls', 'ss': 'nq', 'sr': 'kz', 'sq': 're', 'sp': 'zk', 'sw': 'xc', 'sv': 'nb', 'su': 'vv', 'f_': 'ok', 'sk': 'tg', 'sj': 'xt', 'si': 'd_', 'sh': 'jy', 'so': 'ck', 'sn': 'du', 'sm': 'ct', 'sl': 'ax', 'sc': 'oc', 'sb': 'ob', 'sa': 'ip', 'sg': 'eb', 'sf': 's_', 'se': 'iq', 'sd': 'pj', '__': 'yh', 'l_': 'ua', 'lf': 'jb', 'lg': 'cd', 'ld': 'ws', 'le': 'l_', 'lb': 'uh', 'lc': 'dk', '_y': 'bf', 'la': 'qr', 'ln': 'ez', 'lo': 'vy', 'll': 'ph', 'lm': 'si', 'lj': 'os', 'lk': 'qs', 'lh': 'ne', 'li': 'jq', 'lv': 'xu', 'lw': 'st', 'lt': 'ti', 'lu': 'qx', 'lr': 'qm', 'ls': 'kj', 'lp': 'xf', 'lq': 'vq', '_g': 'nh', '_f': 'eu', '_e': 'cg', '_d': 'sx', 'lz': 'an', '_b': 'au', 'lx': 'np', 'ly': 'ux', 'wq': 'wv', 'yh': 'ai', 'yk': 'ug', 'yj': 'qj', 'ym': 'co', 'yl': 'ay', 'yo': 'sj', 'yn': 'hs', 'ya': 'zh', 'yc': 'pr', 'yb': 'mr', 'ye': 'pc', 'yd': 'pn', 'yg': 'vm', 'yf': 'ad', 'yy': 'ro', 'yx': '_h', 'yz': 'mw', 'yq': 'lx', 'yp': 'xw', 'ys': 'i_', 'yr': 'ny', 'yu': 'hp', 'yt': 'mb', 'yw': 'xv', 'yv': 'dv', 'y_': 'kq', 'em': 'tu', 'el': 'vd', 'eo': 'ft', 'en': 'ga', 'ei': 'no', 'eh': 'ig', 'ek': '_y', 'ej': 'ie', 'ee': 'ej', 'ed': '_d', 'eg': 'um', 'ef': 'by', 'ea': 'bb', 'ec': 'te', 'eb': 'jf', 'ey': 'yw', 'ex': 'il', 'ez': 'jx', 'eu': 'jd', 'et': 'gt', 'ew': 'pp', 'ev': 'rv', 'eq': 'rr', 'ep': 'fs', 'es': 'yn', 'er': 'oa', 'rt': 'rc', 'ru': 'sn', 'rv': 'ff', 'rw': 'hl', 'rp': 'ek', 'rq': 'ei', 'rr': 'zd', 'rs': 'nf', 'rx': '_e', 'ry': 'qc', 'rz': 'of', 'rd': 'ha', 're': 'lt', 'e_': 'lz', 'rg': 'fy', 'ra': 'sr', 'rb': 'me', 'rc': 'lm', 'rl': 'jg', 'rm': 'cb', 'rn': 'gl', 'ro': 'ex', 'rh': 'hw', 'ri': 'ib', 'rj': 'km', 'rk': 'gn', '_t': 'fv', 'n_': 'ur', 'xj': 'oy', 'xk': 'xm', 'xh': 'tm', 'xi': 'q_', 'xn': 'ey', 'xo': 'ss', 'xl': 'bc', 'xm': 'yf', 'xb': 'ym', 'xc': 'pt', 'xa': 'az', 'xf': 'cs', 'xg': 'vs', 'xd': 'hm', 'xe': 'uu', 'xz': 'qq', 'xx': 'zo', 'xy': 'yu', 'xr': 'ps', 'xs': 'cw', 'xp': 'rh', 'xq': 'dl', 'xv': 'h_', 'xw': 'x_', 'xt': 'ol', 'xu': '_q', 'wy': 'ww', 'x_': 'th', 'wh': 'my', 'wx': 'tc', 'sx': 'ed', '_s': 'tb', 'u_': 'ov', 'st': 'df', 'k_': 'xe', 'kc': 'dg', 'kb': 'uk', 'ka': 'yx', 'kg': 'dw', 'kf': 'tr', 'ke': 'bt', 'kd': 'zy', 'kk': 'qg', 'kj': 'bk', 'ki': 'ze', 'kh': 'pa', 'ko': 'pv', 'kn': 'gz', 'km': 'ql', 'kl': 'eq', 'ks': 'fp', 'kr': 'jo', 'kq': 'uo', 'kp': 'zj', 'kw': 'mh', 'kv': 'dp', 'ku': 'wa', 'kt': 'jn', 'kz': 'mg', 'ky': 'wl', 'kx': 'kd', 'dn': 'fc', 'do': 'uc', 'dl': 'tn', 'dm': 'pw', 'dj': 'wu', 'dk': 'va', 'dh': 'di', 'di': 'nn', 'df': 'cr', 'dg': 'ra', 'dd': 'ui', 'de': 'v_', 'db': 'ev', 'dc': 'kx', 'q_': 'sy', 'da': 'kn', 'dz': 'ts', 'dx': 'fo', 'dy': 'lr', 'dv': 'ku', 'dw': 'xg', 'dt': 'ht', 'du': '_t', 'dr': 'pe', 'ds': 'dn', 'dp': 'gg', 'dq': 'up', 'qq': '_w', 'qp': 'nv', 'qs': 'lc', 'qr': 'nd', 'qu': 'xq', 'qt': 'hj', 'qw': 'fu', 'qv': 'jw', 'qy': '__', 'qx': 'p_', 'qz': 'kv', '_z': 'fm', 'qa': 'yi', 'd_': 'la', 'qc': 'mx', 'qb': 'ot', 'qe': 'ue', 'qd': 'dq', 'qg': 'y_', 'qf': 'kk', 'qi': 'xh', 'qh': '_l', 'qk': 'rz', 'qj': 'ud', 'qm': 'ju', 'ql': 'ta', 'qo': 'zg', 'qn': 'qp', 'wc': 'f_', 'wb': 'ky', 'wa': 'wh', 'wo': 'vb', 'wn': 'ih', 'wm': '_s', 'wg': 'jk', 'wf': 'z_', 'we': 'nc', 'wd': 'wr', 'jx': 'ki', 'jy': 'py', 'jz': 'vk', 'jt': 'sc', 'ju': 'wy', 'jv': 'nx', 'jw': 'hi', 'jp': 'nm', 'jq': 'qk', 'jr': 'tl', 'js': 'bp', 'jl': 'in', 'jm': 'rs', 'jn': 'mm', 'jo': 'or', 'jh': 'xa', 'ji': 'pb', 'jj': '_n', 'jk': 'sp', 'jd': 'wx', 'je': 'bv', 'jf': 'dj', 'jg': 'hx', 'ja': 'db', 'jb': 'lg', 'jc': '_u', 'ww': 'gs', 'j_': 'yk', 'wv': 'yg', '_x': 'qf', 'wu': 'fj', '_w': 'eo', 'wt': '_r', '_v': 'qo', 'w_': 'na', 'ws': 'gh', '_u': 'zw', 'wr': 'sm', 'ck': 'yv', 'cj': 'cy', 'ci': 'tk', 'ch': 'xi', 'co': '_j', 'cn': '_o', 'cm': 'gr', 'cl': 'cp', 'cc': 'gu', 'cb': 'po', 'ca': 'lo', 'wp': 'n_', 'cg': 'zn', 'cf': 'qd', 'ce': 'kg', 'cd': 'un', 'cz': 'wd', 'cy': 'hz', 'cx': 'qi', '_q': 'tz', 'cs': 'vg', 'cr': 'nu', 'cq': 'iu', 'cp': 'ji', 'cw': 'wp', 'cv': 'ry', 'cu': 'tq', 'ct': 'wn', 'pr': 'yo', 'ps': 'gp', 'pp': 'he', 'pq': 'td', 'pv': '_v', 'pw': 'xn', 'pt': '_x', 'pu': 'vw', 'pz': 'ea', 'px': 'jz', 'py': 'lj', '_m': 'pf', 'wz': 'e_', 'pb': 'cj', 'pc': 'cu', 'pa': 'el', 'c_': 'et', 'pg': 'mj', 'pd': 'vf', 'pe': 'qv', 'pj': 'm_', 'pk': 've', 'ph': 'gf', 'pi': 'vc', 'pn': 'ly', 'po': 'nk', 'pl': 'rp', 'pm': 'jh', '_i': 'aq', '_h': 'hy', 's_': 'sd', '_r': 'op', '_c': 'kc', '_a': 'rd', 'iy': 'mp', 'ix': 'pz', 'vb': 'qu', 'iz': 'dx', 'vd': 'zc', 've': 'uz', 'vf': 'ng', 'vg': 'sw', 'iq': 'uf', 'ip': 'eh', 'is': 't_', 'ir': 'ks', 'iu': 'fn', 'it': 'rj', 'iw': 'dc', 'iv': 'kp', 'ii': 'we', 'ih': 'gd', 'ik': 'lu', 'ij': 'oq', 'im': 'js', 'il': 'ko', 'io': 'yt', 'in': 'wb', 'ia': 'ah', 'vy': 'af', 'ic': 'cq', 'ib': 'xo', 'ie': 'ge', 'id': '_m', 'ig': 'rf', 'if': 'pk', 'i_': 'kw', 'r_': 'ja', '_o': 'it', 'v_': 'ia', 'yi': 'fl', '_n': 'dh', 'vr': 'ox', '_l': 'zq', '_k': 'gq', '_j': 'cm', 'p_': 'ys', 'nv': 'us', 'ux': 'w_', 'vs': 'aj', 'bd': 'a_', 'be': 'cl', 'bf': 'hv', 'bg': 'nw', 'ba': 'vx', 'bb': 'o_', 'bc': 'sf', 'bl': 'gv', 'bm': 'vp', 'bn': 'jj', 'bo': 'rt', 'bh': 'kb', 'bi': 'ln', 'bj': 'gm', 'bk': 'yy', 'bt': '_f', 'bu': 'go', 'bv': 'pg', 'bw': 'aa', 'bp': 'jt', 'bq': 'mf', 'br': 'as', 'bs': 'ul', 'bx': 'sk', 'by': 'ar', 'bz': 'od', 'oo': 'id', 'on': 'ru', 'om': 'bq', 'ol': 'cc', 'ok': 'bx', 'oj': 'gi', 'oi': 'rl', 'oh': 'ca', 'og': 'zl', 'of': 'fd', 'oe': 'dm', 'od': 'wt', 'oc': 'ty', 'ob': 'yq', 'oa': 'br', 'oz': 'ao', 'oy': 'xx', 'ox': 'bm', 'ow': 'qz', 'ov': 'so', 'ou': 'vo', 'b_': 'rm', 'os': 'hk', 'or': 'ae', 'oq': 'qb', 'op': 'av', 'pf': 'iy', 'hz': 'sq', 'hx': 'tv', 'hy': 'ak', 'hr': 'zx', 'hs': 'dt', 'hp': 'mz', 'hq': 'g_', 'hv': 'rq', 'hw': 'yz', 'ht': 'vn', 'hu': 'ir', 'hj': 'zp', 'hk': '_b', 'hh': 'wj', 'hi': 'sh', 'hn': 'wz', 'ho': 'mu', 'hl': 'yd', 'hm': 'xs', 'hb': 'gk', 'hc': 'kt', 'ha': 'ni', 'hf': 'lp', 'hg': 'xd', 'hd': 'nz', 'he': 'll', '_p': 'yj', 'uy': 'zs', 'h_': 'fx', 'uz': 'hb', 'uu': 'hc', 'ut': 'qy', 'uw': 'am', 'uv': 'tx', 'uq': 'uw', 'up': 'zr', 'us': 'zv', 'ur': 'ml', 'um': 'gw', 'ul': 'mv', 'uo': 'ya', 'un': 'hf', 'ui': 'hr', 'uh': 'tp', 'uk': 'ef', 'uj': 'hg', 'ue': 'qw', 'ud': 'em', 'ug': 'ci', 'uf': 'sg', 'ua': 'zb', 'uc': 'rb', 'ub': 'yr', 'aa': 'ri', 'ac': 'wc', 'ab': 'yp', 'ae': 'fb', 'ad': 'nj', 'ag': 'fk', 'af': 'pi', 'ai': 'if', 'ah': 'r_', 'ak': 'vt', 'aj': 'ee', 'am': 'rk', 'al': 'mo', 'ao': 'u_', 'an': 'ik', 'aq': 'ke', 'ap': 'wo', 'as': 'uy', 'ar': 'lq', 'au': 'hd', 'at': 'bl', 'aw': 'iz', 'av': 'fi', 'ay': 'su', 'ax': 'on', 'az': 'oh', 'nh': 'vz', 'ni': 'ch', 'nj': 'uq', 'nk': 'ep', 'nl': 'hq', 'nm': 'rx', 'nn': 'se', 'no': '_z', 'na': 'ow', 'nb': 'wm', 'nc': 'nl', 'nd': 'al', 'ne': 'kr', 'nf': '_a', 'ng': 'ld', 'nx': 'lf', 'ny': 'rn', 'nz': 'yb', 'np': 'er', 'nq': 'bo', 'nr': 'lh', 'ns': 'sz', 'nt': 'do', 'nu': 'iv', 'a_': 'cv', 'nw': 'ns', 'vp': 'sl', 'vq': 'oi'}, 'aeq_tywjfkhowelwbmzsfufvhykieccelbszgsfha_xhkdksaqcmfjd_qh')
certain_box, possible_box = crack_double_map(double_box)

boxes = find_all(certain_box, possible_box)
print(len(boxes))
for certain_box in boxes:
	print(decrypt(c_flag, certain_box))
```

By browsing the output for a while, we can find the flag: 

`slide_attack_still_relevant_for_home_rolled_crypto_systems`