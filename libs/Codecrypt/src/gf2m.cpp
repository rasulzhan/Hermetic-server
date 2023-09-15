
/*
 * This file is part of Codecrypt.
 *
 * Copyright (C) 2013-2016 Mirek Kratochvil <exa.exa@gmail.com>
 *
 * Codecrypt is free software: you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or (at
 * your option) any later version.
 *
 * Codecrypt is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public
 * License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with Codecrypt. If not, see <http://www.gnu.org/licenses/>.
 */

#include "gf2m.h"

/*
 * helpful stuff for arithmetic in GF(2^m) - polynomials over GF(2).
 */

int gf2p_degree (uint p)
{
	int r = 0;
	while (p) {
		++r;
		p >>= 1;
	}
	return r - 1;
}

uint gf2p_mod (uint a, uint p)
{
	if (!p) return 0;
	int t, degp = gf2p_degree (p);
	while ( (t = gf2p_degree (a)) >= degp) {
		a ^= (p << (t - degp));
	}
	return a;
}

uint gf2p_gcd (uint a, uint b)
{
	if (!a) return b;
	while (b) {
		uint c = gf2p_mod (a, b);
		a = b;
		b = c;
	}
	return a;
}

uint gf2p_modmult (uint a, uint b, uint p)
{
	a = gf2p_mod (a, p);
	b = gf2p_mod (b, p);
	uint r = 0;
	uint d = 1 << gf2p_degree (p);
	if (b) while (a) {
			if (a & 1) r ^= b;
			a >>= 1;
			b <<= 1;
			if (b >= d) b ^= p;
		}
	return r;
}

bool is_irreducible_gf2_poly (uint p)
{
	if (!p) return false;
	int d = gf2p_degree (p) / 2;
	uint test = 2; //x^1+0
	for (int i = 1; i <= d; ++i) {
		test = gf2p_modmult (test, test, p);

		if (gf2p_gcd (test ^ 2 /* test - x^1 */, p) != 1)
			return false;
	}
	return true;
}

bool gf2m::create (uint M)
{
	if (M < 1) return false; //too small.
	m = M;
	n = 1 << m;
	if (!n) return false; //too big.
	poly = 0;

	/*
	 * find a conway polynomial for given degree. First we "filter out" the
	 * possibilities that cannot be conway (reducible ones), then we check
	 * that Z2[x]/poly is a field.
	 */
	for (uint t = (1 << m) + 1, e = 1 << (m + 1); t < e; t += 2) {

		if (!is_irreducible_gf2_poly (t)) continue;

		//try to prepare log and antilog tables
		log.resize (n, 0);
		antilog.resize (n, 0);
		log[0] = n - 1;
		antilog[n - 1] = 0;

		uint i, xi = 1; //x^0
		for (i = 0; i < n - 1; ++i) {
			if (log[xi] != 0) { //not a cyclic group
				log.clear();
				antilog.clear();
				break;
			}
			log[xi] = i;
			antilog[i] = xi;

			xi <<= 1; //multiply by x
			xi = gf2p_mod (xi, t);
		}

		//if it broke...
		if (i < n - 1) continue;
		poly = t;
		break;
	}

	if (!poly) return false;

	return true;
}
