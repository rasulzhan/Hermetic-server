

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

#ifndef _ccr_tiger_hash_h_
#define _ccr_tiger_hash_h_

#if HAVE_CRYPTOPP==1

#include "hash.h"

#if CRYPTOPP_DIR_PLUS
#  include <crypto++/tiger.h>
#else
#  include <cryptopp/tiger.h>
#endif

//it's used just like SHA, so create it from SHA
class tiger192hash : public shahash<CryptoPP::Tiger> {};
class tiger192proc : public shaproc<CryptoPP::Tiger> {};

#endif //HAVE_CRYPTOPP==1

#endif
