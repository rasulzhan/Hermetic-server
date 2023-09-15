#ifndef __asymmetric_h_
#define __asymmetric_h_

#include "libs/Codecrypt/src/algos_enc.h"
#include "libs/Codecrypt/src/sencode.h"
#include "libs/Codecrypt/src/mce_qcmdpc.h"
#include "libs/Codecrypt/src/arcfour.h"
#include "libs/Codecrypt/src/generator.h"

namespace asymmetric {

static algo_mceqcmdpc128cube algo;

static int gen_pair(std::string& pub_str, std::string& priv_str)
{
	sencode* pub, * priv;
	ccr_rng rng;
	algo.create_keypair(&pub, &priv, rng);

	pub_str = pub->encode();
	priv_str = priv->encode();

	return 0;
}

static int encrypt (std::vector<uint8_t>& in, std::vector<uint8_t>& out, std::string pubkey, size_t& ciphersize)
{
	bvector p;
	bvector c;
	ccr_rng rng;
	p.from_bytes(in);
	sencode* key = sencode_decode(pubkey);
	algo.encrypt(p, c, key, rng);
	c.to_bytes(out);
	ciphersize = c.size();
	return 0;
}

static int encrypt (std::string& in, std::string& out, std::string pubkey, size_t& ciphersize)
{
	bvector p;
	bvector c;
	ccr_rng rng;
	p.from_string(in);
	sencode* key = sencode_decode(pubkey);
	algo.encrypt(p, c, key, rng);
	c.to_string(out);
	ciphersize = c.size();
	return 0;
}

static int decrypt (std::vector<uint8_t>& out, std::vector<uint8_t>& in, std::string privkey, size_t& ciphersize)
{
	bvector p;
	bvector c;
	c.from_bytes(in);
	c.resize(ciphersize, 0);
	sencode* key = sencode_decode(privkey);
	algo.decrypt(c, p, key);
	p.to_bytes(out);
	return 0;
}

static int decrypt (std::string& out, std::string& in, std::string privkey, size_t& ciphersize)
{
	bvector p;
	bvector c;
	c.from_string(in);
	c.resize(ciphersize, 0);
	sencode* key = sencode_decode(privkey);
	algo.decrypt(c, p, key);
	p.to_string(out);
	return 0;
}

}
#endif __asymmetric_h_