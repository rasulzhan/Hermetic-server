#ifndef __SSH_OPENSSL_H__
#define __SSH_OPENSSL_H__

#include <openssl/bn.h>
#if defined(_WIN32)
#else
#include <fstream>
#include <iostream>
#include <string>
#include <cerrno>
#include <clocale>

#endif

#ifndef errno_t
#define errno_t FILE*
#endif

#ifndef fopen_s
#define fopen_s(fp, fmt, mode)          *(fp)=fopen( (fmt), (mode))
#endif


int curve25519_new(unsigned char* out_public_key, unsigned char* out_private_key);
int curve25519_gen_k(unsigned char* local_private_key, unsigned char* server_public_key, BIGNUM* k_bn);

int nistp_sign_verify(
    const unsigned char* hostkey, unsigned int hostkey_len, 
    const unsigned char* sign, unsigned int sign_len, 
    unsigned char* m, unsigned int m_len);

int read_publickey(const char *pubkey, unsigned char **pubkey_data, size_t& pubkey_len);
int read_privatekey_openssh(void **ctx, const char *privkey, const char *passphrase);

int sign_rsa_privatekey(const char *privkey, const char *passphrase, const unsigned char *data, size_t datalen, unsigned char **sign, size_t& signlen);

int get_sshstring(const unsigned char **in, size_t& inlen, const unsigned char **out, size_t& outlen);
int get_sshbignum_bytes(const unsigned char **in, size_t& inlen, const unsigned char **out, size_t& outlen);

int hostkey_method_ssh_rsa_signv(unsigned char **signature, size_t& signature_len,
    const unsigned char *iov_base, size_t iov_len, void **ctx);

#endif // __SSH_OPENSSL_H__