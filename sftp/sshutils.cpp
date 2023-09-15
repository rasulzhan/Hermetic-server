#include "sshutils.h"
#include <cstring>
#include <ctype.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/sha.h>
#include <openssl/pem.h>
#include <openssl/blowfish.h>
#include "sshconst.h"
#include "sshlog.h"
#include "utils.h"
#include "bcrypt/blf.h"

int curve25519_new(unsigned char* out_public_key, unsigned char* out_private_key)
{
    EVP_PKEY* key = NULL;
    EVP_PKEY_CTX* pctx = NULL;
    size_t length;
    int rc = -1;

    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
    if (pctx == NULL) {
        return -1;
    }

    if (EVP_PKEY_keygen_init(pctx) != 1 || EVP_PKEY_keygen(pctx, &key) != 1) {
        goto exit;
    }

    if (out_private_key != NULL) {
        length = 32;
        if (EVP_PKEY_get_raw_private_key(key, out_private_key, &length) != 1) {
            goto exit;
        }
    }

    if (out_public_key != NULL) {
        length = 32;
        if (EVP_PKEY_get_raw_public_key(key, out_public_key, &length) != 1) {
            goto exit;
        }

    }
    rc = 1;
exit:
    if (pctx) {
        EVP_PKEY_CTX_free(pctx);
    }
    if (key) {
        EVP_PKEY_free(key);
    }
    return rc;
}

int curve25519_gen_k(unsigned char* local_private_key, unsigned char* server_public_key, BIGNUM* k_bn)
{
    int rc = -1;
    EVP_PKEY *peer_key = NULL, *local_key = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    BN_CTX *bn_ctx = NULL;
    size_t out_len = 0;
    unsigned char out_shared_key[32];

    bn_ctx = BN_CTX_new();
    if (bn_ctx == NULL) {
        return -1;
    }

    peer_key = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, server_public_key, 32);
    local_key = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, local_private_key, 32);
    if (peer_key == NULL || local_key == NULL) {
        goto exit;
    }

    ctx = EVP_PKEY_CTX_new(local_key, NULL);
    if (ctx == NULL) {
        goto exit;
    }

    rc = EVP_PKEY_derive_init(ctx);
    if (rc <= 0) {
        goto exit;
    }

    rc = EVP_PKEY_derive_set_peer(ctx, peer_key);
    if (rc <= 0) {
        goto exit;
    }

    rc = EVP_PKEY_derive(ctx, NULL, &out_len);
    if (rc <= 0) {
        goto exit;
    }

    if (out_len != 32) {
        rc = -1;
        goto exit;
    }

    rc = EVP_PKEY_derive(ctx, out_shared_key, &out_len);

    if (rc == 1 && out_len == 32) {
        BN_bin2bn(out_shared_key, 32, k_bn);
    } else {
        rc = -1;
    }

exit:
    if (ctx) {
        EVP_PKEY_CTX_free(ctx);
    }
    if (peer_key) {
        EVP_PKEY_free(peer_key);
    }
    if (local_key) {
        EVP_PKEY_free(local_key);
    }
    if (bn_ctx) {
        BN_CTX_free(bn_ctx);
    }
    return rc;
}

int nistp_sign_verify(const unsigned char* hostkey, unsigned int hostkey_len, const unsigned char* sign, unsigned int sign_len, unsigned char* m, unsigned int m_len)
{
    int rc = -1;
    int t = NID_X9_62_prime256v1;

    const unsigned char *hk_name = NULL, *hk_domain = NULL, *hk_key = NULL, *r_ = NULL, *s_ = NULL;
    size_t length = 0, tmp_len = 0, hk_name_len = 0, hk_domain_len = 0, 
        hk_key_len = 0, r_len = 0, s_len = 0;
    EC_POINT *point = NULL;
    const EC_GROUP *ec_group = NULL;
    BIGNUM *pr = NULL, *ps = NULL;
    ECDSA_SIG *ecdsa_sig = NULL;
    unsigned char hash[SHA256_DIGEST_LENGTH];
    EVP_MD_CTX* ctx = NULL;

    const unsigned char *p = hostkey;
    length = hostkey_len;

    get_sshstring(&p, length, &hk_name, hk_name_len);
    get_sshstring(&p, length, &hk_domain, hk_domain_len);
    get_sshstring(&p, length, &hk_key, hk_key_len);

    EC_KEY *ec_key = EC_KEY_new_by_curve_name(t);
    if (!ec_key) {
        goto exit;
    }
    ec_group = EC_KEY_get0_group(ec_key);
    point = EC_POINT_new(ec_group);
    if (EC_POINT_oct2point(ec_group, point, hk_key, hk_key_len, NULL) != 1) {
        goto exit;
    }
    if (EC_KEY_set_public_key(ec_key, point) != 1) {
        goto exit;
    }

    ecdsa_sig = ECDSA_SIG_new();
    if (!ecdsa_sig) {
        goto exit;
    }
    pr = BN_new();
    ps = BN_new();

    p = sign;
    length = sign_len;

    tmp_len = ntonu32(p);   
    p += tmp_len + 4 + 4; // SKIP LENGTH

    get_sshstring(&p, length, &r_, r_len);
    get_sshstring(&p, length, &s_, s_len);

    BN_bin2bn(r_, r_len, pr); // 1
    BN_bin2bn(s_, s_len, ps); // 2
    if (ECDSA_SIG_set0(ecdsa_sig, pr, ps) != 1) {
        goto exit;
    }

    ctx = EVP_MD_CTX_new();
    if (!ctx) {
        goto exit;
    }
    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1) {
        goto exit;
    }
    if (EVP_DigestUpdate(ctx, m, m_len) != 1) {
        goto exit;
    }
    if (EVP_DigestFinal(ctx, hash, NULL) != 1) {
        goto exit;
    }

    rc = ECDSA_do_verify(hash, SHA256_DIGEST_LENGTH, ecdsa_sig, ec_key);

exit:
    if (point) {
        EC_POINT_free(point);
    }
    /*
    if (pr) {
        BN_free(pr);
    }
    if (ps) {
        BN_free(ps);
    }
    */
    if (ecdsa_sig) {
        ECDSA_SIG_free(ecdsa_sig);
    }
    if (ctx) {
        EVP_MD_CTX_free(ctx);
    }
    return rc;
}

int read_publickey(const char *pubkey, unsigned char **pubkey_data, size_t& pubkey_len)
{
    int rc = -1;
    char c;
    FILE *fd = NULL;
    size_t data_len = 0, sp_len = 0;
    unsigned char *data = NULL, *sp1 = NULL, *sp2 = NULL;

    errno_t err = fopen_s(&fd, pubkey, "rt");
    if (fd == NULL) {
        LOGERR("Unable to open public key file: '%s'", pubkey);
        return -1;
    }
    while (!feof(fd) && 1 == fread(&c, 1, 1, fd) && c != '\r' && c != '\n') {
        data_len++;
    }
    rewind(fd);
    if (data_len <= 1) {
        LOGERR("Invalid data in public key file");
        goto exit;
    }
    data = new unsigned char[data_len];
    if (fread(data, 1, data_len, fd) != data_len) {
        LOGERR("Unable to read public key from file");
        goto exit;
    }
    fclose(fd);
    fd = NULL;

    while (data_len && isspace(data[data_len - 1])) {
        data_len--;
    }
    sp1 = (unsigned char*)memchr(data, ' ', data_len);
    if (sp1 == NULL) {
        LOGERR("Invalid public key data");
        goto exit;
    }
    sp1++;
    sp_len = sp1 > data ? (sp1 - data) - 1 : 0;
    sp2 = (unsigned char*)memchr(sp1, ' ', data_len - sp_len);
    if (sp2 == NULL) {
        sp2 = data + data_len;
    }

    if (base64_decode((char**)pubkey_data, pubkey_len, (char*)sp1, sp2 - sp1) != 1) {
        LOGERR("Invalid key data, not base64 encoded");
        goto exit;
    }
    rc = 1;

exit:
    if (fd) {
        fclose(fd);
    }
    if (data) {
        delete[] data;
    }
    return rc;
}

int sign_rsa_privatekey(const char *privkey, const char *passphrase, 
    const unsigned char *data, size_t datalen,
    unsigned char **sign, size_t& signlen)
{
    int rc = -1;

    BIO *bp = NULL;
    RSA *rsa = NULL;

    bp = BIO_new_file(privkey, "r");
    if (bp == NULL) {
        LOGERR("Unable to open private key");
        goto exit;
    }
    BIO_reset(bp);
    rsa = PEM_read_bio_RSAPrivateKey(bp, NULL, NULL, (void *)passphrase);
    if (rsa == NULL) {
        LOGERR("Try to read OpenSSH format");
        if (read_privatekey_openssh((void**)&rsa, privkey, passphrase) != 1 || rsa == NULL) {
            LOGERR("Unable to read private key");
            goto exit;
        }
    }
    if (hostkey_method_ssh_rsa_signv(sign, signlen, data, datalen, (void**)&rsa) != 1) {
        goto exit;
    }
    rc = 1;
exit:
    if (bp) {
        BIO_free(bp);
    }
    if (rsa) {
        RSA_free(rsa);
    }
    return rc;
}

/*
OpenSSH format

"openssh-key-v1"0x00    # NULL-terminated "Auth Magic" string
32-bit length, "none"   # ciphername length and string
32-bit length, "none"   # kdfname length and string
32-bit length, nil      # kdf (0 length, no kdf)
32-bit 0x01             # number of keys, hard-coded to 1 (no length)
32-bit length, sshpub   # public key in ssh format
    32-bit length, keytype
    32-bit length, pub0
    32-bit length, pub1
32-bit length for rnd+prv+comment+pad
    64-bit dummy checksum?  # a random 32-bit int, repeated
    32-bit length, keytype  # the private key (including public)
    32-bit length, pub0     # Public Key parts
    32-bit length, pub1
    32-bit length, prv0     # Private Key parts
    ...                     # (number varies by type)
    32-bit length, comment  # comment string
    padding bytes 0x010203  # pad to blocksize (see notes below)
*/

int openssh_pem_parse_data(const char *passphrase, const char *b64data, size_t b64datalen, unsigned char **decrypted, size_t& decrypted_len)
{
    int rc = -1;

    uint32_t nkeys, check1, check2, rounds = 0;
    int keylen = 0, ivlen = 0, total_len = 0;
    const char *ciphername = NULL, *kdfname = NULL;
    unsigned char *privdata = NULL, *p = NULL, *kdf = NULL, *buf = NULL, 
        *key = NULL, *salt = NULL, *key_part = NULL, *iv_part = NULL;
    size_t privdata_len = 0, ciphername_len = 0, kdfname_len = 0, 
        kdf_len = 0, buf_len = 0, salt_len = 0, tmp_len = 0, blocksize = 0;
    unsigned char block[EVP_MAX_BLOCK_LENGTH];
    EVP_CIPHER_CTX *ctx = NULL;

    if (decrypted) {
        *decrypted = NULL;
    }

    /* decode file */
    if (base64_decode((char **)&privdata, privdata_len, b64data, b64datalen) != 1) {
        goto exit;
    }

    /* Parse the file */
    if (privdata_len < strlen(OPENSSH_AUTH_MAGIC)) {
        LOGERR("Private key too short");
        goto exit;
    }
    if (strncmp((char *)privdata, OPENSSH_AUTH_MAGIC, strlen(OPENSSH_AUTH_MAGIC)) != 0) {
        LOGERR("Private key is not: '%s'", OPENSSH_AUTH_MAGIC);
        goto exit;
    }
    p = privdata + strlen(OPENSSH_AUTH_MAGIC) + 1;
    ciphername_len = ntonu32(p);
    if (ciphername_len == 0) {
        LOGERR("Cipher name is missing");
        goto exit;
    }
    ciphername = (char*)(p + 4);
    p += 4 + ciphername_len;

    if ((passphrase == NULL || strlen(passphrase) == 0) && 
        strcmp(ciphername, "none") != 0) {
        LOGERR("Passphrase is required");
        goto exit;
    }
    
    if (strncmp((char*)ciphername, "aes256-ctr", 10) != 0) {
        LOGERR("The cipher '%.*s' is unsupported. Currently only aes256-ctr is supported.", (int)ciphername_len, ciphername);
        goto exit;
    }

    kdfname_len = ntonu32(p);
    if (kdfname_len == 0) {
        LOGERR("KDF name is missing");
        goto exit;
    }
    kdfname = (char*)(p + 4);
    p += 4 + kdfname_len;

    kdf_len = ntonu32(p);
    if (kdf_len == 0) {
        LOGERR("KDF is missing");
        goto exit;
    }
    kdf = p + 4;
    p += 4 + kdf_len;

    if (strcmp((const char *)kdfname, "none") != 0 &&
        strcmp((const char *)kdfname, "bcrypt") != 0) {
        LOGERR("Unknown cipher: %.*s", (int)kdfname_len, kdfname);
        goto exit;
    }
    if (!strcmp((const char *)kdfname, "none") &&
        strcmp((const char *)ciphername, "none") != 0) {
        LOGERR("Invalid format");
        goto exit;
    }

    nkeys = ntonu32(p);
    p += 4;

    if (nkeys != 1) {
        LOGERR("Multiple keys are unsupported");
        goto exit;
    }

    // unencrypted public key 
    buf_len = ntonu32(p);
    if (buf_len == 0) {
        LOGERR("Invalid private key. Expect embedded public key.");
        goto exit;
    }
    p += 4 + buf_len;
    buf_len = ntonu32(p);
    if (buf_len == 0) {
        LOGERR("Private key data not found");
        goto exit;
    }
    buf = p + 4;
    p += 4 + buf_len;
   
    // aes256-ctr
    keylen = 32;
    ivlen = 16;
    blocksize = 16;

    total_len = keylen + ivlen;

    key = new unsigned char[total_len];

    if (strcmp((const char *)kdfname, "bcrypt") == 0 && passphrase != NULL) {
        unsigned char *kdf_buf = kdf;
        salt_len = ntonu32(kdf_buf);
        if (salt_len == 0) {
            LOGERR("kdf contains unexpected values");
            goto exit;
        }
        salt = kdf_buf + 4;
        kdf_buf += 4 + salt_len;
        rounds = ntonu32(kdf_buf);

        if (bcrypt_pbkdf(passphrase, strlen(passphrase), salt, salt_len, key, keylen + ivlen, rounds) != 1) {
            LOGERR("Invalid format");
            goto exit;
        }
    } else {
        LOGERR("bcrypted without passphrase");
        goto exit;
    }

    key_part = new unsigned char[keylen];
    iv_part  = new unsigned char[ivlen];

    memcpy(key_part, key, keylen);
    memcpy(iv_part, key + keylen, ivlen);

    ctx = EVP_CIPHER_CTX_new();
    EVP_CipherInit(ctx, EVP_aes_256_ctr(), key_part, iv_part, 0);

    // Do the actual decryption 
    if ((buf_len % blocksize) != 0) {
        goto exit;
    }

    tmp_len = 0;
    while (tmp_len <= buf_len - blocksize) {
        rc = EVP_Cipher(ctx, block, buf + tmp_len, blocksize);
        memcpy(buf + tmp_len, block, blocksize);
        tmp_len += blocksize;
    }

    p = buf;
    check1 = ntonu32(p);
    p += 4;
    check2 = ntonu32(p);
    if (check1 != check2) {
        LOGERR("Private key unpack failed (does password is correct?)");
        goto exit;
    }

    if (decrypted) {
        *decrypted = new unsigned char[buf_len];
        memcpy(*decrypted, buf, buf_len);
        decrypted_len = buf_len;
    }

    rc = 1;
exit:
    if (privdata) {
        delete[] privdata;
        privdata = nullptr;
    }
    if (key) {
        delete key;
        key = nullptr;
    }
    if (key_part) {
        delete[] key_part;
        key_part = nullptr;
    }
    if (iv_part) {
        delete[] iv_part;
        iv_part = nullptr;
    }
    if (ctx) {
        EVP_CIPHER_CTX_free(ctx);
    }
    return rc;
}

int get_sshstring(const unsigned char **in, size_t& inlen, const unsigned char **out, size_t& outlen)
{
    if (inlen < 4 || in == NULL || out == NULL) {
        return -1;
    }
    outlen = ntonu32(*in);
    if (inlen - 4 < outlen) {
        return -1;
    }
    *out = *in + 4;
    *in   += 4 + outlen;
    inlen -= 4 + outlen;
    return 1;
}

int get_sshbignum_bytes(const unsigned char **in, size_t& inlen, const unsigned char **out, size_t& outlen)
{
    if (get_sshstring(in, inlen, out, outlen) != 1) {
        return -1;
    }
    /* trim leading zeros */
    while (outlen > 0 && **out == 0x00) {
        outlen--;
        (*out)++;
    }
    return 1;
}

unsigned char* write_bn(unsigned char *buf, const BIGNUM *bn, int bn_bytes)
{
    unsigned char *p = buf;

    /* Left space for bn size which will be written below. */
    p += 4;

    *p = 0;
    BN_bn2bin(bn, p + 1);
    if (!(*(p + 1) & 0x80)) {
        memmove(p, p + 1, --bn_bytes);
    }
    htonu32(p - 4, bn_bytes);  /* Post write bn size. */

    return p + bn_bytes;
}

int rsa_new(RSA **rsa, 
    const unsigned char *edata, unsigned long elen,
    const unsigned char *ndata, unsigned long nlen,
    const unsigned char *ddata, unsigned long dlen,
    const unsigned char *pdata, unsigned long plen,
    const unsigned char *qdata, unsigned long qlen,
    const unsigned char *e1data, unsigned long e1len,
    const unsigned char *e2data, unsigned long e2len,
    const unsigned char *coeffdata, unsigned long coefflen)
{
    BIGNUM * e;
    BIGNUM * n;
    BIGNUM * d = 0;
    BIGNUM * p = 0;
    BIGNUM * q = 0;
    BIGNUM * dmp1 = 0;
    BIGNUM * dmq1 = 0;
    BIGNUM * iqmp = 0;
    int rc = -1;

    e = BN_new();
    if (!BN_bin2bn(edata, elen, e)) {
        goto exit;
    }
    n = BN_new();
    if (!BN_bin2bn(ndata, nlen, n)) {
        goto exit;
    }
    if (ddata) {
        d = BN_new();
        if (!BN_bin2bn(ddata, dlen, d)) {
            goto exit;
        }
        p = BN_new();
        if (!BN_bin2bn(pdata, plen, p)) {
            goto exit;
        }
        q = BN_new();
        if (!BN_bin2bn(qdata, qlen, q)) {
            goto exit;
        }
        dmp1 = BN_new();
        if (!BN_bin2bn(e1data, e1len, dmp1)) {
            goto exit;
        }
        dmq1 = BN_new();
        if (!BN_bin2bn(e2data, e2len, dmq1)) {
            goto exit;
        }
        iqmp = BN_new();
        if (!BN_bin2bn(coeffdata, coefflen, iqmp)) {
            goto exit;
        }
    }
    *rsa = RSA_new();
    if (RSA_set0_key(*rsa, n, e, d) != 1) {
        goto exit;
    }
    if (RSA_set0_factors(*rsa, p, q) != 1) {
        goto exit;
    }
    if (RSA_set0_crt_params(*rsa, dmp1, dmq1, iqmp) != 1) {
        goto exit;
    }
    rc = 1;
exit:
    if (rc != 1) {
        if (*rsa) {
            RSA_free(*rsa);
            *rsa = NULL;
        }
    }
    return rc;
}

int rsa_new_additional_parameters(RSA *rsa)
{
    BN_CTX *ctx = NULL;
    BIGNUM *aux = NULL;
    BIGNUM *dmp1 = NULL;
    BIGNUM *dmq1 = NULL;
    const BIGNUM *p = NULL;
    const BIGNUM *q = NULL;
    const BIGNUM *d = NULL;
    int rc = -1;

    RSA_get0_key(rsa, NULL, NULL, &d);
    RSA_get0_factors(rsa, &p, &q);

    ctx = BN_CTX_new();
    if (ctx == NULL) {
        goto exit;
    }
    aux = BN_new();
    if (aux == NULL) {
        goto exit;
    }
    dmp1 = BN_new();
    if (dmp1 == NULL) {
        goto exit;
    }
    dmq1 = BN_new();
    if (dmq1 == NULL) {
        goto exit;
    }
    if ((BN_sub(aux, q, BN_value_one()) == 0) ||
        (BN_mod(dmq1, d, aux, ctx) == 0) ||
        (BN_sub(aux, p, BN_value_one()) == 0) ||
        (BN_mod(dmp1, d, aux, ctx) == 0)) {
        goto exit;
    }
    if (RSA_set0_crt_params(rsa, dmp1, dmq1, NULL) != 1) {
        goto exit;
    }
    rc = 1;
exit:
    if (aux) {
        BN_clear_free(aux);
    }
    if (ctx) {
        BN_CTX_free(ctx);
    }
    if (rc != 1) {
        if (dmp1) {
            BN_clear_free(dmp1);
        }
        if (dmq1) {
            BN_clear_free(dmq1);
        }
    }
    return rc;
}

unsigned char *gen_publickey_from_rsa(RSA *rsa, size_t& key_len)
{
    int  e_bytes, n_bytes;
    unsigned long len;
    unsigned char *key, *p;
    const BIGNUM *e, *n;

    RSA_get0_key(rsa, &n, &e, NULL);
    e_bytes = BN_num_bytes(e) + 1;
    n_bytes = BN_num_bytes(n) + 1;

    /* Key form is "ssh-rsa" + e + n. */
    len = 4 + 7 + 4 + e_bytes + 4 + n_bytes;

    key = new unsigned char[len];
    if (key == NULL) {
        return NULL;
    }

    /* Process key encoding. */
    p = key;
    htonu32(p, 7);  /* Key type. */
    p += 4;
    memcpy(p, "ssh-rsa", 7);
    p += 7;
    p = write_bn(p, e, e_bytes);
    p = write_bn(p, n, n_bytes);

    key_len = (size_t)(p - key);
    return key;
}

int gen_publickey_from_rsa_evp(unsigned char **method, size_t *method_len,
    unsigned char **pubkeydata, size_t *pubkeydata_len, EVP_PKEY *pk)
{
    RSA* rsa = NULL;
    unsigned char *key;
    unsigned char *method_buf = NULL;
    size_t  key_len;
    int rc = -1;

    LOGINF("Computing public key from RSA private key envelop");

    rsa = EVP_PKEY_get1_RSA(pk);
    if (rsa == NULL) {
        goto exit;
    }
    method_buf = new unsigned char[7];  /* ssh-rsa. */
    if (method_buf == NULL) {
        goto exit;
    }
    key = gen_publickey_from_rsa(rsa, key_len);
    if (key == NULL) {
        goto exit;
    }

    memcpy(method_buf, "ssh-rsa", 7);
    *method = method_buf;
    *method_len = 7;
    *pubkeydata = key;
    *pubkeydata_len = key_len;
    rc = 1;
exit:
    if (rsa) {
        RSA_free(rsa);
    }
    if (method_buf) {
        delete[] method_buf;
        method_buf = nullptr;
    }
    return rc;
}

int gen_publickey_from_rsa_openssh_priv_data(const unsigned char *decrypted, size_t decrypted_len,
    unsigned char **method, size_t *method_len, unsigned char **pubkeydata,
    size_t *pubkeydata_len, void **rsa_ctx)
{
    int rc = -1;
    size_t nlen, elen, dlen, plen, qlen, coefflen, commentlen, len;
    const unsigned char *n, *e, *d, *p, *q, *coeff, *comment, *data;
    RSA *rsa = NULL;
    EVP_PKEY *pk = NULL;

    LOGINF("Computing RSA keys from private key data");

    if (rsa_ctx == NULL) {
        goto exit;
    }

    data = decrypted;
    len = decrypted_len;

    /* public key data */
    if (get_sshbignum_bytes(&data, len, &n, nlen) != 1) {
        LOGERR("RSA no n");
        goto exit;
    }
    if (get_sshbignum_bytes(&data, len, &e, elen) != 1) {
        LOGERR("RSA no e");
        goto exit;
    }
    /* private key data */
    if (get_sshbignum_bytes(&data, len, &d, dlen) != 1) {
        LOGERR("RSA no d");
        goto exit;
    }
    if (get_sshbignum_bytes(&data, len, &coeff, coefflen) != 1) {
        LOGERR("RSA no coeff");
        return -1;
    }
    if (get_sshbignum_bytes(&data, len, &p, plen) != 1) {
        LOGERR("RSA no p");
        goto exit;
    }
    if (get_sshbignum_bytes(&data, len, &q, qlen) != 1) {
        LOGERR("RSA no q");
        goto exit;
    }
    if (get_sshstring(&data, len, &comment, commentlen) != 1) {
        LOGERR("RSA no comment");
        goto exit;
    }
    if (rsa_new(&rsa, e, elen, n, nlen, d, dlen, p, plen,
        q, qlen, NULL, 0, NULL, 0, coeff, coefflen) != 1 || rsa == NULL) {
        LOGERR("Could not create RSA private key");
        goto exit;
    }
    if (rsa_new_additional_parameters(rsa) != 1) {
        LOGERR("Could not add RSA additional parameters");
        goto exit;
    }
    if (rsa != NULL && pubkeydata != NULL && method != NULL) {
        pk = EVP_PKEY_new();
        if (EVP_PKEY_set1_RSA(pk, rsa) != 1) {
            LOGERR("Could not set RSA private key");
            goto exit;
        }

        if (gen_publickey_from_rsa_evp(method, method_len, pubkeydata, pubkeydata_len, pk) != 1) {
            goto exit;
        }
    }

    *rsa_ctx = rsa;
    rc = 1;
exit:
    if (pk) {
        EVP_PKEY_free(pk);
    }
    if (rc != 1) {
        if (rsa) {
            RSA_free(rsa);
        }
    }
    return rc;
}

int read_privatekey_openssh(void **ctx, const char *privkey, const char *passphrase)
{
    int rc = -1;

    FILE *fd = NULL;
    char *b64data = NULL, *p;
    size_t linelen = 0, decrypted_len = 0, data_len = 0,
        method_len = 0;
    unsigned char *decrypted = NULL;
    const unsigned char *data = NULL, *method = NULL;
    char line[128] = { 0 };

    errno_t err = fopen_s(&fd, privkey, "r");
    if (fd == NULL) {
        LOGERR("Unable to open private key file: '%s'", privkey);
        goto exit;
    }
    while (strcmp(line, OPENSSH_HEADER_BEGIN) != 0) {
        *line = '\0';
        if (readline(line, 128, fd)) {
            goto exit;
        }
    }
    if (strcmp(line, OPENSSH_HEADER_BEGIN)) {
        LOGERR("Not an OpenSSH private key format");
        goto exit;
    }
    if (readline(line, 128, fd)) {
        goto exit;
    }
    b64data = new char[4096];
    p = b64data;
    while (strcmp(line, OPENSSH_HEADER_END) != 0) {
        if (*line) {
            linelen = strlen(line);
            memcpy(p, line, linelen);
            p += linelen;
        }
        *line = '\0';
        if (readline(line, 128, fd)) {
            goto exit;
        }
    }
    if (openssh_pem_parse_data(passphrase, b64data, p - b64data, &decrypted, decrypted_len) != 1) {
        goto exit;
    }
    data     = decrypted + 8; // 2*DWORD are check dwords, skip it, we've already cheked
    data_len = decrypted_len - 8;
    if (get_sshstring(&data, data_len, &method, method_len) != 1) {
        goto exit;
    }
    if (strncmp((char*)method, "ssh-rsa", 7) != 0) {
        LOGERR("Unsupported cipher of private key: %.*s. Currently ssh-rsa supported only", (int)method_len, method);
        goto exit;
    }
    if (gen_publickey_from_rsa_openssh_priv_data(data, data_len, NULL, 0, NULL, 0, ctx) != 1) {
        goto exit;
    }

    rc = 1;
exit:
    if (fd) {
        fclose(fd);
    }
    if (b64data) {
        delete[] b64data;
        b64data = nullptr;
    }
    if (decrypted) {
        delete[] decrypted;
        decrypted = nullptr;
    }
    return rc;
}

int hostkey_method_ssh_rsa_signv(unsigned char **signature, size_t& signature_len, 
    const unsigned char *iov_base, size_t iov_len, void **ctx)
{
    int rc = -1;
    RSA *rsactx = (RSA*)(*ctx);
    unsigned char hash[SHA_DIGEST_LENGTH];
    unsigned char *sig = NULL;
    size_t sig_len;

    EVP_MD_CTX *shactx = EVP_MD_CTX_new();
    if (!shactx) {
        goto exit;
    }
    if (EVP_DigestInit(shactx, EVP_sha1()) != 1) {
        goto exit;
    }
    if (EVP_DigestUpdate(shactx, iov_base, iov_len) != 1) {
        goto exit;
    }
    if (EVP_DigestFinal(shactx, hash, NULL) != 1) {
        goto exit;
    }
    sig_len = RSA_size(rsactx);
    sig = new unsigned char[sig_len];

    if (RSA_sign(NID_sha1, hash, SHA_DIGEST_LENGTH, sig, (unsigned int*)&sig_len, rsactx) != 1) {
        LOGERR("Failed on RSA signing");
        goto exit;
    }

    *signature = sig;
    signature_len = sig_len;

    rc = 1;
exit:
    if (shactx) {
        EVP_MD_CTX_free(shactx);
    }
    if (rc != 1) {
        if (sig) {
            delete[] sig;
            sig = nullptr;
        }
    }
    return rc;
}
