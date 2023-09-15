//
// Created by viktor on 25.02.23.
//

#ifndef SERVER_ENC_DEC_AES_H
#define SERVER_ENC_DEC_AES_H

#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/err.h>
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <random>
#include <string>

const static uint8_t __char2int[256]
{
	0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
	0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
    0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
	0x0, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
	0x0, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
	0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
	0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
	0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
	0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0
};

static void handleErrors(void);

class Encryption
{
public:
    Encryption(unsigned char *aad, int aad_len, unsigned char *key, unsigned char *iv)
    {
        /* Create and initialise the context */
        if (!(ctx = EVP_CIPHER_CTX_new()))
            handleErrors();

        /* Initialise the encryption operation. */
        if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL))
            handleErrors();

        /* Set IV length if default 12 bytes (96 bits) is not appropriate */
        if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 16, NULL))
            handleErrors();

        /* Initialise key and IV */
        if (1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv))
            handleErrors();

        /* Provide any AAD data. This can be called zero or more times as
         * required
         */
        if (aad && aad_len > 0) {
            if (1 != EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len))
                handleErrors();
        }
    }

    void EncyptNextBlock(unsigned char *plaintext, int plaintext_len, unsigned char *ciphertext)
    {
        /* Provide the message to be encrypted, and obtain the encrypted output.
         * EVP_EncryptUpdate can be called multiple times if necessary
         */
        if (plaintext) {
            if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
                handleErrors();

            ciphertext_len = len;
        }
    }

    void FinishEncryption(unsigned char *ciphertext, unsigned char *tag)
    {
        /* Finalise the encryption. Normally ciphertext bytes may be written at
         * this stage, but this does not occur in GCM mode
         */
        if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
            handleErrors();
        ciphertext_len += len;

        /* Get the authentication tag for this chunk */
        if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag))
            handleErrors();
    }

    ~Encryption()
    {
        /* Clean up */
        EVP_CIPHER_CTX_free(ctx);
    }

    void SetLen(int len)
    {
        ciphertext_len = len;
    }

private:
    EVP_CIPHER_CTX *ctx = NULL;
    int             len = 0, ciphertext_len = 0;
};

class Decryption
{
public:
    Decryption(unsigned char *aad, int aad_len, unsigned char *key, unsigned char *iv,
               const unsigned char *tag, size_t tag_size)
    {
        ctx = NULL;
        len = 0;
        plaintext_len = 0;

        /* Create and initialise the context */
        if (!(ctx = EVP_CIPHER_CTX_new()))
            handleErrors();

        /* Initialise the decryption operation. */
        if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL))
            handleErrors();

        /* Set IV length. Not necessary if this is 12 bytes (96 bits) */
        if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 16, NULL))
            handleErrors();

        /* Initialise key and IV */
        if (!EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv))
            handleErrors();

        // Set the authentication tag for this chunk
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, tag_size, const_cast<unsigned char *>(tag));

        /* Provide any AAD data. This can be called zero or more times as
         * required
         */
        if (aad && aad_len > 0) {
            if (!EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len))
                handleErrors();
        }
    }
    ~Decryption()
    {
        EVP_CIPHER_CTX_free(ctx);
    }

    void DecryptNextBlock(unsigned char *plaintext, int plaintext_len, unsigned char *ciphertext)
    {

        /* Provide the message to be decrypted, and obtain the plaintext output.
         * EVP_DecryptUpdate can be called multiple times if necessary
         */
        if (ciphertext) {
            if (!EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, plaintext_len))
                handleErrors();

            plaintext_len = len;
        }
    }

    void FinishDecryption(unsigned char *plaintext, unsigned char *tag)
    {
        /* Finalise the decryption. A positive return value indicates success,
         * anything else is a failure - the plaintext is not trustworthy.
         */
        EVP_DecryptFinal_ex(ctx, plaintext + len, &len);
    }

private:
    EVP_CIPHER_CTX *ctx = NULL;
    int             len = 0, plaintext_len = 0;
};

static int Serialize(void* var, size_t byte_size, std::string& ret) {
	uint8_t* reinterpreted = (uint8_t*)(var);
	ret = std::string(byte_size * 2, '\0');
	int i = 0;
	for (i = 0; i < byte_size; i++) sprintf(ret.data() + (i * 2), "%02x", reinterpreted[i]);

    return i;
}

static int Deserialize(void* ret, size_t byte_size, std::string& var) {
    uint8_t* reinterpreted = (uint8_t*)(ret);
	int i = 0;
	for (i = 0; i < byte_size; i++) reinterpreted[i] = __char2int[var[i * 2]] * 0x10 + __char2int[var[i * 2 + 1]] * 0x1;

    return i;
}

static void sha256_hash_string(unsigned char hash[SHA256_DIGEST_LENGTH], char outputBuffer[SHA256_DIGEST_LENGTH * 2 + 1])
{
    int i = 0;

    for (i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(outputBuffer + (i * 2), "%02x", hash[i]);
    }

    outputBuffer[SHA256_DIGEST_LENGTH * 2] = 0;
}

static void sha256_hash(std::string str, unsigned char hash[SHA256_DIGEST_LENGTH])
{
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, str.data(), str.size());
    SHA256_Final(hash, &sha256);
}

static std::string sha256_string(std::string str)
{
    char outputBuffer[SHA256_DIGEST_LENGTH * 2 + 1];
    unsigned char hash[SHA256_DIGEST_LENGTH];
    sha256_hash(str, hash);
    sha256_hash_string(hash, outputBuffer);
    return std::string(outputBuffer);
}

static void sha512_hash_string(unsigned char hash[SHA512_DIGEST_LENGTH], char outputBuffer[SHA512_DIGEST_LENGTH * 2 + 1])
{
    int i = 0;

    for (i = 0; i < SHA512_DIGEST_LENGTH; i++) {
        sprintf(outputBuffer + (i * 2), "%02x", hash[i]);
    }

    outputBuffer[SHA512_DIGEST_LENGTH * 2 + 1] = 0;
}

static void sha512_hash(std::string str, unsigned char hash[SHA512_DIGEST_LENGTH])
{
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, str.data(), str.size());
    SHA256_Final(hash, &sha256);
}

static std::string sha512_string(std::string str)
{
    char outputBuffer[SHA512_DIGEST_LENGTH * 2 + 1];
    unsigned char hash[SHA512_DIGEST_LENGTH];
    sha512_hash(str, hash);
    sha256_hash_string(hash, outputBuffer);
    return std::string(outputBuffer);
}


/* Buffer for the tag */
static unsigned char example_aes_tag[16];

///* A 256 bit key */
static const unsigned char example_aes_key[] = "I_Am_Waiting_for_You_Last_Summer";

/* A 128 bit IV */
static const unsigned char example_aes_iv[] = "GodIsAnAstronaut";


static std::string generateEncodeKey()
{
    const char alphabet[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

    std::string out;
    for (int i = 0; i < 32; ++i)
    {
        int random = rand() % 62;
        out += alphabet[random];
    }
    return out;
}


static void handleErrors(void)
{
    unsigned long errCode;

    printf("An error occurred\n");
    while((errCode = ERR_get_error()) > 0)
    {
        char *err = ERR_error_string(errCode, NULL);
        printf("%s\n", err);
    }
    abort();
}

static int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *aad,
            int aad_len, unsigned char *key, unsigned char *iv,
            unsigned char *ciphertext, unsigned char *tag)
{
    EVP_CIPHER_CTX *ctx = NULL;
    int len = 0, ciphertext_len = 0;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

    /* Initialise the encryption operation. */
    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL))
        handleErrors();

    /* Set IV length if default 12 bytes (96 bits) is not appropriate */
    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 16, NULL))
        handleErrors();

    /* Initialise key and IV */
    if(1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv)) handleErrors();

    /* Provide any AAD data. This can be called zero or more times as
     * required
     */
    if(aad && aad_len > 0)
    {
        if(1 != EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len))
            handleErrors();
    }

    /* Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */
    if(plaintext)
    {
        if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
            handleErrors();

        ciphertext_len = len;
    }

    /* Finalise the encryption. Normally ciphertext bytes may be written at
     * this stage, but this does not occur in GCM mode
     */
    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) handleErrors();
    ciphertext_len += len;

    /* Get the tag */
    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag))
        handleErrors();

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

static int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *aad,
            int aad_len, unsigned char *tag, unsigned char *key, unsigned char *iv,
            unsigned char *plaintext)
{
    EVP_CIPHER_CTX *ctx = NULL;
    int len = 0, plaintext_len = 0, ret;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

    /* Initialise the decryption operation. */
    if(!EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL))
        handleErrors();

    /* Set IV length. Not necessary if this is 12 bytes (96 bits) */
    if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 16, NULL))
        handleErrors();

    /* Initialise key and IV */
    if(!EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv)) handleErrors();

    /* Provide any AAD data. This can be called zero or more times as
     * required
     */
    if(aad && aad_len > 0)
    {
        if(!EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len))
            handleErrors();
    }

    /* Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary
     */
    if(ciphertext)
    {
        if(!EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
            handleErrors();

        plaintext_len = len;
    }

    /* Set expected tag value. Works in OpenSSL 1.0.1d and later */
    if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag))
        handleErrors();

    /* Finalise the decryption. A positive return value indicates success,
     * anything else is a failure - the plaintext is not trustworthy.
     */
    ret = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    if(ret > 0)
    {
        /* Success */
        plaintext_len += len;
        return plaintext_len;
    }
    else
    {
        /* Verify failed */
        return -1;
    }
}

#endif //SERVER_ENC_DEC_AES_H
