#include "cryptographer.h"

// openssl
#include <openssl/evp.h>
#include <openssl/md5.h>
#include <openssl/sha.h>

// std
#include <cstring>
#include <fstream>
#include <iostream>
#include <vector>
#include <array>

void
sha256_hash_string(unsigned char hash[SHA256_DIGEST_LENGTH], char outputBuffer[65])
{
    int i = 0;

    for (i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(outputBuffer + (i * 2), "%02x", hash[i]);
    }

    outputBuffer[64] = 0;
}

std::string
Cryptographer::SHA256(std::filesystem::path file)
{
    std::ifstream f;
    f.open(file, std::ios::binary | std::ios::in);

    size_t            size = 32768;
    std::vector<char> buffer(size);
    int               readed;

    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX    sha256;
    SHA256_Init(&sha256);

    while ((readed = f.readsome(buffer.data(), size))) {
        SHA256_Update(&sha256, buffer.data(), readed);
    }
    SHA256_Final(hash, &sha256);

    char outputBuffer[65];
    sha256_hash_string(hash, outputBuffer);
    std::cout << outputBuffer << "\n";

    f.close();

    return outputBuffer;
}

std::string
Cryptographer::MD5(std::filesystem::path file)
{
    std::ifstream f;
    f.open(file, std::ios::binary | std::ios::in);

    size_t            size = 32768;
    std::vector<char> buffer(size);
    int               readed;

    unsigned char hash[MD5_DIGEST_LENGTH];
    MD5_CTX       md5;
    MD5_Init(&md5);

    while ((readed = f.readsome(buffer.data(), size))) {
        MD5_Update(&md5, buffer.data(), readed);
    }
    MD5_Final(hash, &md5);

    f.close();

    char outputBuffer[MD5_DIGEST_LENGTH * 2 + 1];
    int  i = 0;
    for (i = 0; i < MD5_DIGEST_LENGTH; i++) {
        sprintf(outputBuffer + (i * 2), "%02x", hash[i]);
    }

    outputBuffer[MD5_DIGEST_LENGTH * 2] = 0;

    return outputBuffer;
}

// static constexpr auto salt = R"(7D+%ew}u_nP)_)'j9yMh328iPc_>_aF&wF{r7 ~pZk:gteMrjL]jdsF_[-p6.] s
// = K)";
#define SALT R"(7D+%ew}u_nP)_)'j9yMh328iPc_>_aF&wF{r7 ~pZk:gteMrjL]jdsF_[-p6.] s = K)"
int const KEY_BLOCK_SIZE = 48;

Cryptographer::Cryptographer()
{
    char secret[] = R"(khfTsePoQKuvbAeCoegYTTb8ALG8BWtjxWx7Dkw647Vr5HEzvq7ACrp2yDGRPVEZ)";

    std::array<uint8_t, sizeof(SALT)> asalt = {SALT};
    

    PKCS5_PBKDF2_HMAC_SHA1(secret, std::strlen(secret), asalt.data(), asalt.size() - 1, 1000,
                           KEY_BLOCK_SIZE, payload_.buf);
    OPENSSL_cleanse(secret, strlen(secret));
    OPENSSL_cleanse(asalt.data(), asalt.size());
}

static const unsigned int KEY_SIZE = 32;
static const unsigned int BLOCK_SIZE = 16;
static const unsigned int FILE_BLOCK_SIZE = 1024;

void
Cryptographer::EncryptFileTo(std::filesystem::path file, std::filesystem::path out)
{
    if (out.extension().string() != ".enc") {
        std::cerr << "Warning: file not ended with .enc\n";
    }

    std::ifstream ifile;
    ifile.open(file, std::ios::in | std::ios::binary);

    std::stringstream ss;
    ss << ifile.rdbuf();
    secure_string instr(ss.str());

    ifile.close();

    secure_string        outstr;
    [[maybe_unused]] int ret = AesEncrypt(instr, outstr);

    std::ofstream ofile;
    ofile.open(out, std::ios::out | std::ios::binary);
    ofile << outstr;
    ofile.close();
}

void
Cryptographer::DecryptFileTo(std::filesystem::path file, std::filesystem::path out)
{
    std::ifstream ifile;
    ifile.open(file, std::ios::in | std::ios::binary);

    std::stringstream ss;
    ss << ifile.rdbuf();
    secure_string instr(ss.str());

    ifile.close();

    secure_string        outstr;
    [[maybe_unused]] int ret = AesDecrypt(instr, outstr);

    std::ofstream ofile;
    ofile.open(out, std::ios::out | std::ios::binary);
    ofile << outstr;
    ofile.close();
}

int
Cryptographer::AesDecrypt(secure_string &in, secure_string &out)
{
    EVP_CIPHER_CTX_free_ptr ctx(EVP_CIPHER_CTX_new(), ::EVP_CIPHER_CTX_free);
    int                     rc =
        EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_cbc(), NULL, payload_.in.key, payload_.in.iv);
    if (rc != 1) {
        return -1;
    }

    // Recovered text contracts upto BLOCK_SIZE
    out.resize(in.size());
    int out_len1 = (int)out.size();

    // EVP_CIPHER_CTX_set_padding(ctx.get(), 0);

    rc = EVP_DecryptUpdate(ctx.get(), (uint8_t *)&out[0], &out_len1, (const uint8_t *)&in[0],
                           (int)in.size());
    if (rc != 1) {
        return -1;
    }

    int out_len2 = (int)out.size() - out_len1;
    rc = EVP_DecryptFinal_ex(ctx.get(), (uint8_t *)&out[0] + out_len1, &out_len2);
    if (rc != 1) {
        // ERR_print_errors_fp(stderr);
        // LOG(ERROR) << "EVP_DecryptFinal_ex failed";
        return -1;
    }
    // Set recovered text size now that we know it
    out.resize(out_len1 + out_len2);
    return 0;
}

int
Cryptographer::AesEncrypt(secure_string &in, secure_string &out)
{
    EVP_CIPHER_CTX_free_ptr ctx(EVP_CIPHER_CTX_new(), ::EVP_CIPHER_CTX_free);
    [[maybe_unused]] int    len = 0, ciphertext_len = 0;

    // Initialise the encryption operation.
    int rc =
        EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_cbc(), NULL, payload_.in.key, payload_.in.iv);
    if (rc != 1) {
        return -1;
    }

    // Recovered text contracts upto BLOCK_SIZE
    out.resize((in.size() + BLOCK_SIZE) / BLOCK_SIZE * BLOCK_SIZE);
    int out_len1 = (int)out.size();

    rc = EVP_EncryptUpdate(ctx.get(), (uint8_t *)&out[0], &out_len1, (const uint8_t *)&in[0],
                           (int)in.size());
    if (rc != 1) {
        return -1;
    }

    int out_len2 = (int)out.size() - out_len1;
    rc = EVP_EncryptFinal_ex(ctx.get(), (uint8_t *)&out[0] + out_len1, &out_len2);
    if (rc != 1) {
        // ERR_print_errors_fp(stderr);
        return -1;
    }
    // Set recovered text size now that we know it
    out.resize(out_len1 + out_len2);
    return 0;
}
