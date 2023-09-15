#ifndef ENCRYPTOR_H
#define ENCRYPTOR_H

#include <filesystem>
#include <iostream>
#include <memory>
#include <openssl/evp.h>

// IMPORTANT: compiler will optimize out for short strings
template<class T>
struct secure_allacator
{
    typedef T value_type;

    secure_allacator() = default;

    [[nodiscard]] T *allocate(std::size_t n)
    {
        if (n > std::numeric_limits<std::size_t>::max() / sizeof(T))
            throw std::bad_array_new_length();

        if (auto p = static_cast<T *>(std::malloc(n * sizeof(T)))) {
            report(p, n);
            return p;
        }

        throw std::bad_alloc();
    }

    void deallocate(T *p, std::size_t n) noexcept
    {
        OPENSSL_cleanse(p, n * sizeof(T));
        report(p, n, 0);
        std::free(p);
        p = nullptr;
    }

private:
    void report(T *p, std::size_t n, bool alloc = true) const
    {
        // std::cout << (alloc ? "Alloc: " : "Dealloc: ") << sizeof(T) * n << " bytes at " << std::hex
                //   << std::showbase << reinterpret_cast<void *>(p) << std::dec << '\n';
    }
};

typedef std::basic_string<char, std::char_traits<char>, secure_allacator<char>> secure_string;

class Cryptographer
{
public:
    Cryptographer();
    static std::string SHA256(std::filesystem::path file);
    static std::string MD5(std::filesystem::path file);

    void EncryptFileTo(std::filesystem::path file, std::filesystem::path out);
    void DecryptFileTo(std::filesystem::path file, std::filesystem::path out);

private:
    union AesPayload
    {
        uint8_t buf[48];
        struct
        {
            uint8_t key[32];
            uint8_t iv[16];
        } in;
    } payload_;
    using EVP_CIPHER_CTX_free_ptr = std::unique_ptr<EVP_CIPHER_CTX, decltype(&::EVP_CIPHER_CTX_free)>;

    int AesDecrypt(secure_string &in, secure_string &out);
    int AesEncrypt(secure_string &in, secure_string &out);
};

#endif /* ENCRYPTOR_H */
