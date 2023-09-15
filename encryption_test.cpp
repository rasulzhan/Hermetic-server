
#include <cstring>
#include <iostream>
#include <vector>
#include <memory>
#include <future>

// NOTE(Sedenkov): compiling without optimization when this header after <iostream> gives different result
#include <enc_dec_AES.h>

std::string m_uuid = "random_uuid";
std::string m_aesKey = "random_aesKey";

void
Encrypt(void *input_data, void *output_data, size_t data_size, void *key)
{
    ::encrypt((unsigned char *)input_data, data_size,
              reinterpret_cast<unsigned char *>(m_uuid.data()), (int)m_uuid.size(),
              (unsigned char *)key, const_cast<unsigned char *>(example_aes_iv),
              (unsigned char *)output_data, example_aes_tag);
}



int
main(int ac, char **av)
{
    const size_t data_size = 100'000;
    const size_t chunk_size = 4 * 1024;

    uint8_t *data = new uint8_t[100'000];

    for (size_t i = 0; i < data_size; i++) {
        data[i] = i & 0xff * 5;
    }

    std::string password = "test_password";

    std::vector<uint8_t> m_data(data_size);
    if (password.size() > 0) {
        unsigned char key[SHA256_DIGEST_LENGTH];
        sha256_hash(password, key);
        std::vector<uint8_t> t_data(data_size);
        std::copy(data, data + data_size, t_data.data());
        Encrypt(t_data.data(), m_data.data(), data_size, key);
    }

    /* Buffer for the decrypted text */
    auto       *encrypted_text_full = new unsigned char[data_size];
    std::size_t ciphertext_len;

    /* encrypt data */
    ciphertext_len = data_size;
    Encrypt(m_data.data(), encrypted_text_full, data_size, m_aesKey.data());

    ///////////////////////////////////////////////

    auto *encrypted_text_by_chunks = new unsigned char[data_size];

    unsigned char key[SHA256_DIGEST_LENGTH];
    sha256_hash(password, key);

    Encryption encrypt1 {
        reinterpret_cast<unsigned char *>(m_uuid.data()),
        (int)m_uuid.size(),
        (unsigned char *)key,
        const_cast<unsigned char *>(example_aes_iv),
    };
    Encryption encrypt2 {
        reinterpret_cast<unsigned char *>(m_uuid.data()),
        (int)m_uuid.size(),
        (unsigned char *)m_aesKey.data(),
        const_cast<unsigned char *>(example_aes_iv),
    };

    uint8_t *chunk = new uint8_t[chunk_size];

    size_t len_encrypted = 0;
    int    full_blocks = data_size / chunk_size;
    int    i = 0;
    while (i < full_blocks) {

#if 0
        std::async(std::launch::async, [] () {
            std::lock_guard
        });
#endif
        encrypt1.EncyptNextBlock(data + len_encrypted, chunk_size, chunk);

        encrypt2.EncyptNextBlock(chunk, chunk_size, encrypted_text_by_chunks + len_encrypted);

        len_encrypted += chunk_size;
        ++i;
    }
    size_t remaining_size = data_size - len_encrypted;
    if (remaining_size) {
        encrypt1.EncyptNextBlock(data + len_encrypted, remaining_size, chunk);

        encrypt1.FinishEncryption(data, example_aes_tag);

        encrypt2.EncyptNextBlock(chunk, remaining_size, encrypted_text_by_chunks + len_encrypted);

        encrypt2.FinishEncryption(data, example_aes_tag);
    } else {
        encrypt1.FinishEncryption(data, example_aes_tag);
        encrypt2.FinishEncryption(data, example_aes_tag);
    }

    if (std::memcmp(encrypted_text_full, encrypted_text_by_chunks, data_size) == 0) {
        std::cout << "Data is the same" << std::endl;
    } else {
        std::cout << "Data is different" << std::endl;
    }

    delete[] chunk;
    delete[] data;
    delete[] encrypted_text_full;
    delete[] encrypted_text_by_chunks;

    return 0;
}
