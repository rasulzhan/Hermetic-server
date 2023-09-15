#include <openssl/evp.h>
#include <iostream>
#include <vector>
#include <thread>
#include <mutex>
#include <iomanip>
#include <cassert>
#include <cstring>

// Function to encrypt a chunk of data using AES-GCM
void encryptChunk(const unsigned char* plaintext, size_t plaintextSize,
                  const unsigned char* key, const unsigned char* iv,
                  unsigned char* ciphertext, unsigned char* tag,
                  const unsigned char* aad, size_t aadSize) {
    EVP_CIPHER_CTX* ctx;
    int len = 0;
    int ciphertextLen = 0;
    int res = 0;

    // Create and initialize the context for AES-GCM encryption
    ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    EVP_CIPHER_CTX_set_key_length(ctx, 32); // 32 bytes for AES-256
    EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv);
    // EVP_SealInit(ctx, EVP_aes_256_gcm(), &key, nullptr, &iv, 1);

     // Provide Additional Authenticated Data (AAD)
    res = EVP_EncryptUpdate(ctx, NULL, &ciphertextLen, aad, aadSize);
    assert(res > 0);

    // Encrypt the chunk
    res = EVP_EncryptUpdate(ctx, ciphertext, &ciphertextLen, plaintext, plaintextSize);
    assert(res > 0);

    res = EVP_EncryptFinal_ex(ctx, ciphertext + ciphertextLen, &len);
    assert(res > 0);


    // Get the authentication tag for this chunk
    res = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag);
    assert(res > 0);

    // Clean up the context
    EVP_CIPHER_CTX_free(ctx);
}

// Function to decrypt a chunk of data using AES-GCM
void decryptChunk(const unsigned char* ciphertext, size_t ciphertextSize,
                  const unsigned char* tag, size_t tagSize,
                  const unsigned char* key, const unsigned char* iv,
                  unsigned char* plaintext, const unsigned char* aad, size_t aadSize) {
    EVP_CIPHER_CTX* ctx;
    int len = 0;
    int plaintextLen = 0;
    int res = 0;

    // Create and initialize the context for AES-GCM decryption
    ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    EVP_CIPHER_CTX_set_key_length(ctx, 32); // 32 bytes for AES-256
    EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv);

    // Set the authentication tag for this chunk
    res = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, tagSize, const_cast<unsigned char*>(tag));
    assert(res > 0);

    // Set the Additional Authenticated Data (AAD) for GCM mode during decryption
    res = EVP_DecryptUpdate(ctx, NULL, &len, aad, aadSize);
    assert(res > 0);

    // Decrypt the chunk
    res = EVP_DecryptUpdate(ctx, plaintext, &plaintextLen, ciphertext, ciphertextSize);
    assert(res > 0);

    res = EVP_DecryptFinal_ex(ctx, plaintext + plaintextLen, &len);
    if (res <= 0) {
        // Decryption failed (authentication tag mismatch or other error)
        std::cerr << "Decryption failed." << res << std::endl;
        // Handle the error appropriately (e.g., throw an exception)
    }

    // Clean up the context
    EVP_CIPHER_CTX_free(ctx);
}

int main() {
    // Example key and IV (Initialization Vector)
    unsigned char key[] = "0123456789abcdef0123456789abcdef";
    unsigned char iv[] = "0123456789abcdef";
     // Provide Additional Authenticated Data (AAD)
    unsigned char aad[] = "Additional Authenticated Data";
    size_t aadSize = sizeof(aad) - 1; // Excluding null terminator

    // Example plaintext data (replace this with your actual data)
    unsigned char plaintext[] = "In the vast expanse of the cosmos, countless stars twinkle like celestial jewels, adorning the dark canvas of space with their radiant light. Across the eons, galaxies dance in cosmic ballets, weaving a tapestry of grandeur and mystery. Planets, moons, and asteroids glide through the celestial symphony, bound by the invisible threads of gravity. On Earth, a blue gem nestled amidst the stars, life teems and flourishes in its myriad forms. From the towering forests to the depths of the ocean, an intricate web of ecosystems sustains a diversity of creatures, each intricately adapted to their environments. Humans, with their boundless curiosity and ingenuity, explore, discover, and create, leaving their mark on the planet's history. Throughout history, cultures have risen and fallen like tides, leaving behind tales of triumphs and tragedies etched into the annals of time. From the ancient civilizations of Egypt and Mesopotamia to the empires of Rome and China, each chapter in human history tells a unique story of human achievement and struggle. The pursuit of knowledge has been an ever-present force, propelling societies forward into new eras of enlightenment and understanding. The scientific method has unlocked the secrets of the universe, revealing the wonders of quantum mechanics, relativity, and the vastness of the cosmos. Technological advancements have reshaped the way we communicate, travel, and connect with one another, shrinking the once formidable barriers of distance and time. Yet, amidst the progress and prosperity, challenges persist. Environmental degradation, political conflicts, and social inequalities cast shadows over the collective human experience. Climate change looms as a global threat, urging humanity to confront its actions and seek sustainable solutions. The quest for equality and justice remains a battle fought on many fronts, as people strive to bridge divides and foster empathy and understanding. In the pursuit of self-discovery and meaning, individuals embark on personal journeys, traversing the landscapes of their own hearts and minds. Love, joy, grief, and resilience intertwine, shaping the complex tapestry of human emotions. Dreams and aspirations propel individuals forward, while fears and doubts stand as formidable adversaries to be conquered. The power of art and culture permeates through the essence of human existence. From the strokes of a painter's brush to the melodies of a musician's composition, creativity speaks to the soul and enriches the human experience. Literature, poetry, and cinema offer windows into different worlds and perspectives, allowing us to empathize with characters and stories that resonate with our shared humanity. In the digital age, information flows like an endless river, connecting people across continents and time zones. Social media, once a novelty, has become an integral part of modern life, shaping opinions and influencing societies. As the world becomes increasingly interconnected, the responsibility to use these tools wisely and compassionately becomes paramount. As we look to the future, uncertainty and hope intertwine like vines reaching for the sun. Space exploration beckons humanity to new frontiers, promising to expand our understanding of the universe and our place within it. Advancements in medicine hold the potential to eradicate diseases that have plagued humanity for generations. The pursuit of renewable energy and sustainable practices aims to preserve the beauty and bounty of the planet for future generations. In this grand tapestry of existence, each individual thread weaves together to create a mosaic of human history, triumphs, and challenges. As we navigate the complexities of life, let us remember that we are but temporary custodians of this world, entrusted with the duty to care for it and for one another. May our shared journey through time and space be one of compassion, understanding, and harmony.The world we live in is a complex and ever-changing place, filled with an abundance of information and possibilities. It is a tapestry woven with threads of diverse cultures, histories, and perspectives. Each individual, like a singular note in a grand symphony, contributes their unique melody to the unfolding composition of human existence.From the depths of ancient civilizations to the soaring heights of modern technology, humanity has strived to unravel the mysteries of the universe and its own nature. We have harnessed the power of fire, discovered the laws of physics, and explored the far reaches of outer space. Through our collective endeavors, we have witnessed both triumphs and failures, advancements and setbacks, but always with the unwavering spirit of curiosity and progress.In this interconnected world, our actions ripple across continents, transcending borders and time zones. Ideas and innovations flow freely, traversing the digital highways that connect us all. We have the ability to instantaneously communicate with someone on the other side of the globe, forging connections that were once unimaginable. But amidst this vast web of connectivity, we must also be mindful of the consequences of our actions and the responsibility we bear as stewards of this planet.As we navigate the complexities of the present and peer into the horizon of the future, we are faced with myriad challenges. Climate change looms large, threatening the delicate balance of ecosystems and the very survival of countless species. Inequality persists, as socioeconomic disparities create divides and hinder the progress of individuals and communities. The quest for peace and harmony continues, as conflicts and tensions persist in different corners of the globe.Yet, despite these obstacles, we find hope in the resilience of the human spirit. Throughout history, we have witnessed the power of compassion, unity, and perseverance. When faced with adversity, we have banded together, lending a helping hand to those in need. We have created art that transcends boundaries, igniting emotions and inspiring change. We have pushed the boundaries of knowledge, unraveling the mysteries of the universe and unlocking the potential within ourselves.In the grand tapestry of life, each of us has a role to play, a purpose to fulfill. Our choices and actions, no matter how small, can have a profound impact on the world around us. We must strive for a future that is sustainable, equitable, and harmonious. It is through our collective efforts that we can create a world where every individual has the opportunity to thrive, where compassion and understanding guide our interactions, and where the beauty of diversity is celebrated.So, let us embark on this journey together, hand in hand, with open minds and open hearts. Let us embrace the challenges that lie ahead, armed with the knowledge that we are not alone. As we navigate the twists and turns of this intricate dance called life, let us remember that the power to shape the world rests within each and every one of us. Together, we can create a symphony of compassion, a masterpiece of progress, and a legacy of love that will resonate for generations to come.The world we live in is a complex and ever-changing place, filled with an abundance of information and possibilities. It is a tapestry woven with threads of diverse cultures, histories, and perspectives. Each individual, like a singular note in a grand symphony, contributes their unique melody to the unfolding composition of human existence.From the depths of ancient civilizations to the soaring heights of modern technology, humanity has strived to unravel the mysteries of the universe and its own nature. We have harnessed the power of fire, discovered the laws of physics, and explored the far reaches of outer space. Through our collective endeavors, we have witnessed both triumphs and failures, advancements and setbacks, but always with the unwavering spirit of curiosity and progress.In this interconnected world, our actions ripple across continents, transcending borders and time zones. Ideas and innovations flow freely, traversing the digital highways that connect us all. We have the ability to instantaneously communicate with someone on the other side of the globe, forging connections that were once unimaginable. But amidst this vast web of connectivity, we must also be mindful of the consequences of our actions and the responsibility we bear as stewards of this planet.As we navigate the complexities of the present and peer into the horizon of the future, we are faced with myriad challenges. Climate change looms large, threatening the delicate balance of ecosystems and the very survival of countless species. Inequality persists, as socioeconomic disparities create divides and hinder the progress of individuals and communities. The quest for peace and harmony continues, as conflicts and tensions persist in different corners of the globe.Yet, despite these obstacles, we find hope in the resilience of the human spirit. Throughout history, we have witnessed the power of compassion, unity, and perseverance. When faced with adversity, we have banded together, lending a helping hand to those in need. We have created art that transcends boundaries, igniting emotions and inspiring change. We have pushed the boundaries of knowledge, unraveling the mysteries of the universe and unlocking the potential within ourselves.In the grand tapestry of life, each of us has a role to play, a purpose to fulfill. Our choices and actions, no matter how small, can have a profound impact on the world around us. We must strive for a future that is sustainable, equitable, and harmonious. It is through our collective efforts that we can create a world where every individual has the opportunity to thrive, where compassion and understanding guide our interactions, and where the beauty of diversity is celebrated.So, let us embark on this journey together, hand in hand, with open minds and open hearts. Let us embrace the challenges that lie ahead, armed with the knowledge that we are not alone. As we navigate the twists and turns of this intricate dance called life, let us remember that the power to shape the world rests within each and every one of us. Together, we can create a symphony of compassion, a masterpiece of progress, and a legacy of love that will resonate for generations to come.1234567812345678123456781234567812345678123456781234567812345678123456781234567812345678123456781234567812345678123456781234567812345678123456781234567812345678123456781234567812345678123456781234567812345678123456781234567812345678123456781234567812345678123456781234567812345678123456781234567812345678123456781234567812345678123456781234567812345678123456781234567812345678123456781234"
    ;
    size_t plaintextSize = sizeof(plaintext) - 1; // Excluding null terminator

    // Determine the chunk size (choose an appropriate size)
    size_t chunkSize = 64 * 1024;

    // Calculate the number of chunks
    size_t numChunks = (plaintextSize + chunkSize - 1) / chunkSize;

    // Data structures to store ciphertext and authentication tags for each chunk
    std::vector<unsigned char> ciphertext(plaintextSize);
    std::vector<unsigned char> tags(numChunks * EVP_GCM_TLS_TAG_LEN);

    // Data structure to store the decrypted plaintext for each chunk
    std::vector<unsigned char> decryptedPlaintext(plaintextSize);

    // Create a vector to hold the encryption threads
    std::vector<std::thread> encryptionThreads(numChunks);

    // Encrypt each chunk separately using multiple threads
    for (size_t i = 0; i < numChunks; ++i) {
        size_t offset = i * chunkSize;
        size_t chunkLen = (i == numChunks - 1) ? (plaintextSize - offset) : chunkSize;

        // Start a new thread to encrypt the chunk
        encryptionThreads[i] = std::thread([&plaintext, offset, chunkLen, &ciphertext, &tags, key,
                                            iv, i, aad, aadSize]() {
            encryptChunk(plaintext + offset, chunkLen, key, iv,
                         ciphertext.data() + offset, tags.data() + (i * EVP_GCM_TLS_TAG_LEN), aad, aadSize);
        });
    }

    // Wait for all encryption threads to finish
    for (auto& thread : encryptionThreads) {
        thread.join();
    }

    // Combine the authentication tags to get the final tag
    unsigned char finalTag[EVP_GCM_TLS_TAG_LEN];
    std::memset(finalTag, 0, EVP_GCM_TLS_TAG_LEN);
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    // EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    // EVP_CIPHER_CTX_set_key_length(ctx, 32); // 32 bytes for AES-256
    // EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv);
    //          int b;
    // EVP_EncryptUpdate(ctx, NULL, &b, aad, aadSize);
    // for (size_t i = 0; i < numChunks; ++i) {
    //     EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, EVP_GCM_TLS_TAG_LEN, tags.data() + (i * EVP_GCM_TLS_TAG_LEN));
    // }
    // EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, EVP_GCM_TLS_TAG_LEN, tags.data());
    // EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, EVP_GCM_TLS_TAG_LEN, finalTag);
    EVP_CIPHER_CTX_free(ctx);

    for (size_t i = 0; i < numChunks; ++i) {
        for (size_t j = 0; j < EVP_GCM_TLS_TAG_LEN; ++j) {
            finalTag[j] ^= tags[i * EVP_GCM_TLS_TAG_LEN + j];
        }
    }

    // Print the encrypted ciphertext and tags for each chunk
    std::cout << "Encrypted ciphertext: ";
    for (size_t i = 0; i < ciphertext.size(); ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(ciphertext[i]);
    }
    std::cout << std::endl;

    std::cout << "finalTag: ";
    for (size_t i = 0; i < 16; ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(finalTag[i]);
    }
    std::cout << std::endl;
        std::cout << "Tags: ";
    for (size_t i = 0; i < tags.size(); ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(tags[i]);
    }
    std::cout << std::endl;

    // Create a mutex for thread synchronization during merging of decrypted chunks
    std::mutex decryptMutex;

    std::vector<std::thread> decryptionThreads(numChunks);

    // Decrypt each chunk separately using multiple threads
    for (size_t i = 0; i < numChunks; ++i) {
        size_t offset = i * chunkSize;
        size_t chunkLen = (i == numChunks - 1) ? (plaintextSize - offset) : chunkSize;

        // Start a new thread to decrypt the chunk
        decryptionThreads[i] = std::thread([&ciphertext, &tags, i, offset, chunkLen, &decryptedPlaintext, key, iv, finalTag, chunkSize, aad, aadSize, &decryptMutex]() {
            // std::cout << "I: " << i << std::endl;
            // Decrypt the chunk
            unsigned char *decryptedChunk = new unsigned char[chunkLen];
            decryptChunk(ciphertext.data() + offset, chunkLen, tags.data() + (i * EVP_GCM_TLS_TAG_LEN), EVP_GCM_TLS_TAG_LEN,
                         key, iv, decryptedChunk, aad, aadSize);

            // Lock the mutex to synchronize access to the decryptedPlaintext vector
            std::lock_guard<std::mutex> lock(decryptMutex);
            // Copy the decrypted chunk into the merged decrypted plaintext
            std::memcpy(decryptedPlaintext.data() + offset, decryptedChunk, chunkLen);
        });
    }
    decryptedPlaintext.push_back(0);
    // Wait for all decryption threads to finish
    for (auto& thread : decryptionThreads) {
        thread.join();
    }

    // Calculate the final tag for decrypted data
    unsigned char computedFinalTag[EVP_GCM_TLS_TAG_LEN];
    std::memset(computedFinalTag, 0, EVP_GCM_TLS_TAG_LEN);
    ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    EVP_CIPHER_CTX_set_key_length(ctx, 32); // 32 bytes for AES-256
    EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv);
         // Provide Additional Authenticated Data (AAD)
    //      int a;
    // EVP_EncryptUpdate(ctx, NULL, &a, aad, aadSize);
    for (size_t i = 0; i < numChunks; ++i) {
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, EVP_GCM_TLS_TAG_LEN, tags.data() + (i * EVP_GCM_TLS_TAG_LEN));
    }
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, EVP_GCM_TLS_TAG_LEN, tags.data());
    // EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, EVP_GCM_TLS_TAG_LEN, computedFinalTag);
    EVP_CIPHER_CTX_free(ctx);

        for (size_t i = 0; i < numChunks; ++i) {
        for (size_t j = 0; j < EVP_GCM_TLS_TAG_LEN; ++j) {
            computedFinalTag[j] ^= tags[i * EVP_GCM_TLS_TAG_LEN + j];
        }
    }
    // Print the decrypted plaintext
    std::cout << "Decrypted plaintext: " << decryptedPlaintext.data() << std::endl;

    // Compare the computed final tag with the original final tag obtained during encryption
    if (std::memcmp(computedFinalTag, finalTag, EVP_GCM_TLS_TAG_LEN) == 0) {
        std::cout << "Decryption successful. Data is authentic." << std::endl;
    } else {
        std::cout << "Decryption failed. Data has been modified or corrupted."  << std::endl;
    }
    std::cout << "finalTag: ";
    for (size_t i = 0; i < EVP_GCM_TLS_TAG_LEN; ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(computedFinalTag[i]);
    }
    return 0;
}
