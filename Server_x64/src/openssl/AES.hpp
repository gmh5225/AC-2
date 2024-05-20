#pragma once

#include <iostream>
#include <vector>

namespace AESGCM {

    constexpr auto TAG_SIZE = 16;
    constexpr auto IV_SIZE = 12;
    const auto KEY_SIZE_256 = 32;

    // Generate a random key of specified length
    std::vector<unsigned char> generateKey(int keyLength);

    // Encrypt plaintext using AES-GCM (up to 4GB)
    bool encrypt(std::vector<unsigned char>& buffer, std::vector<unsigned char>& key);

    // Decrypt ciphertext using AES-GCM (up to 4GB)
    bool decrypt(std::vector<unsigned char>& buffer, std::vector<unsigned char>& key);
}