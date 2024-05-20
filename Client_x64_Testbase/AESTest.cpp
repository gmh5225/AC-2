#include "gtest/gtest.h"
#include "../Client_x64/AES.hpp"

// Test for generating a random key
TEST(AESGCMTest, GenerateKeyTest) {
    int keyLength = 32; // 256-bit key length
    std::vector<unsigned char> key = AESGCM::generateKey(keyLength);

    // Check if the key has the correct length
    ASSERT_EQ(key.size(), keyLength);
}

// Test for encryption and decryption
TEST(AESGCMTest, EncryptDecryptTest) {
    // Prepare plaintext data
    std::string plaintext = "This is a secret message.";
    std::vector<unsigned char> buffer(plaintext.begin(), plaintext.end());

    // Generate a random key
    int keyLength = 32; // 256-bit key length
    std::vector<unsigned char> key = AESGCM::generateKey(keyLength);

    // Encrypt the plaintext
    bool encryptionResult = AESGCM::encrypt(buffer, key);
    ASSERT_TRUE(encryptionResult);

    // Decrypt the ciphertext
    bool decryptionResult = AESGCM::decrypt(buffer, key);
    ASSERT_TRUE(decryptionResult);

    // Convert decrypted buffer back to string
    std::string decryptedText(buffer.begin(), buffer.end());

    // Check if decrypted text matches original plaintext
    ASSERT_EQ(decryptedText, plaintext);
}