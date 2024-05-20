#include "gtest/gtest.h"
#include "../Client_x64/RSA.hpp"

// Test key generation
TEST(RSATest, KeyGenerationTest) {
    int keyBits = 2048; // Key length in bits
    auto keyPair = RSA_OSSL::generateKeyPair(keyBits);

    // Check if key generation was successful
    ASSERT_TRUE(keyPair.has_value());
    ASSERT_FALSE(keyPair->pubKey.empty());
    ASSERT_FALSE(keyPair->privKey.empty());
}

// Test encryption and decryption using public key
TEST(RSATest, EncryptionDecryptionPublicTest) {
    // Prepare plaintext data
    std::string plaintext = "This is a secret message.";
    std::vector<unsigned char> plaintextVec(plaintext.begin(), plaintext.end());

    // Generate key pair
    int keyBits = 2048; // Key length in bits
    auto keyPair = RSA_OSSL::generateKeyPair(keyBits);
    ASSERT_TRUE(keyPair.has_value());

    // Encrypt the plaintext using public key
    auto ciphertext = RSA_OSSL::encryptPublic(plaintextVec, keyPair->pubKey);
    ASSERT_FALSE(ciphertext.empty());

    // Decrypt the ciphertext using private key
    auto decryptedText = RSA_OSSL::decryptPrivate(ciphertext, keyPair->privKey);
    ASSERT_FALSE(decryptedText.empty());

    // Convert decrypted text back to a string
    std::string decryptedStr(decryptedText.begin(), decryptedText.end());

    // Remove null bytes from the decrypted string
    decryptedStr.erase(std::remove(decryptedStr.begin(), decryptedStr.end(), '\0'), decryptedStr.end());

    // Check if decrypted text matches original plaintext
    ASSERT_EQ(decryptedStr, plaintext);
}