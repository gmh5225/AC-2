#include "AES.hpp"
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/rand.h>

// Generate a random key of specified length
std::vector<unsigned char> AESGCM::generateKey(int keyLength) {
    std::vector<unsigned char> key(keyLength);
    RAND_bytes(key.data(), keyLength);
    return key;
}

// Encrypt plaintext using AES-GCM (up to 4GB)
bool AESGCM::encrypt(std::vector<unsigned char>& buffer, std::vector<unsigned char>& key) {

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();

    // Use AES-GCM with a 256-bit key
    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr);
    EVP_CIPHER_CTX_set_key_length(ctx, static_cast<int>(key.size()));
    EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), nullptr);

    // Allocate memory for IV
    std::vector<unsigned char> iv(EVP_CIPHER_iv_length(EVP_aes_256_gcm()));
    RAND_bytes(iv.data(), EVP_CIPHER_iv_length(EVP_aes_256_gcm()));

    // Set the IV
    EVP_EncryptInit_ex(ctx, nullptr, nullptr, nullptr, iv.data());

    // Encrypt plaintext
    int ciphertext_len;
    if (!EVP_EncryptUpdate(ctx, buffer.data(), &ciphertext_len, buffer.data(), static_cast<int>(buffer.size()))) {
        EVP_CIPHER_CTX_free(ctx);
        return false; //Encryption failed
    }

    // Finalize encryption
    int tempLen;
    if (EVP_EncryptFinal_ex(ctx, buffer.data() + ciphertext_len, &tempLen) <= 0) {
        EVP_CIPHER_CTX_free(ctx);
        return false; //Encryption failed
    }

    // Get the authentication tag
    std::vector<unsigned char> tag(TAG_SIZE);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_SIZE, tag.data());

    EVP_CIPHER_CTX_free(ctx);

    // Append IV and tag to the buffer
    buffer.resize((size_t)ciphertext_len + EVP_CIPHER_iv_length(EVP_aes_256_gcm()) + TAG_SIZE);
    std::copy(iv.begin(), iv.end(), buffer.begin() + (size_t)ciphertext_len);
    std::copy(tag.begin(), tag.end(), buffer.begin() + (size_t)ciphertext_len + EVP_CIPHER_iv_length(EVP_aes_256_gcm()));

    return true;
}

// Decrypt ciphertext using AES-GCM (up to 4GB)
bool AESGCM::decrypt(std::vector<unsigned char>& buffer, std::vector<unsigned char>& key) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();

    // Use AES-GCM with a 256-bit key
    EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr);
    EVP_CIPHER_CTX_set_key_length(ctx, static_cast<int>(key.size()));
    EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), nullptr);

    // Extract IV from the ciphertext buffer
    std::vector<unsigned char> iv(EVP_CIPHER_iv_length(EVP_aes_256_gcm()));
    std::copy(buffer.end() - EVP_CIPHER_iv_length(EVP_aes_256_gcm()) - TAG_SIZE, buffer.end() - TAG_SIZE, iv.begin());

    // Set the IV
    if (!EVP_DecryptInit_ex(ctx, nullptr, nullptr, nullptr, iv.data())) {
        EVP_CIPHER_CTX_free(ctx);
        return false; //Decryption failed
    }

    // Decrypt ciphertext (excluding IV and tag)
    int plaintext_len;
    if (!EVP_DecryptUpdate(ctx, buffer.data(), &plaintext_len, buffer.data(),
        static_cast<int>(buffer.size() - EVP_CIPHER_iv_length(EVP_aes_256_gcm()) - TAG_SIZE))) {
        EVP_CIPHER_CTX_free(ctx);
        return false; //Decryption failed
    }

    // Set the authentication tag
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_SIZE, buffer.data() + buffer.size() - TAG_SIZE);

    // Finalize decryption
    int tempLen;
    int ret = EVP_DecryptFinal_ex(ctx, buffer.data() + plaintext_len, &tempLen);

    EVP_CIPHER_CTX_free(ctx);

    if (ret > 0) {
        buffer.resize((size_t)plaintext_len);
        return true;
    }
    else {
        // Decryption failed
        return false;
    }
}