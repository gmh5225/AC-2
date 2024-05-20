#include "RSA.hpp"

// Generate an RSA key pair and return the public key as a string
std::optional<KEY_PAIR> RSA_OSSL::generateKeyPair(int bits) {
    KEY_PAIR keyPair = {};
    auto pKey = EVP_RSA_gen(bits);

    auto pubKeyBio = BIO_new(BIO_s_mem());
    if (!pubKeyBio) return std::nullopt;

    if (!PEM_write_bio_PUBKEY(pubKeyBio, pKey)) {
        BIO_free(pubKeyBio);
        EVP_PKEY_free(pKey);
        return std::nullopt;
    }

    char* pubKeyData;
    auto pubKeyLen = BIO_get_mem_data(pubKeyBio, &pubKeyData);
    if (pubKeyLen <= 0) {
        BIO_free(pubKeyBio);
        EVP_PKEY_free(pKey);
        return std::nullopt;
    }

    keyPair.pubKey = pubKeyData;
    BIO_free(pubKeyBio);

    auto privKeyBio = BIO_new(BIO_s_mem());
    if (!privKeyBio) return std::nullopt;

    if (!PEM_write_bio_PrivateKey(privKeyBio, pKey, nullptr, nullptr, 0, nullptr, nullptr)) {
        BIO_free(privKeyBio);
        EVP_PKEY_free(pKey);
        return std::nullopt;
    }

    char* privKeyData;
    auto privKeyLen = BIO_get_mem_data(privKeyBio, &privKeyData);
    if (privKeyLen <= 0) {
        BIO_free(privKeyBio);
        EVP_PKEY_free(pKey);
        return std::nullopt;
    }

    keyPair.privKey = privKeyData;

    EVP_PKEY_free(pKey);
    BIO_free(privKeyBio);
    return keyPair;
}

EVP_PKEY* RSA_OSSL::createPublicKeyFromStr(const std::string& publicKeyStr) {
    // Create a memory BIO to hold the public key data
    BIO* pubKeyBio = BIO_new_mem_buf(publicKeyStr.c_str(), static_cast<int>(publicKeyStr.length()));
    if (!pubKeyBio) {
        // Handle error
        return nullptr;
    }

    // Read the public key from the memory BIO
    EVP_PKEY* publicKey = PEM_read_bio_PUBKEY(pubKeyBio, nullptr, nullptr, nullptr);
    if (!publicKey) {
        // Handle error
        BIO_free(pubKeyBio);
        return nullptr;
    }

    // Free the memory BIO
    BIO_free(pubKeyBio);

    return publicKey;
}

EVP_PKEY* RSA_OSSL::createPrivateKeyFromStr(const std::string& privateKeyStr) {
    // Create a memory BIO to hold the private key data
    BIO* privateKeyBio = BIO_new_mem_buf(privateKeyStr.c_str(), static_cast<int>(privateKeyStr.length()));
    if (!privateKeyBio) {
        // Handle error
        return nullptr;
    }

    // Read the private key from the memory BIO
    EVP_PKEY* privateKey = PEM_read_bio_PrivateKey(privateKeyBio, nullptr, nullptr, nullptr);
    if (!privateKey) {
        // Handle error
        BIO_free(privateKeyBio);
        return nullptr;
    }

    // Free the memory BIO
    BIO_free(privateKeyBio);

    return privateKey;
}

// Encrypt data using RSA public key
std::vector<unsigned char> RSA_OSSL::encryptPublic(const std::vector<unsigned char>& plaintext, const std::string& pubKey) {

    //Create pKey from public key
    auto pKey = createPublicKeyFromStr(pubKey);
    if (!pKey) return std::vector<unsigned char>();

    //Create context
    auto ctx = EVP_PKEY_CTX_new(pKey, nullptr);
    if (!ctx) {
        EVP_PKEY_free(pKey);
        return std::vector<unsigned char>();
    }

    if (EVP_PKEY_encrypt_init(ctx) <= 0) {
        EVP_PKEY_free(pKey);
        EVP_PKEY_CTX_free(ctx);
        return std::vector<unsigned char>();
    }

    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0) {
        EVP_PKEY_free(pKey);
        EVP_PKEY_CTX_free(ctx);
        return std::vector<unsigned char>();
    }

    size_t ciphertextLen = 0;
    //Get the buffer size
    if (EVP_PKEY_encrypt(ctx, nullptr, &ciphertextLen, plaintext.data(), plaintext.size()) <= 0) {
        EVP_PKEY_free(pKey);
        EVP_PKEY_CTX_free(ctx);
        return std::vector<unsigned char>();
    }

    std::vector<unsigned char> ciphertext(ciphertextLen);
    if (EVP_PKEY_encrypt(ctx, ciphertext.data(), &ciphertextLen, plaintext.data(), plaintext.size()) <= 0) {
        EVP_PKEY_free(pKey);
        EVP_PKEY_CTX_free(ctx);
        return std::vector<unsigned char>();
    }

    // Cleanup
    EVP_PKEY_free(pKey);
    EVP_PKEY_CTX_free(ctx);

    return ciphertext;
}

// Decrypt data using RSA private key
std::vector<unsigned char> RSA_OSSL::decryptPrivate(const std::vector<unsigned char>& ciphertext, const std::string& privKey) {
    // Create EVP_PKEY* from the private key string representation
    EVP_PKEY* privateKey = createPrivateKeyFromStr(privKey);
    if (!privateKey) {
        // Handle error
        return std::vector<unsigned char>();
    }

    // Create EVP_PKEY_CTX
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(privateKey, nullptr);
    if (!ctx) {
        EVP_PKEY_free(privateKey);
        // Handle error
        return std::vector<unsigned char>();
    }

    // Initialize decryption operation
    if (EVP_PKEY_decrypt_init(ctx) <= 0) {
        EVP_PKEY_free(privateKey);
        EVP_PKEY_CTX_free(ctx);
        // Handle error
        return std::vector<unsigned char>();
    }

    // Set RSA padding
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0) {
        EVP_PKEY_free(privateKey);
        EVP_PKEY_CTX_free(ctx);
        // Handle error
        return std::vector<unsigned char>();
    }

    // Get the size of the plaintext
    size_t plaintextLen = 0;
    if (EVP_PKEY_decrypt(ctx, nullptr, &plaintextLen, ciphertext.data(), ciphertext.size()) <= 0) {
        EVP_PKEY_free(privateKey);
        EVP_PKEY_CTX_free(ctx);
        // Handle error
        return std::vector<unsigned char>();
    }

    // Allocate memory for plaintext
    std::vector<unsigned char> plaintext(plaintextLen);

    // Perform the decryption
    if (EVP_PKEY_decrypt(ctx, plaintext.data(), &plaintextLen, ciphertext.data(), ciphertext.size()) <= 0) {
        EVP_PKEY_free(privateKey);
        EVP_PKEY_CTX_free(ctx);
        // Handle error
        return std::vector<unsigned char>();
    }

    // Cleanup
    EVP_PKEY_free(privateKey);
    EVP_PKEY_CTX_free(ctx);

    return plaintext;
}