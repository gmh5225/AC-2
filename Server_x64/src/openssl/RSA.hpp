#pragma once

#include <vector>
#include <iostream>

#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <optional>

typedef struct {
    std::string pubKey;
    std::string privKey;
}KEY_PAIR;

namespace RSA_OSSL {

    // Generate an RSA key pair and return the public key as a string
    std::optional<KEY_PAIR> generateKeyPair(int bits);

    EVP_PKEY* createPublicKeyFromStr(const std::string& publicKeyStr);

    EVP_PKEY* createPrivateKeyFromStr(const std::string& privateKeyStr);

    // Encrypt data using RSA public key
    std::vector<unsigned char> encryptPublic(const std::vector<unsigned char>& plaintext, const std::string& pubKey);
    
    // Decrypt data using RSA private key
    std::vector<unsigned char> decryptPrivate(const std::vector<unsigned char>& ciphertext, const std::string& privKey);

}