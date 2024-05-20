#pragma once

#include <openssl/evp.h>
#include <openssl/sha.h>
#include <string>
#include <vector>
#include <sstream>
#include <iomanip>

namespace HASH {

    // Hash a buffer using SHA256
    std::vector<unsigned char> sha256(const std::vector<unsigned char>& buffer) {
        std::vector<unsigned char> hash(SHA256_DIGEST_LENGTH);
        EVP_MD_CTX* ctx = EVP_MD_CTX_new();
        EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr);
        EVP_DigestUpdate(ctx, buffer.data(), buffer.size());
        EVP_DigestFinal_ex(ctx, hash.data(), nullptr);
        EVP_MD_CTX_free(ctx);
        return hash;
    }

    // Hash a string using SHA256
    std::vector<unsigned char> sha256(const std::string& str) {
        return sha256(std::vector<unsigned char>(str.begin(), str.end()));
    }

    // Convert a hash vector to a string representation (hexadecimal)
    std::string hashToString(const std::vector<unsigned char>& hash) {
        std::stringstream ss;
        for (unsigned char byte : hash) {
            ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
        }
        return ss.str();
    }

    // Hash a buffer using SHA256 and return string representation
    std::string sha256String(const std::vector<unsigned char>& buffer) {
        std::vector<unsigned char> hash = sha256(buffer);
        return hashToString(hash);
    }

    // Hash a string using SHA256 and return string representation
    std::string sha256String(const std::string& str) {
        return sha256String(std::vector<unsigned char>(str.begin(), str.end()));
    }
}