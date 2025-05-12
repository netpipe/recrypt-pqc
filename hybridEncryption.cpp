#include <iostream>
#include <vector>
#include <string>
#include <algorithm>
#include <random>
#include <sstream>
#include <ctime>
#include <functional>

// Simple Caesar cipher
std::string caesarEncrypt(const std::string& input, int shift) {
    std::string result = input;
    for (char& c : result) c += shift;
    return result;
}

std::string caesarDecrypt(const std::string& input, int shift) {
    std::string result = input;
    for (char& c : result) c -= shift;
    return result;
}

// Simple XOR cipher
std::string xorEncryptDecrypt(const std::string& input, char key) {
    std::string result = input;
    for (char& c : result) c ^= key;
    return result;
}

// Simulated Base64 encode/decode (reverse string for demo)
std::string fakeBase64Encode(const std::string& input) {
    return std::string(input.rbegin(), input.rend());
}

std::string fakeBase64Decode(const std::string& input) {
    return std::string(input.rbegin(), input.rend());
}

// Simulated hash
std::string simpleHash(const std::string& input) {
    std::hash<std::string> hasher;
    return std::to_string(hasher(input));
}

// Simulated RSA sign/verify using hash prefix match
std::string signMessage(const std::string& message, const std::string& privateKey) {
    return simpleHash(privateKey + message);
}

bool verifySignature(const std::string& message, const std::string& signature, const std::string& publicKey) {
    return simpleHash(publicKey + message) == signature;
}

// Get permutation from key
std::vector<int> getMethodOrder(const std::string& key) {
    std::vector<int> order = {0, 1, 2};
    std::seed_seq seed(key.begin(), key.end());
    std::mt19937 rng(seed);
    std::shuffle(order.begin(), order.end(), rng);
    return order;
}

// Encrypt using permutation
std::string hybridEncrypt(const std::string& message, const std::string& key, std::vector<int>& methodOrder) {
    methodOrder = getMethodOrder(key);
    std::string temp = message;
    for (int method : methodOrder) {
        if (method == 0) temp = caesarEncrypt(temp, 3);
        else if (method == 1) temp = xorEncryptDecrypt(temp, 'K');
        else if (method == 2) temp = fakeBase64Encode(temp);
    }
    return temp;
}

// Decrypt using reverse permutation
std::string hybridDecrypt(const std::string& ciphertext, const std::string& key, const std::vector<int>& methodOrder) {
    std::string temp = ciphertext;
    for (auto it = methodOrder.rbegin(); it != methodOrder.rend(); ++it) {
        int method = *it;
        if (method == 0) temp = caesarDecrypt(temp, 3);
        else if (method == 1) temp = xorEncryptDecrypt(temp, 'K');
        else if (method == 2) temp = fakeBase64Decode(temp);
    }
    return temp;
}

int main() {
    std::string message = "Hello, Hybrid PQC!";
    std::string privateKey = "my_private_key_xyz";
    std::string publicKey = "my_private_key_xyz"; // Simulated

    std::string signature = signMessage(message, privateKey);

    std::vector<int> methodOrder;
    std::string encrypted = hybridEncrypt(message, publicKey, methodOrder);
    std::string decrypted = hybridDecrypt(encrypted, publicKey, methodOrder);

    std::cout << "Original: " << message << std::endl;
    std::cout << "Signature: " << signature << std::endl;
    std::cout << "Encryption Order: ";
    for (int i : methodOrder) std::cout << i << " ";
    std::cout << std::endl;
    std::cout << "Encrypted: " << encrypted << std::endl;
    std::cout << "Decrypted: " << decrypted << std::endl;
    std::cout << (verifySignature(decrypted, signature, publicKey) ? "\u2705 Signature verified." : "\u274C Verification failed!") << std::endl;

    return 0;
}
