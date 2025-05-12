#include <iostream>
#include <string>
#include <vector>
#include <algorithm>
#include <cryptopp/rsa.h>
#include <cryptopp/osrng.h>
#include <cryptopp/sha.h>
#include <cryptopp/aes.h>
#include <cryptopp/chacha.h>
#include <cryptopp/filters.h>
#include <cryptopp/hex.h>
#include <cryptopp/modes.h>
#include <cryptopp/pssr.h>
#include <cryptopp/secblock.h>

using namespace CryptoPP;
using namespace std;

// Generate mock Kyber-like public key
string generateMockPublicKey(size_t length = 32) {
    AutoSeededRandomPool rng;
    SecByteBlock key(length);
    rng.GenerateBlock(key, key.size());
    return string((const char*)key.BytePtr(), key.size());
}

// Derive key and permutation from public key
pair<SecByteBlock, vector<string>> deriveKeyAndOrder(const string& pubKey) {
    SHA256 hash;
    SecByteBlock derivedKey(AES::DEFAULT_KEYLENGTH);
    hash.CalculateDigest(derivedKey, (const byte*)pubKey.data(), pubKey.size());

    // Create a simple permutation based on the hash
    vector<string> order = {"AES", "ChaCha"};
    int mod = derivedKey[0] % 2;
    if (mod == 1) std::swap(order[0], order[1]);

    return {derivedKey, order};
}

// AES CBC Encrypt
string aesEncrypt(const string& input, const SecByteBlock& key, byte iv[AES::BLOCKSIZE]) {
    CBC_Mode<AES>::Encryption enc;
    enc.SetKeyWithIV(key, key.size(), iv);
    string output;
    StringSource(input, true, new StreamTransformationFilter(enc, new StringSink(output)));
    return output;
}

// AES CBC Decrypt
string aesDecrypt(const string& input, const SecByteBlock& key, byte iv[AES::BLOCKSIZE]) {
    CBC_Mode<AES>::Decryption dec;
    dec.SetKeyWithIV(key, key.size(), iv);
    string output;
    StringSource(input, true, new StreamTransformationFilter(dec, new StringSink(output)));
    return output;
}

// ChaCha20 Encrypt/Decrypt
string chachaTransform(const string& input, const SecByteBlock& key, byte nonce[ChaCha::IV_LENGTH]) {
    string output;
    ChaCha::Encryption chacha;
    chacha.SetKeyWithIV(key, key.size(), nonce);
    StringSource(input, true, new StreamTransformationFilter(chacha, new StringSink(output)));
    return output;
}

// RSA sign
string sign(const string& msg, const RSA::PrivateKey& priv) {
    AutoSeededRandomPool rng;
    string signature;
    RSASS<PSS, SHA256>::Signer signer(priv);
    StringSource(msg, true, new SignerFilter(rng, signer, new StringSink(signature)));
    return signature;
}

// RSA verify
bool verify(const string& msg, const string& sig, const RSA::PublicKey& pub) {
    RSASS<PSS, SHA256>::Verifier verifier(pub);
    bool result = false;
    StringSource(sig + msg, true, new SignatureVerificationFilter(
        verifier, new ArraySink((byte*)&result, sizeof(result)),
        SignatureVerificationFilter::SIGNATURE_AT_BEGIN));
    return result;
}

int main() {
    AutoSeededRandomPool rng;

    // RSA keys
    RSA::PrivateKey priv;
    priv.GenerateRandomWithKeySize(rng, 2048);
    RSA::PublicKey pub(priv);

    // Generate mock public key (Kyber-style)
    string mockPubKey = generateMockPublicKey();
    auto [derivedKey, order] = deriveKeyAndOrder(mockPubKey);

    // Display algorithm order
    cout << "🔁 Encryption order: ";
    for (auto& algo : order) cout << algo << " ";
    cout << "\n";

    // IVs and nonces
    byte aesIV[AES::BLOCKSIZE]; rng.GenerateBlock(aesIV, AES::BLOCKSIZE);
    byte chachaNonce[ChaCha::IV_LENGTH]; rng.GenerateBlock(chachaNonce, ChaCha::IV_LENGTH);

    // Original message
    string message = "Hybrid PQC Simulation!";
    cout << "📤 Original: " << message << "\n";

    // === Encrypt in permuted order ===
    string encrypted = message;
    for (const auto& algo : order) {
        if (algo == "AES")
            encrypted = aesEncrypt(encrypted, derivedKey, aesIV);
        else if (algo == "ChaCha")
            encrypted = chachaTransform(encrypted, derivedKey, chachaNonce);
    }

    // Sign the final encrypted data
    string signature = sign(encrypted, priv);

    // === Decrypt in reverse order ===
    string received = encrypted;
    bool valid = verify(received, signature, pub);
    cout << (valid ? "✅ Signature valid!\n" : "❌ Signature failed!\n");

    if (valid) {
        for (auto it = order.rbegin(); it != order.rend(); ++it) {
            if (*it == "AES")
                received = aesDecrypt(received, derivedKey, aesIV);
            else if (*it == "ChaCha")
                received = chachaTransform(received, derivedKey, chachaNonce);
        }
        cout << "📥 Decrypted: " << received << "\n";
    }

    return 0;
}
