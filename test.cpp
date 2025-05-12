#include <iostream>
#include <string>
#include <vector>
#include <cryptopp/rsa.h>
#include <cryptopp/osrng.h>
#include <cryptopp/sha.h>
#include <cryptopp/aes.h>
#include <cryptopp/filters.h>
#include <cryptopp/hex.h>
#include <cryptopp/modes.h>
#include <cryptopp/pssr.h>
#include <cryptopp/files.h>
#include <cryptopp/secblock.h>

using namespace CryptoPP;
using namespace std;

// Mocked Kyber-like public key (just random bytes for this example)
string generateKyberPublicKey(size_t len = 32) {
    AutoSeededRandomPool rng;
    SecByteBlock key(len);
    rng.GenerateBlock(key, key.size());

    string encoded;
    StringSource(key, key.size(), true, new HexEncoder(new StringSink(encoded)));
    return encoded;
}

// Derive AES key from Kyber public key (via SHA256)
SecByteBlock deriveAESKeyFromKyber(const string& kyberPubKey) {
    SHA256 hash;
    SecByteBlock aesKey(AES::DEFAULT_KEYLENGTH);
    hash.CalculateDigest(aesKey, (const byte*)kyberPubKey.data(), kyberPubKey.size());
    return aesKey;
}

// AES Encrypt message
string aesEncrypt(const string& message, const SecByteBlock& key, byte iv[AES::BLOCKSIZE]) {
    string ciphertext;
    CBC_Mode<AES>::Encryption enc;
    enc.SetKeyWithIV(key, key.size(), iv);

    StringSource(message, true,
        new StreamTransformationFilter(enc, new StringSink(ciphertext))
    );
    return ciphertext;
}

// AES Decrypt message
string aesDecrypt(const string& ciphertext, const SecByteBlock& key, byte iv[AES::BLOCKSIZE]) {
    string recovered;
    CBC_Mode<AES>::Decryption dec;
    dec.SetKeyWithIV(key, key.size(), iv);

    StringSource(ciphertext, true,
        new StreamTransformationFilter(dec, new StringSink(recovered))
    );
    return recovered;
}

// Sign data with RSA private key
string signMessage(const string& message, const RSA::PrivateKey& privateKey) {
    AutoSeededRandomPool rng;
    string signature;

    RSASS<PSS, SHA256>::Signer signer(privateKey);
    StringSource(message, true,
        new SignerFilter(rng, signer, new StringSink(signature))
    );
    return signature;
}

// Verify signature with RSA public key
bool verifySignature(const string& message, const string& signature, const RSA::PublicKey& publicKey) {
    RSASS<PSS, SHA256>::Verifier verifier(publicKey);
    bool result = false;

    StringSource(signature + message, true,
        new SignatureVerificationFilter(verifier,
            new ArraySink((byte*)&result, sizeof(result)),
            SignatureVerificationFilter::SIGNATURE_AT_BEGIN
        )
    );
    return result;
}

int main() {
    AutoSeededRandomPool rng;

    // === Generate RSA keypair ===
    RSA::PrivateKey rsaPrivKey;
    rsaPrivKey.GenerateRandomWithKeySize(rng, 2048);
    RSA::PublicKey rsaPubKey(rsaPrivKey);

    // === Mock Kyber public key ===
    string kyberPubKey = generateKyberPublicKey();

    // === Derive AES key from "Kyber" public key ===
    SecByteBlock aesKey = deriveAESKeyFromKyber(kyberPubKey);

    // === Create IV ===
    byte iv[AES::BLOCKSIZE];
    rng.GenerateBlock(iv, AES::BLOCKSIZE);

    // === Original message ===
    string message = "Post-Quantum Hybrid Crypto!";
    cout << "Original: " << message << endl;

    // === Encrypt with AES derived from Kyber ===
    string ciphertext = aesEncrypt(message, aesKey, iv);

    // === Sign the ciphertext with RSA ===
    string signature = signMessage(ciphertext, rsaPrivKey);

    // === Simulate transfer of data ===
    // Send: ciphertext, signature, RSA public key, IV, kyberPubKey

    // === Receiver side ===
    // Derive key again from kyberPubKey
    SecByteBlock receiverAESKey = deriveAESKeyFromKyber(kyberPubKey);

    // Verify RSA Signature
    bool valid = verifySignature(ciphertext, signature, rsaPubKey);
    cout << (valid ? "✅ Signature verified!" : "❌ Signature invalid!") << endl;

    if (valid) {
        // Decrypt AES ciphertext
        string recovered = aesDecrypt(ciphertext, receiverAESKey, iv);
        cout << "Recovered: " << recovered << endl;
    }

    return 0;
}
