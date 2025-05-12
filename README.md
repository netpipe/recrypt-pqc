# multicrypt
multiple encryptions based on experimental random order encryptions from PKE to be PQC(post quantum)

for testing only currently.


🔐 PQC-Ready Hybrid Design (Encryption + Signing)
🧩 Components:

Kyber (or baby Kyber): Post-quantum public-key encryption (PKE)
RSA: Traditional digital signature + optional legacy support
Optional Transformations: Extra obfuscation, layered ciphers, permutation-based encoding
📤 Sender Side (Encrypt + Sign):
Encrypt message:
Encrypt with Kyber public key of the receiver:
C_kyber = Kyber_Encrypt(pub_kyber, message)
Sign ciphertext:
Use RSA private key of sender to sign:
Sig = RSA_Sign(priv_rsa, hash(C_kyber))
Send:
Send (C_kyber, Sig, pub_rsa_sender) to the receiver.
📥 Receiver Side (Verify + Decrypt):
Verify:
Verify Sig using sender’s RSA public key:
valid = RSA_Verify(pub_rsa_sender, hash(C_kyber), Sig)
If invalid, reject message.
Decrypt:
Use receiver’s Kyber private key:
message = Kyber_Decrypt(priv_kyber, C_kyber)

✅ Why This Works
You get post-quantum confidentiality from Kyber (resistant to quantum attacks).
You get authentication and non-repudiation from RSA (or swap in a PQC signature scheme later).
You can still be interoperable with older systems while preparing for a post-quantum future.
🚀 Optional Enhancements
Extract a method permutation from hash(pub_kyber) to layer obfuscation on the message before encryption (like applying transformations).
Consider adding a key derivation step: derive a symmetric AES key from Kyber, and use it for message encryption instead.
Replace RSA signatures with Dilithium or SPHINCS+ when you're fully post-quantum.