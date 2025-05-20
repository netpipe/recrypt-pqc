#include "RSM.h"

// maybe use last 8 bytes of private key hashed as the key and also give it with public key for messages sent from sender so they need key to decrypt(secondary key) optional

int main() {
    ModuloEncryptor::PublicKey pub;
    ModuloEncryptor::PrivateKey priv;
    ModuloEncryptor::generateKeys(pub, priv,128);

    std::string pubkeye= pub.e.get_str(); // GMP integer to decimal string
    std::string privkeyd = priv.d.get_str(); // GMP integer to decimal string
    std::string pubkeyn = pub.n.get_str(); // GMP integer to decimal string
    std::string privkeyn = priv.n.get_str(); // GMP integer to decimal string
  //  cout << "pubkey e: " << pubkeye << endl << "privkey e: " << pubkeyn <<endl;
  //  cout << "privkey d: " << privkeyd << endl << "privkey n: " << privkeyn <<endl;
    std::string pubkey = pubkeye + ":" + pubkeyn;
    std::string privkey = privkeyd + ":" + privkeyn;

        cout << "PubKEY: " << pubkey << endl;
        cout << "PrivKEY: " << privkey << endl;
    if (0){// for testing
        size_t delim_pos = pubkey.find(':');
        std::string pubextracted_e = pubkey.substr(0, delim_pos);
        std::string pubextracted_n = pubkey.substr(delim_pos + 1);
        delim_pos = privkey.find(':');
        std::string privextracted_d = privkey.substr(0, delim_pos);
        std::string privextracted_n = privkey.substr(delim_pos + 1);
        //setting vars
        pub.e.set_str(pubextracted_e, 10);     // ✅ safe: base 10
        priv.d.set_str(privextracted_d, 10);
        pub.n.set_str(pubextracted_n, 10);
        priv.n.set_str(privextracted_n, 10);
       if (0){
        //setting vars back for debugging/matching
        pubkeye= pub.e.get_str();
        privkeyd = priv.d.get_str();
        pubkeyn = pub.n.get_str();
        privkeyn = priv.n.get_str();
        cout << "pubkey e: " << pubkeye << endl << "privkey e: " << pubkeyn <<endl;
        cout << "privkey d: " << privkeyd << endl << "privkey n: " << privkeyn <<endl;
       }
    }

    //Message to test
    string key = pubkey;
    //string key = "supersecret"; // its more secure as an extra string ?
    string message = "HelloWorld123";

    string enc = ModuloEncryptor::encrypt(message, pub, key);

    cout << "customMix: " << enc << endl;
    std::string tag = pubkeyn.substr(pubkeyn.size() - 8);
    // std::string tag = sha256(enc).substr(0, 8);
    cout << "tag: " << tag << endl;
    enc.append(tag);

    //sender extra entropy Optional
    ModuloEncryptor::customMix(enc);
    ModuloEncryptor::flipBytePairs(enc);
	
	// Testing Entropy / Storage String
    cout << "encrypted: " << enc <<endl;

    //Receiver
    ModuloEncryptor::flipBytePairs(enc);
    ModuloEncryptor::customUnmix(enc);
    std::string extractedTag = enc.substr(enc.size() - 8);
    cout << "extractedTag: " << tag << endl;
    if (tag == extractedTag){
        cout << "Verified: "<< endl;
        string withoutTag = enc.substr(0, enc.size() - 8);
        // cout << "withouttag: " << withoutTag<< endl;
        string dec = ModuloEncryptor::decrypt(withoutTag, priv, key);
        cout << "Encrypted: " << enc << endl;
        cout << "Decrypted: " << dec << endl;
    }
    return 0;
}
