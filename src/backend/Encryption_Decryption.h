#ifndef ENCRYPTION_DECRYPTION_H
#define ENCRYPTION_DECRYPTION_H

#include <string>
#include <unordered_map>
#include <openssl/evp.h>

class EncryptionDecryption {
private:
    std::string AUTH_HOST;
    int AUTH_PORT;
    EVP_PKEY* keypair = nullptr;
    std::unordered_map<std::string, EVP_PKEY*> userPublicKeys; // Cache for user public keys
    bool debugMode = false;
    bool loadMyKeys();
    bool fetchPublicKey(const std::string& recipient);
    void saveMyKeys();
    void generateKeys();
    bool uploadPublicKey();
    bool needsPublicKeyUpload(); // Check if public key needs to be uploaded

public:
    EncryptionDecryption(std::string auth_host, int auth_port);
    ~EncryptionDecryption();

    std::string encrypt(const std::string& data, const std::string& recipient);
    std::string decrypt(const std::string& data);
    bool loadUserPublicKey(const std::string& username);
    std::string getMyPublicKey();
};

#endif
