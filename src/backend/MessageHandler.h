#ifndef MESSAGE_HANDLER_H
#define MESSAGE_HANDLER_H

#include <string>
#include <vector>
#include <memory>
#include <iostream>
#include <sys/socket.h>
#include <cstring>

class NetworkManager;
class EncryptionDecryption;

class MessageHandler {
private:
    NetworkManager* networkManager;
    EncryptionDecryption* encryptionDecryption; 
    bool debugMode = false;
    std::string base64_encode(const std::string& input);
    std::string base64_decode(const std::string& input);
    
public:
    MessageHandler(NetworkManager* networkManager, EncryptionDecryption* encryptionDecryption);
    ~MessageHandler();

    void sendMessage(const std::string& message, const std::string& recipient);
    std::string receiveMessage();
    std::string decryptMessage(const std::string& encryptedMessage, const std::string& sender);
};

#endif