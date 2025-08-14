#include "MessageHandler.h"
#include "NetworkManager.h"
#include "Encryption_Decryption.h"
#include <errno.h>
#include <sstream>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>
using namespace std;


MessageHandler::MessageHandler(NetworkManager *networkManager, EncryptionDecryption *encryptionDecryption)
    : networkManager(networkManager), encryptionDecryption(encryptionDecryption) {}

MessageHandler::~MessageHandler() {}

void MessageHandler::sendMessage(const string &message, const string &recipient)
{
    if(debugMode) {
        cout << "[ChatWindow] ===== PROCESSING CHAT_HISTORY_MSG =====" << endl;
        cout << "[ChatWindow] Full message: " << message << endl;
    }
    if (networkManager && encryptionDecryption)
    {
        encryptionDecryption->loadUserPublicKey(recipient);
        string encryptedMessage = encryptionDecryption->encrypt(message, recipient);
        if (encryptedMessage.empty()) {
            if (debugMode) {
                cout << "[-] Failed to encrypt message for recipient: " << recipient << endl;
            }
            return;
        }

        string encodedMessage = base64_encode(encryptedMessage);

        string fullMessage = networkManager->username + ":" + recipient + ":ENCRYPTED:" + encodedMessage;
        send(networkManager->socket_fd, fullMessage.c_str(), fullMessage.size(), 0);


        networkManager->addContactedUser(recipient);
        if (debugMode) {
            cout << "[MessageHandler] Sent encrypted message to: " << recipient << endl;
        }
    }
}

string MessageHandler::receiveMessage()
{
    if (networkManager)
    {
        char buffer[1024] = {0};
        int bytesReceived = recv(networkManager->socket_fd, buffer, sizeof(buffer) - 1, MSG_DONTWAIT);
        if (bytesReceived > 0)
        {
            buffer[bytesReceived] = '\0';
            string message(buffer);
            if (debugMode) {
                cout << "[MessageHandler::receiveMessage] Raw received data (" << bytesReceived << " bytes): " << endl;
                cout << "<<<" << message << ">>>" << endl;
            }

\
            istringstream iss(message);
            string line;
            string lastProcessedMessage;

            while (getline(iss, line))
            {
                if (line.empty())
                    continue;
                if (debugMode) {
                    cout << "[MessageHandler] Processing line: " << line << endl;
                }
                lastProcessedMessage = line;


                if (line.substr(0, 16) == "CONTACTED_USERS:")
                {
                    networkManager->processServerMessage(line);
                    continue;
                }


                if (line.substr(0, 19) == "CHAT_HISTORY_START:" ||
                    line.substr(0, 17) == "CHAT_HISTORY_MSG:" ||
                    line.substr(0, 17) == "CHAT_HISTORY_END:" ||
                    line.substr(0, 19) == "CHAT_HISTORY_ERROR:")
                {
                    if (debugMode) {
                        cout << "[MessageHandler] Received chat history message: " << line.substr(0, 50) << "..." << endl;
                    }
                    networkManager->processServerMessage(line);
                    if (debugMode) {
                        cout << "[MessageHandler] Processed chat history message" << endl;
                    }
                    continue;
                }


                size_t colonPos = line.find(": ");
                if (colonPos != string::npos)
                {
                    string sender = line.substr(0, colonPos);
                    string messageContent = line.substr(colonPos + 2);
                    
                    if (messageContent.substr(0, 10) == "ENCRYPTED:") {
                        string encryptedData = messageContent.substr(10);
                        

                        string decodedData = base64_decode(encryptedData);
                        

                        if (encryptionDecryption) {
                            string decryptedMessage = encryptionDecryption->decrypt(decodedData);
                            if (!decryptedMessage.empty()) {
                                lastProcessedMessage = sender + ": " + decryptedMessage;
                                if (debugMode) {
                                    cout << "[MessageHandler] Decrypted message from: " << sender << endl;
                                }
                            } else {
                                if (debugMode) {
                                    cerr << "[MessageHandler] Failed to decrypt message from: " << sender << endl;
                                }
                                lastProcessedMessage = sender + ": [Failed to decrypt message]";
                            }
                        } else {
                            lastProcessedMessage = sender + ": [Encrypted message - decryption unavailable]";
                        }
                    }
                    
                    if (!sender.empty() && sender != networkManager->username)
                    {
                        networkManager->addContactedUser(sender);
                    }
                }
            }

            return lastProcessedMessage;
        }
        else if (bytesReceived < 0 && errno != EAGAIN && errno != EWOULDBLOCK)
        {
            if (debugMode) {
                cerr << "[-] Error receiving message: " << strerror(errno) << endl;
            }
        }
    }
    return "";
}

string MessageHandler::base64_encode(const string& input) {
    BIO *bio, *b64;
    BUF_MEM *bufferPtr;

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);

    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(bio, input.c_str(), input.length());
    BIO_flush(bio);
    BIO_get_mem_ptr(bio, &bufferPtr);

    string result(bufferPtr->data, bufferPtr->length);
    BIO_free_all(bio);

    return result;
}

string MessageHandler::base64_decode(const string& input) {
    BIO *bio, *b64;
    char *buffer = new char[input.length()];
    
    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new_mem_buf(input.c_str(), input.length());
    bio = BIO_push(b64, bio);
    
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    int decodedLength = BIO_read(bio, buffer, input.length());
    BIO_free_all(bio);
    
    string result;
    if (decodedLength > 0) {
        result = string(buffer, decodedLength);
    }
    
    delete[] buffer;
    return result;
}

string MessageHandler::decryptMessage(const string& encryptedMessage, const string& sender) {
    if (!encryptionDecryption) {
        if (debugMode) {
            cerr << "[MessageHandler] EncryptionDecryption not available for decryption" << endl;
        }
        return "Failed to decrypt message";
    }

    if (debugMode) {
        cout << "[MessageHandler] Attempting to decrypt message from: " << sender << endl;
        cout << "[MessageHandler] Encrypted message length: " << encryptedMessage.length() << endl;
        cout << "[MessageHandler] First 50 chars: " << encryptedMessage.substr(0, 50) << endl;
    }

    try {
        string decodedMessage = base64_decode(encryptedMessage);
        if (debugMode) {
            cout << "[MessageHandler] Base64 decoded length: " << decodedMessage.length() << endl;
        }
        
        if (decodedMessage.empty()) {
            if (debugMode) {
                cerr << "[-] Base64 decoding failed" << endl;
            }
            return "Failed to decrypt message";
        }
        
        if (debugMode) {
            cout << "[MessageHandler] First 10 bytes of decoded data: ";
        }
        for (int i = 0; i < min(10, (int)decodedMessage.length()); i++) {
            printf("%02x ", (unsigned char)decodedMessage[i]);
        }
        cout << endl;
        

        if (debugMode) {
            cout << "[MessageHandler] Using our private key for decryption" << endl;
        }
        

        string decryptedMessage = encryptionDecryption->decrypt(decodedMessage);
        
        if (decryptedMessage.empty()) {
            if (debugMode) {
                cerr << "Failed to decrypt message from sender: " << sender << endl;
            }
            return "Failed to decrypt message";
        }
        
        if (debugMode) {
            cout << "[MessageHandler] Successfully decrypted message from: " << sender << endl;
            cout << "[MessageHandler] Decrypted message: " << decryptedMessage.substr(0, 50) << "..." << endl;
        }
        return decryptedMessage;
    }
    catch (const exception& e) {
        if (debugMode) {
            cerr << "[MessageHandler] Exception during decryption: " << e.what() << endl;
        }
        return "Error decrypting message";
    }
}
