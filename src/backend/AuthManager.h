#ifndef AUTH_MANAGER_H
#define AUTH_MANAGER_H

#include <libsecret-1/libsecret/secret.h>

static const SecretSchema snibble_schema = {
    "com.snibble.credentials", SECRET_SCHEMA_NONE,
    {
        { "application", SECRET_SCHEMA_ATTRIBUTE_STRING },
        { "type", SECRET_SCHEMA_ATTRIBUTE_STRING },
        { NULL, (SecretSchemaAttributeType)0 },
    }
};

#define SNIBBLE_SCHEMA &snibble_schema

#include <string>
#include <vector>
#include <curl/curl.h>
#include <iostream>
#include <jwt-cpp/jwt.h>
#include <json/json.h>
#include <dotenv.h>

struct WriteCallbackData {
    std::string data;
};

class AuthManager {
private:
    bool verbose = true;
    std::string HOST;
    int PORT;
    CURL* curl = NULL;
    std::string currentToken;
    std::string currentUsername;
    
    bool storeCredentialsSecurely(const std::string& username, const std::string& token);
    bool loadCredentialsFromStorage();
    void clearStoredCredentials();
    
    static size_t WriteCallback(void* contents, size_t size, size_t nmemb, WriteCallbackData* data);
    
public:
    AuthManager(const bool& verbose, const std::string& HOST, const int& PORT);
    ~AuthManager();
    bool login(const std::string& username, const std::string& password);
    bool signup(const std::string& username, const std::string& password);
    bool logout(const std::string username);
    
    std::vector<std::string> searchUsers(const std::string& query);
    
    bool uploadPublicKey(const std::string& username, const std::string& publicKey);
    
    bool verifyToken(const std::string& token);
    bool isTokenValid();
    std::string getCurrentToken() const { return currentToken; }
    std::string getCurrentUsername() const { return currentUsername; }
    bool restoreSession();
};

#endif