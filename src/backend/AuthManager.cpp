#include "AuthManager.h"
#include <chrono>
#include <sstream>

using namespace std;


size_t AuthManager::WriteCallback(void* contents, size_t size, size_t nmemb, WriteCallbackData* data) {
    size_t realsize = size * nmemb;
    data->data.append((char*)contents, realsize);
    return realsize;
}

AuthManager::AuthManager(const bool& verbose, const std::string& HOST, const int& PORT)
: verbose(verbose), HOST(HOST), PORT(PORT) {
    dotenv::init("../.env");
    curl_global_init(CURL_GLOBAL_DEFAULT);
    curl = curl_easy_init();
    if (!curl) {
        cerr << "Failed to initialize CURL." << endl;
    }
    
    restoreSession();
}

AuthManager::~AuthManager() {
    if (curl) {
        curl_easy_cleanup(curl);
    }
    curl_global_cleanup();
}


bool AuthManager::login(const string& username, const string& password) {
    try {
        if(!curl) {
            throw runtime_error("CURL is not initialized.");
        }
        if (this->verbose) {
            cerr << "Attempting to log in user: " << username << endl;
        }
        string url = "http://" + HOST + ":" + to_string(PORT) + "/login";
        
        WriteCallbackData response_data;
        
        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response_data);
        
        struct curl_slist* slist1 = NULL;
        slist1 = curl_slist_append(slist1, "Content-Type: application/json");
        slist1 = curl_slist_append(slist1, "Accept: application/json");
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, slist1);
        
        string jsonData = "{\"username\":\"" + username + "\",\"password\":\"" + password + "\"}";
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, jsonData.c_str());
        
        CURLcode res = curl_easy_perform(curl);

        if(res == CURLE_OK) {
            long response_code;
            curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
            
            if (response_code == 200) {
 
                Json::Value json_response;
                Json::Reader reader;
                
                if (reader.parse(response_data.data, json_response)) {
                    if (json_response.isMember("token") && json_response.isMember("username")) {
                        currentToken = json_response["token"].asString();
                        currentUsername = json_response["username"].asString();

                        if (storeCredentialsSecurely(currentUsername, currentToken)) {
                            if (verbose) {
                                cerr << "Login successful, credentials stored securely." << endl;
                            }
                        }
                        
                        curl_slist_free_all(slist1);
                        return true;
                    }
                }
            }
            curl_slist_free_all(slist1);
            return false;
        }
        curl_slist_free_all(slist1);
        return false;
        
    } catch (const exception& e) {
        cerr << "Login error: " << e.what() << endl;
        return false;
    }
}

bool AuthManager::signup(const string& username, const string& password) {
    try {
        if(!curl) {
            throw runtime_error("CURL is not initialized.");
        }
        if (this->verbose) {
            cerr << "Attempting to sign up user: " << username << endl;
        }
        string url = "http://" + HOST + ":" + to_string(PORT) + "/signup";
        
        WriteCallbackData response_data;
        
        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response_data);
        
        struct curl_slist* slist1 = NULL;
        slist1 = curl_slist_append(slist1, "Content-Type: application/json");
        slist1 = curl_slist_append(slist1, "Accept: application/json");
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, slist1);
        
        string jsonData = "{\"username\":\"" + username + "\",\"password\":\"" + password + "\"}";
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, jsonData.c_str());
        
        CURLcode res = curl_easy_perform(curl);

        if(res == CURLE_OK) {
            long response_code;
            curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);

            
            if (response_code == 201) {
                curl_slist_free_all(slist1);
                return true;
            }
            curl_slist_free_all(slist1);
            return false;
        }
        curl_slist_free_all(slist1);
        return false;

    } catch (const exception& e) {
        cerr << "Signup error: " << e.what() << endl;
        return false;
    }
}

bool AuthManager::logout(const string username) {
    try {
        if(!curl) {
            throw runtime_error("CURL is not initialized.");
        }
        if (this->verbose) {
            cerr << "Attempting to log out user: " << username << endl;
        }
        
        clearStoredCredentials();
        currentToken.clear();
        currentUsername.clear();
        
        string url = "http://" + HOST + ":" + to_string(PORT) + "/logout";
        
        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        struct curl_slist* slist1 = NULL;
        slist1 = curl_slist_append(slist1, "Content-Type: application/json");
        slist1 = curl_slist_append(slist1, "Accept: application/json");
        slist1 = curl_slist_append(slist1, ("Authorization: Bearer " + currentToken).c_str());
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, slist1);
        
        string jsonData = "{\"username\":\"" + username + "\"}";
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, jsonData.c_str());
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, NULL);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, NULL);
        
        CURLcode res = curl_easy_perform(curl);
        curl_slist_free_all(slist1);
        
        return true;

    } catch (const exception& e) {
        cerr << "Logout error: " << e.what() << endl;
        clearStoredCredentials();
        currentToken.clear();
        currentUsername.clear();
        return true;
    }
}


bool AuthManager::verifyToken(const string& token) {
    if(token.empty()) {
        return false;
    }
    try {
        auto decoded = jwt::decode(token);

        const string JWT_SECRET = dotenv::getenv("JWT_SECRET", "your-super-secret-key-change-this-in-production");
        
        auto verifier = jwt::verify()
            .allow_algorithm(jwt::algorithm::hs256{JWT_SECRET})
            .with_type("JWT")
            .with_issuer("snibble-auth")
            .leeway(60UL);

        verifier.verify(decoded);
        auto now = std::chrono::system_clock::now();
        auto exp = decoded.get_expires_at();
        if(exp < now) {
            if(verbose) {
                cerr << "Token has expired" << endl;
            }
            return false;
        }
        if(decoded.has_payload_claim("username")) {
            string tokenUsername = decoded.get_payload_claim("username").as_string();
            if(tokenUsername != currentUsername and !currentUsername.empty()) {
                if(verbose) {
                    cerr << "Token username mismatch" << endl;
                }
                return false;
            }
        }
        if(verbose) {
            cerr << "Token verification successful" << endl;
        }
        return true;
    } catch(const jwt::error::signature_verification_exception& e) {
        if(verbose) {
            cerr << "Token signature verification failed: " << e.what() << endl;
        }
        return false;
    } catch(const jwt::error::token_verification_exception& e) {
        if (verbose) {
            cerr << "Token verification failed: " << e.what() << endl;
        }
        return false;
    } catch (const std::exception& e) {
        if (verbose) {
            cerr << "Token verification error: " << e.what() << endl;
        }
        return false;
    }
}


bool AuthManager::isTokenValid() {
    return verifyToken(currentToken);
}



bool AuthManager::loadCredentialsFromStorage() {
    try {
        GError* error = NULL;
        gchar* username = secret_password_lookup_sync(
            SNIBBLE_SCHEMA,
            NULL, 
            &error,
            "application", "snibble",
            "type", "username",
            NULL
        );
        if (error || !username) {
            if(error) g_error_free(error);
            return false;
        }
        error = NULL;
        gchar* token = secret_password_lookup_sync(
            SNIBBLE_SCHEMA,
            NULL,
            &error,
            "application", "snibble",
            "type", "token",
            NULL
        );
        if (error || !token) {
            if(error) g_error_free(error);
            secret_password_free(username);
            return false;
        }
        currentUsername = string(username);
        currentToken = string(token);

        secret_password_free(username);
        secret_password_free(token);

        return true;
    } catch (const exception& e) {
        if(verbose) {
            cerr << "Error loading the credentials: " << e.what() << endl;
        }
        return false;
    }
}


bool AuthManager::storeCredentialsSecurely(const string& username, const string& token) {
    try {
        GError* error = NULL;
        secret_password_store_sync(
            SNIBBLE_SCHEMA,
            SECRET_COLLECTION_DEFAULT,
            "Snibble Username",
            username.c_str(),
            NULL,
            &error,
            "application", "snibble",
            "type", "username",
            NULL
        );
        if(error) {
            if(verbose) {
                cerr << "Failed to store username: " << error->message << endl; 
            }
            g_error_free(error);
            return false;
        }

        error = NULL;
        secret_password_store_sync(
            SNIBBLE_SCHEMA,
            SECRET_COLLECTION_DEFAULT,
            "Snibble Token", 
            token.c_str(),
            NULL,
            &error,
            "application", "snibble",
            "type", "token",
            NULL
        );
        if(error) {
            if(verbose) {
                cerr << "Failed to store token: " << error->message << endl;
            }
            g_error_free(error);
            return false;
        }
        return true;
    } catch(const exception &e) {
        if(verbose) {
            cerr << "Error storing credentials: " << e.what() << endl;
        }
        return false;
    }
}


bool AuthManager::restoreSession() {
    if(loadCredentialsFromStorage()) {
        if (isTokenValid()) {
            if(verbose) {
                cerr << "Session restored successful for user: " << currentUsername << endl;
            }
            return true;
        } else {
            if(verbose) {
                cerr << "Stored token is invalid, clearing credentials" << endl;
            }
            clearStoredCredentials();
            currentToken.clear();
            currentUsername.clear();
        }
    }
    return false;
}



void AuthManager::clearStoredCredentials() {
    try {
        GError* error = NULL;
        secret_password_clear_sync(
            SNIBBLE_SCHEMA,
            NULL,
            &error,
            "application", "snibble",
            "type", "username",
            NULL
        );
        if (error) {
            if(verbose) {
                cerr << "Error clearing username: " << error->message << endl;
            }
            g_error_free(error);
        }

        error = NULL;
        secret_password_clear_sync(
            SNIBBLE_SCHEMA,
            NULL,
            &error,
            "application", "snibble",
            "type", "token",
            NULL
        );
        if(error) {
            if(verbose) {
                cerr << "Error clearing token: " << error->message <<endl;
            }
            g_error_free(error);
        }
    } catch (const exception &e) {
        if(verbose) {
            cerr << "Error clearing stored credentials: " << e.what() << endl;
        }
    }
}

std::vector<std::string> AuthManager::searchUsers(const std::string& query) {
    std::vector<std::string> results;
    
    try {
        if(!curl) {
            throw runtime_error("CURL is not initialized.");
        }
        
        if (query.empty() || query.length() < 2) {
            return results;
        }
        
        if (verbose) {
            cerr << "Searching for users with query: " << query << endl;
        }
        
        string url = "http://" + HOST + ":" + to_string(PORT) + "/search?q=" + query;
        
        WriteCallbackData response_data;
        
        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response_data);
        curl_easy_setopt(curl, CURLOPT_HTTPGET, 1L);
        struct curl_slist* slist1 = NULL;
        if (!currentToken.empty()) {
            string auth_header = "Authorization: Bearer " + currentToken;
            slist1 = curl_slist_append(slist1, auth_header.c_str());
            curl_easy_setopt(curl, CURLOPT_HTTPHEADER, slist1);
        }
        
        CURLcode res = curl_easy_perform(curl);
        
        if (slist1) {
            curl_slist_free_all(slist1);
        }
        
        if (res != CURLE_OK) {
            throw runtime_error("CURL request failed: " + string(curl_easy_strerror(res)));
        }
        
        long response_code;
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
        
        if (response_code == 200) {
            Json::Value root;
            Json::CharReaderBuilder builder;
            string errors;
            
            istringstream stream(response_data.data);
            if (Json::parseFromStream(builder, stream, &root, &errors)) {
                if (root.isArray()) {
                    for (const auto& user : root) {
                        if (user.isString()) {
                            results.push_back(user.asString());
                        } else if (user.isObject() && user.isMember("username")) {
                            results.push_back(user["username"].asString());
                        }
                    }
                }
            } else {
                if (verbose) {
                    cerr << "Failed to parse search response JSON: " << errors << endl;
                }
            }
        } else {
            if (verbose) {
                cerr << "Search request failed with status: " << response_code << endl;
                cerr << "Response: " << response_data.data << endl;
            }
        }
        
    } catch (const exception& e) {
        if (verbose) {
            cerr << "Error searching users: " << e.what() << endl;
        }
    }
    
    return results;
}

bool AuthManager::uploadPublicKey(const string& username, const string& publicKey) {
    try {
        if (!curl) {
            throw runtime_error("CURL is not initialized.");
        }
        
        if (verbose) {
            cout << "Uploading public key for user: " << username << endl;
        }
        
        string url = "http://" + HOST + ":" + to_string(PORT) + "/store_public_key";
        
        WriteCallbackData response_data;
        
        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response_data);
        
        struct curl_slist* slist1 = NULL;
        slist1 = curl_slist_append(slist1, "Content-Type: application/json");
        slist1 = curl_slist_append(slist1, "Accept: application/json");
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, slist1);
        
        Json::Value json_data;
        json_data["username"] = username;
        json_data["public_key"] = publicKey;
        
        Json::StreamWriterBuilder builder;
        string jsonString = Json::writeString(builder, json_data);
        
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, jsonString.c_str());
        
        CURLcode res = curl_easy_perform(curl);
        
        if (res != CURLE_OK) {
            curl_slist_free_all(slist1);
            throw runtime_error("CURL request failed: " + string(curl_easy_strerror(res)));
        }
        
        long response_code;
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
        
        curl_slist_free_all(slist1);
        
        if (response_code == 200) {
            if (verbose) {
                cout << "Successfully uploaded public key for user: " << username << endl;
            }
            return true;
        } else {
            if (verbose) {
                cerr << "Failed to upload public key. Status: " << response_code << endl;
                cerr << "Response: " << response_data.data << endl;
            }
            return false;
        }
        
    } catch (const exception& e) {
        if (verbose) {
            cerr << "Error uploading public key: " << e.what() << endl;
        }
        return false;
    }
}
