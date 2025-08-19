#include "Encryption_Decryption.h"
#include <random>
#include <libsecret-1/libsecret/secret.h>
#include <iostream>
#include <curl/curl.h>
#include <openssl/pem.h>
#include <openssl/err.h>
using namespace std;



static size_t WriteCallback(void* contents, size_t size, size_t nmemb, std::string* userp) {
    size_t totalSize = size * nmemb;
    userp->append((char*)contents, totalSize);
    return totalSize;
}

static const SecretSchema snibble_key_schema = {
    "com.snibble.keys", SECRET_SCHEMA_NONE,
    {
        { "application", SECRET_SCHEMA_ATTRIBUTE_STRING },
        { "type", SECRET_SCHEMA_ATTRIBUTE_STRING },
        { NULL, (SecretSchemaAttributeType)0 },
    }
};

EncryptionDecryption::EncryptionDecryption(std::string auth_host, int auth_port) : AUTH_HOST(auth_host), AUTH_PORT(auth_port) {
    if (!loadMyKeys()) {
        generateKeys();
        saveMyKeys();
        uploadPublicKey();
    } else {
        if (debugMode) {
            cout << "Keys loaded from local storage. Public key upload skipped." << endl;
        }
    }
}

EncryptionDecryption::~EncryptionDecryption() {
    if (keypair) EVP_PKEY_free(keypair);
    
    for (auto& pair : userPublicKeys) {
        if (pair.second) EVP_PKEY_free(pair.second);
    }
    userPublicKeys.clear();
}


bool EncryptionDecryption::loadMyKeys() {
    try {
        GError* error = NULL;
        gchar* key_pem = secret_password_lookup_sync(
            &snibble_key_schema,
            nullptr,
            &error,
            "application", "snibble",
            "type", "private_key",
            nullptr
        );

        if (!key_pem) {
            if (error) {
                cerr << "Error loading private key: " << error->message << endl;
                g_error_free(error);
            }
            if (debugMode) {
                cout << "key_pem is empty" << endl;
            }
            return false;
        }

        BIO* bio = BIO_new_mem_buf(key_pem, -1);
        if (!bio) {
            g_free(key_pem);
            if (debugMode) {
                cout << "bio is empty" << endl;
            }
            return false;
        }

        EVP_PKEY* pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
        BIO_free(bio);
        g_free(key_pem);

        if (!pkey) {
            if (debugMode) {
                cerr << "Failed to parse private key from PEM" << endl;
            }
            return false;
        }

        keypair = pkey;
        return true;
    }
    catch (const exception& e) {
        if (debugMode) {
            cerr << "Exception in loadMyKeys: " << e.what() << endl;
        }
        return false;
    }
}


bool EncryptionDecryption::fetchPublicKey(const std::string& recipient) {
    try {
        CURL* curl = curl_easy_init();
        if (!curl) {
            if (debugMode) {
                cerr << "Failed to initialize CURL." << endl;
            }
            return false;
        }

        curl_slist* slist = nullptr;
        string json_data = "{\"recipient\": \"" + recipient + "\"}";
        slist = curl_slist_append(slist, "Content-Type: application/json");

        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, slist);
        curl_easy_setopt(curl, CURLOPT_URL, ("http://" + AUTH_HOST + ":" + std::to_string(AUTH_PORT) + "/get_public_key").c_str());
        curl_easy_setopt(curl, CURLOPT_POST, 1L);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json_data.c_str());

        string buffer;
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &buffer);

        CURLcode res = curl_easy_perform(curl);
        curl_slist_free_all(slist);
        curl_easy_cleanup(curl);

        if (res != CURLE_OK) {
            if (debugMode) {
                cerr << "CURL request failed: " << curl_easy_strerror(res) << endl;
            }
            return false;
        }

        BIO* bio = BIO_new_mem_buf(buffer.data(), buffer.size());
        EVP_PKEY* pubkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
        BIO_free(bio);

        if (!pubkey) {
            if (debugMode) {
                cerr << "Failed to parse public key for user: " << recipient << endl;
            }
            return false;
        }

        userPublicKeys[recipient] = pubkey;
        if (debugMode) {
            if (debugMode) {
                cout << "Successfully fetched and cached public key for: " << recipient << endl;
            }
        }

        return true;
    }
    catch (const exception& e) {
        if (debugMode) {
            if (debugMode) {
                cerr << "Exception in fetchPublicKey: " << e.what() << endl;
            }
        }
        return false;
    }
}


void EncryptionDecryption::saveMyKeys() {

    try {
        BIO* bio_priv = BIO_new(BIO_s_mem());
        if (!PEM_write_bio_PrivateKey(bio_priv, keypair, NULL, NULL, 0, NULL, NULL)) {
            BIO_free(bio_priv);
            if (debugMode) {
                cerr << "Error writing private key to PEM" << endl;
            }
            return;
        }

        char* priv_pem_data = NULL;
        long priv_pem_len = BIO_get_mem_data(bio_priv, &priv_pem_data);
        string priv_pem_str(priv_pem_data, priv_pem_len);
        BIO_free(bio_priv);

        GError* error = NULL;
        secret_password_store_sync(
            &snibble_key_schema,
            SECRET_COLLECTION_DEFAULT,
            "Snibble Private Key",
            priv_pem_str.c_str(),
            NULL,
            &error,
            "application", "snibble",
            "type", "private_key",
            NULL
        );

        if (error) {
            if (debugMode) {
                cerr << "Error saving private key: " << error->message << endl;
            }
            g_error_free(error);
        } else {
            if (debugMode) {
                cerr << "Private key saved locally." << endl;
            }
        }
        BIO* bio_pub = BIO_new(BIO_s_mem());
        if (!PEM_write_bio_PUBKEY(bio_pub, keypair)) {
            BIO_free(bio_pub);
            if (debugMode) {
                cerr << "Error writing public key to PEM" << endl;
            }
            return;
        }

        char* pub_pem_data = NULL;
        long pub_pem_len = BIO_get_mem_data(bio_pub, &pub_pem_data);
        string pub_pem_str(pub_pem_data, pub_pem_len);
        BIO_free(bio_pub);

        CURL* curl = curl_easy_init();
        if (!curl) {
            if (debugMode) {
                cerr << "[-] Failed to initialize CURL." << endl;
            }
            return;
        }

        string json_data = "{\"public_key\": \"" + pub_pem_str + "\"}";
        curl_slist* slist = nullptr;
        slist = curl_slist_append(slist, "Content-Type: application/json");

        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, slist);
        curl_easy_setopt(curl, CURLOPT_URL, (AUTH_HOST + "/save_public_key").c_str());
        curl_easy_setopt(curl, CURLOPT_POST, 1L);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json_data.c_str());

        CURLcode res = curl_easy_perform(curl);
        if (res != CURLE_OK) {
            if (debugMode) {
                cerr << "[-] CURL error sending public key: " << curl_easy_strerror(res) << endl;
            }
        } else {
            if (debugMode) {
                cout << "[+] Public key uploaded to server successfully." << endl;
            }
        }

        curl_slist_free_all(slist);
        curl_easy_cleanup(curl);

    } catch (const exception& e) {
        if (debugMode) {
            cerr << "Exception in saveMyKeys: " << e.what() << endl;
        }
    }
}




void handleErrors() {
    ERR_print_errors_fp(stderr);
    abort();
}

void EncryptionDecryption::generateKeys() {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (!ctx) handleErrors();

    if (EVP_PKEY_keygen_init(ctx) <= 0) handleErrors();
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0) handleErrors();
    if (EVP_PKEY_keygen(ctx, &keypair) <= 0) handleErrors();

    EVP_PKEY_CTX_free(ctx);
}

string EncryptionDecryption::encrypt(const string& data, const string& recipient) {

    EVP_PKEY* recipientKey = nullptr;
    
    auto it = userPublicKeys.find(recipient);
    if (it != userPublicKeys.end()) {
        recipientKey = it->second;
    } else {
        if (!fetchPublicKey(recipient)) {
            if (debugMode) {
                cerr << "[-] Failed to fetch public key for recipient: " << recipient << endl;
            }
            return "";
        }
        recipientKey = userPublicKeys[recipient];
    }

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(recipientKey, NULL);
    if (!ctx) {
        handleErrors();
        return "";
    }
    
    if (EVP_PKEY_encrypt_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        handleErrors();
        return "";
    }
    
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        handleErrors();
        return "";
    }

    size_t outlen;
    if (EVP_PKEY_encrypt(ctx, NULL, &outlen,
                         reinterpret_cast<const unsigned char*>(data.data()),
                         data.size()) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        handleErrors();
        return "";
    }

    vector<unsigned char> outbuf(outlen);
    if (EVP_PKEY_encrypt(ctx, outbuf.data(), &outlen,
                         reinterpret_cast<const unsigned char*>(data.data()),
                         data.size()) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        handleErrors();
        return "";
    }

    EVP_PKEY_CTX_free(ctx);
    return string(reinterpret_cast<char*>(outbuf.data()), outlen);
}

string EncryptionDecryption::decrypt(const string& data) {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(keypair, NULL);
    if (!ctx) {
        handleErrors();
        return "";
    }
    
    if (EVP_PKEY_decrypt_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        handleErrors();
        return "";
    }
    
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        handleErrors();
        return "";
    }

    size_t outlen;
    if (EVP_PKEY_decrypt(ctx, NULL, &outlen,
                         reinterpret_cast<const unsigned char*>(data.data()),
                         data.size()) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        handleErrors();
        return "";
    }

    vector<unsigned char> outbuf(outlen);
    if (EVP_PKEY_decrypt(ctx, outbuf.data(), &outlen,
                         reinterpret_cast<const unsigned char*>(data.data()),
                         data.size()) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        handleErrors();
        return "";
    }

    EVP_PKEY_CTX_free(ctx);
    return string(reinterpret_cast<char*>(outbuf.data()), outlen);
}

bool EncryptionDecryption::loadUserPublicKey(const string& username) {
    return fetchPublicKey(username);
}

string EncryptionDecryption::getMyPublicKey() {
    try {
        BIO* bio_pub = BIO_new(BIO_s_mem());
        if (!PEM_write_bio_PUBKEY(bio_pub, keypair)) {
            BIO_free(bio_pub);
            if (debugMode) {
                cerr << "[-] Failed to write public key to BIO" << endl;
            }
            return "";
        }

        char* pub_pem_data = NULL;
        long pub_pem_len = BIO_get_mem_data(bio_pub, &pub_pem_data);
        string pub_pem_str(pub_pem_data, pub_pem_len);
        BIO_free(bio_pub);

        return pub_pem_str;
    } catch (const exception& e) {
        if (debugMode) {
            cerr << "Exception in getMyPublicKey: " << e.what() << endl;
        }
        return "";
    }
}

bool EncryptionDecryption::uploadPublicKey() {
    try {
        string publicKeyPem = getMyPublicKey();
        if (publicKeyPem.empty()) {
            if (debugMode) {
                cerr << "Failed to get public key for upload" << endl;
            }
            return false;
        }

        if (debugMode) {
            cout << "Public key ready for upload" << endl;
        }
        return true;
    } catch (const exception& e) {
        if (debugMode) {
            cerr << "[-] Exception in uploadPublicKey: " << e.what() << endl;
        }
        return false;
    }
}
