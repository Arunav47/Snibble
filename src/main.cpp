#include <QApplication>
#include "mainwindow.h"
#include <arpa/inet.h>
#include <cstring>
#include <curl/curl.h>
#include "ui/AuthWindow.h"
#include <QLineEdit>
#include "../src/backend/AuthManager.h"
#include "../src/backend/NetworkManager.h"
#include "../src/backend/MessageHandler.h"
#include "../src/backend/Encryption_Decryption.h"
#include <dotenv.h>
#include "ui/ChatWindow.h"
#include <signal.h>
#include <csignal>
#include <unistd.h>
using namespace std;

static NetworkManager* g_networkManager = nullptr;
static MessageHandler* g_messageHandler = nullptr;
static ChatWindow* g_chatWindow = nullptr;
static AuthWindow* g_authWindow = nullptr;
static EncryptionDecryption* g_encryptionDecryption = nullptr;
static bool g_verbose = false;

void cleanup() {
    static bool cleanupCalled = false;
    
    if (cleanupCalled) {
        if (g_verbose) {
            printf("Cleanup already performed, skipping...\n");
        }
        return;
    }
    
    cleanupCalled = true;
    if (g_verbose) {
        printf("Performing cleanup...\n");
    }
    
    if (g_chatWindow) {
        g_chatWindow->close();
        delete g_chatWindow;
        g_chatWindow = nullptr;
    }
    
    if (g_authWindow) {
        g_authWindow->close();
        delete g_authWindow;
        g_authWindow = nullptr;
    }
    
    if (g_messageHandler) {
        delete g_messageHandler;
        g_messageHandler = nullptr;
    }
    
    if (g_encryptionDecryption) {
        delete g_encryptionDecryption;
        g_encryptionDecryption = nullptr;
    }
    
    if (g_networkManager) {
        g_networkManager->forceDisconnect();
        delete g_networkManager;
        g_networkManager = nullptr;
    }
    
    if (g_verbose) {
        printf("Cleanup completed.\n");
    }
}

void signalHandler(int signal) {
    if (g_verbose) {
        printf("Signal %d received. Cleaning up...\n", signal);
    }
    cleanup();
    
    if (signal == SIGINT || signal == SIGTERM) {
        if (g_verbose) {
            printf("Forcing immediate exit due to signal %d\n", signal);
        }
        _exit(signal);
    }
    
    exit(signal);
}

int main(int argc, char *argv[])
{
    signal(SIGINT, signalHandler);
    signal(SIGTERM, signalHandler);
    signal(SIGABRT, signalHandler);
    
    dotenv::init("../.env");
    bool verbose = dotenv::getenv("VERBOSE", "false") == "true";
    g_verbose = verbose;
    string AUTH_HOST = dotenv::getenv("AUTH_HOST", "localhost");
    int AUTH_PORT = stoi(dotenv::getenv("AUTH_PORT", "8000"));
    string SOCKET_HOST = dotenv::getenv("SOCKET_HOST", "localhost");
    int SOCKET_PORT = stoi(dotenv::getenv("SOCKET_PORT", "8080"));
    bool isLoggedIn = false;
    
    QApplication a(argc, argv);
    a.setApplicationName("Snibble");
    a.setApplicationVersion("1.0.0");
    a.setOrganizationName("Snibble Inc.");
    a.setOrganizationDomain("snibble.example.com");
    
    AuthManager *authManager = new AuthManager(verbose, AUTH_HOST, AUTH_PORT);
    QLineEdit *usernameLineEdit = new QLineEdit();
    QLineEdit *passwordLineEdit = new QLineEdit();
    passwordLineEdit->setEchoMode(QLineEdit::Password);
    
    if (authManager->isTokenValid()) {
        isLoggedIn = true;
        usernameLineEdit->setText(QString::fromStdString(authManager->getCurrentUsername()));
        if (verbose) {
            printf("Restored session for user: %s\n", authManager->getCurrentUsername().c_str());
        }
    }
    AuthWindow *authWindow = nullptr;
    NetworkManager *networkManager = nullptr;
    MessageHandler *messageHandler = nullptr;
    EncryptionDecryption *encryption_decryption = nullptr;
    ChatWindow *chatWindow = nullptr;
    
    if(!isLoggedIn) {
        authWindow = new AuthWindow(&isLoggedIn, authManager, usernameLineEdit, passwordLineEdit);
        g_authWindow = authWindow;
        authWindow->resize(400, 300);

        QObject::connect(authWindow, &AuthWindow::loginSuccessful, [&]() {
            if (verbose) {
                printf("Login successful! Creating chat window...\n");
            }
            networkManager = new NetworkManager(usernameLineEdit->text().toStdString(), SOCKET_HOST, SOCKET_PORT);
            g_networkManager = networkManager;
            encryption_decryption = new EncryptionDecryption(AUTH_HOST, AUTH_PORT);
            g_encryptionDecryption = encryption_decryption;

            string publicKey = encryption_decryption->getMyPublicKey();
            if (!publicKey.empty()) {
                authManager->uploadPublicKey(usernameLineEdit->text().toStdString(), publicKey);
            }
            
            messageHandler = new MessageHandler(networkManager, encryption_decryption);
            g_messageHandler = messageHandler;
            chatWindow = new ChatWindow(networkManager, messageHandler);
            g_chatWindow = chatWindow;
            chatWindow->setAuthManager(authManager);
            chatWindow->resize(800, 600);
            chatWindow->show();
            
            QObject::connect(chatWindow, &ChatWindow::logoutRequested, [&]() {
                if (verbose) {
                    printf("Logout requested. Showing auth window...\n");
                }
                isLoggedIn = false;
                usernameLineEdit->clear();
                passwordLineEdit->clear();
                
                if (networkManager) {
                    delete networkManager;
                    networkManager = nullptr;
                    g_networkManager = nullptr;
                }
                if (messageHandler) {
                    delete messageHandler;
                    messageHandler = nullptr;
                    g_messageHandler = nullptr;
                }
                if (encryption_decryption) {
                    delete encryption_decryption;
                    encryption_decryption = nullptr;
                    g_encryptionDecryption = nullptr;
                }
                
                QObject::disconnect(chatWindow, &QWidget::destroyed, 0, 0);
                
                if (chatWindow) {
                    chatWindow->close();
                    delete chatWindow;
                    chatWindow = nullptr;
                    g_chatWindow = nullptr;
                }
                
                authWindow = new AuthWindow(&isLoggedIn, authManager, usernameLineEdit, passwordLineEdit);
                g_authWindow = authWindow;
                    authWindow->resize(400, 300);
                    
                    QObject::connect(authWindow, &AuthWindow::loginSuccessful, [&]() {
                        if (verbose) {
                            printf("Re-login successful! Creating chat window...\n");
                        }
                        networkManager = new NetworkManager(usernameLineEdit->text().toStdString(), SOCKET_HOST, SOCKET_PORT);
                        g_networkManager = networkManager;
                        encryption_decryption = new EncryptionDecryption(AUTH_HOST, AUTH_PORT);
                        g_encryptionDecryption = encryption_decryption;
                        
                        string publicKey = encryption_decryption->getMyPublicKey();
                        if (!publicKey.empty()) {
                            authManager->uploadPublicKey(usernameLineEdit->text().toStdString(), publicKey);
                        }
                        
                        messageHandler = new MessageHandler(networkManager, encryption_decryption);
                        g_messageHandler = messageHandler;
                        chatWindow = new ChatWindow(networkManager, messageHandler);
                        g_chatWindow = chatWindow;
                        chatWindow->setAuthManager(authManager);
                        chatWindow->resize(800, 600);
                        
                        authWindow->close();
                        
                        chatWindow->show();
                    });
                    
                    QObject::connect(authWindow, &QWidget::destroyed, [&]() {
                        if (verbose) {
                            printf("AuthWindow destroyed after logout. isLoggedIn: %d\n", isLoggedIn);
                        }
                        if(!isLoggedIn) {
                            if (verbose) {
                                printf("User not logged in after logout. Quitting application.\n");
                            }
                            a.quit();
                        }
                    });
                authWindow->show();
            });
        });
        
        QObject::connect(authWindow, &QWidget::destroyed, [&]() {
            if (verbose) {
                printf("AuthWindow destroyed. isLoggedIn: %d\n", isLoggedIn);
            }
            if(!isLoggedIn) {
                if (verbose) {
                    printf("User not logged in. Quitting application.\n");
                }
                a.quit();
            }
        });
        
        authWindow->show();
    }
    else {
        if (verbose) {
            printf("User already logged in. Creating chat window...\n");
        }
        networkManager = new NetworkManager(usernameLineEdit->text().toStdString(), SOCKET_HOST, SOCKET_PORT);
        g_networkManager = networkManager;
        encryption_decryption = new EncryptionDecryption(AUTH_HOST, AUTH_PORT);
        g_encryptionDecryption = encryption_decryption;
        
        string publicKey = encryption_decryption->getMyPublicKey();
        if (!publicKey.empty()) {
            authManager->uploadPublicKey(usernameLineEdit->text().toStdString(), publicKey);
        }
        
        messageHandler = new MessageHandler(networkManager, encryption_decryption);
        g_messageHandler = messageHandler;
        chatWindow = new ChatWindow(networkManager, messageHandler);
        g_chatWindow = chatWindow;
        chatWindow->setAuthManager(authManager);
        chatWindow->resize(800, 600);
        chatWindow->show();
        
        QObject::connect(chatWindow, &ChatWindow::logoutRequested, [&]() {
            if (verbose) {
                printf("Logout requested. Showing auth window...\n");
            }
            isLoggedIn = false;
            usernameLineEdit->clear();
            passwordLineEdit->clear();
            
            if (networkManager) {
                delete networkManager;
                networkManager = nullptr;
                g_networkManager = nullptr;
            }
            if (messageHandler) {
                delete messageHandler;
                messageHandler = nullptr;
                g_messageHandler = nullptr;
            }
            if (encryption_decryption) {
                delete encryption_decryption;
                encryption_decryption = nullptr;
                g_encryptionDecryption = nullptr;
            }
            
            if (chatWindow) {
                chatWindow->close();
                delete chatWindow;
                chatWindow = nullptr;
                g_chatWindow = nullptr;
            }
            
            authWindow = new AuthWindow(&isLoggedIn, authManager, usernameLineEdit, passwordLineEdit);
            g_authWindow = authWindow;
            authWindow->resize(400, 300);
            
            QObject::connect(authWindow, &AuthWindow::loginSuccessful, [&]() {
                if (verbose) {
                    printf("Re-login successful! Creating chat window...\n");
                }
                networkManager = new NetworkManager(usernameLineEdit->text().toStdString(), SOCKET_HOST, SOCKET_PORT);
                g_networkManager = networkManager;
                encryption_decryption = new EncryptionDecryption(AUTH_HOST, AUTH_PORT);
                g_encryptionDecryption = encryption_decryption;
                
                string publicKey = encryption_decryption->getMyPublicKey();
                if (!publicKey.empty()) {
                    authManager->uploadPublicKey(usernameLineEdit->text().toStdString(), publicKey);
                }
                
                messageHandler = new MessageHandler(networkManager, encryption_decryption);
                g_messageHandler = messageHandler;
                chatWindow = new ChatWindow(networkManager, messageHandler);
                g_chatWindow = chatWindow;
                chatWindow->setAuthManager(authManager);
                chatWindow->resize(800, 600);
                
                authWindow->close();
                
                chatWindow->show();
            });
            
            QObject::connect(authWindow, &QWidget::destroyed, [&]() {
                if (verbose) {
                    printf("AuthWindow destroyed. isLoggedIn: %d\n", isLoggedIn);
                }
                if(!isLoggedIn) {
                    if (verbose) {
                        printf("User not logged in. Quitting application.\n");
                    }
                    a.quit();
                }
            });
            
            authWindow->show();
        });
    }
    int result = a.exec();
    
    delete authManager;
    delete usernameLineEdit;
    delete passwordLineEdit;

    return result;
}
