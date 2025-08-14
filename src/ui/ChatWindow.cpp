#include "ChatWindow.h"
#include "../backend/NetworkManager.h"
#include "../backend/MessageHandler.h"
#include "../backend/AuthManager.h"
#include <QApplication>
#include <QDebug>
#include <QFile>
#include <QTextStream>
#include <QDateTime>
#include <QScrollBar>
#include <QThread>
#include <QRegularExpression>
#include <cstdlib>
#include <signal.h>
#include <csignal>
#include <unistd.h>
#include <unordered_set>
using namespace std;


extern void cleanup();


ChatWindow::ChatWindow(NetworkManager* networkManager, MessageHandler* messageHandler, QWidget* parent)
    : QWidget(parent), networkManager(networkManager), messageHandler(messageHandler), authManager(nullptr),
      loadingChatHistory(false) {
    QVBoxLayout *outerLayout = new QVBoxLayout(this);
    
    menuBar = new QMenuBar(this);
    
    accountMenu = menuBar->addMenu("&Account");
    logoutAction = new QAction("&Logout", this);
    logoutAction->setShortcut(QKeySequence("Ctrl+L"));
    logoutAction->setStatusTip("Logout from the current session");
    accountMenu->addAction(logoutAction);
    
    helpMenu = menuBar->addMenu("&Help");
    aboutAction = new QAction("&About", this);
    aboutAction->setStatusTip("About Snibble Chat");
    helpMenu->addAction(aboutAction);
    
    outerLayout->setMenuBar(menuBar);
    
    QHBoxLayout *mainLayout = new QHBoxLayout();
    
    
    QVBoxLayout *userLayout = new QVBoxLayout();
    QHBoxLayout *searchUserLayout = new QHBoxLayout();
    QLabel *userLabel = new QLabel("Recent Contacts", this);
    searchButton = new QPushButton("Search", this);
    searchUserField = new QLineEdit(this);
    searchUserField->setPlaceholderText("Search users...");
    searchUserLayout->addWidget(searchUserField);
    searchUserLayout->addWidget(searchButton);
    userLayout->addLayout(searchUserLayout);
    userLayout->addWidget(userLabel);
    userList = new QListWidget(this);
    userLayout->addWidget(userList);
    userList->setMinimumWidth(200); 
    userList->setMaximumWidth(250);


    QWidget *userPanel = new QWidget(this);
    userPanel->setLayout(userLayout);
    userPanel->setFixedWidth(250);
    mainLayout->addWidget(userPanel);
    
    
    QVBoxLayout *chatLayout = new QVBoxLayout();
    titleLabel = new QLabel("Chat Room", this);
    messagesLayout = new QVBoxLayout();
    

    messagesLayout->setSpacing(3);
    messagesLayout->setAlignment(Qt::AlignTop);
    messagesLayout->setContentsMargins(5, 5, 5, 5);
    
    messagesScrollArea = new QScrollArea(this);
    messagesScrollArea->setWidgetResizable(true);
    QWidget *messagesWidget = new QWidget();
    messagesWidget->setLayout(messagesLayout);
    messagesScrollArea->setWidget(messagesWidget);
    inputField = new QLineEdit(this);
    inputField->setPlaceholderText("Select a user to start chatting...");
    inputField->setEnabled(false);
    sendButton = new QPushButton("Send", this);
    sendButton->setEnabled(false);
    inputLayout = new QHBoxLayout();
    inputLayout->addWidget(inputField);
    inputLayout->addWidget(sendButton);
    chatLayout->addWidget(titleLabel);
    chatLayout->addWidget(messagesScrollArea);
    chatLayout->addLayout(inputLayout);
    mainLayout->addLayout(chatLayout);
    
    outerLayout->addLayout(mainLayout);
    setLayout(outerLayout);
    
    if (networkManager) {
        networkManager->setChatWindow(this);
    }
    

    connect(searchButton, &QPushButton::clicked, this, &ChatWindow::searchUsers);

    connect(searchUserField, &QLineEdit::returnPressed, this, &ChatWindow::searchUsers);

    searchTimer = new QTimer(this);
    searchTimer->setSingleShot(true);
    searchTimer->setInterval(500);
    connect(searchTimer, &QTimer::timeout, this, &ChatWindow::searchUsers);
    connect(searchUserField, &QLineEdit::textChanged, [this]() {
        searchTimer->stop();
        QString query = searchUserField->text().trimmed();
        if (query.isEmpty()) {
            populateContactedUsers();
        } else if (query.length() >= 2) {
            searchTimer->start();
        }
    });
    
    connect(sendButton, &QPushButton::clicked, this, &ChatWindow::sendMessage);
    connect(inputField, &QLineEdit::returnPressed, this, &ChatWindow::sendMessage);
    connect(userList, &QListWidget::itemClicked, this, &ChatWindow::onUserSelected);
    
    connect(logoutAction, &QAction::triggered, this, &ChatWindow::logout);
    connect(aboutAction, &QAction::triggered, this, &ChatWindow::showAbout);
    

    updateTimer = new QTimer(this);
    connect(updateTimer, &QTimer::timeout, this, &ChatWindow::updateUserListSlot);
    updateTimer->start(5000);
    
    messageReceiveTimer = new QTimer(this);
    connect(messageReceiveTimer, &QTimer::timeout, this, &ChatWindow::receiveMessages);
    messageReceiveTimer->start(500);
    
    populateContactedUsers();
}

ChatWindow::~ChatWindow() {
    if(debugMode)
        cout << "[ChatWindow] Destructor called - performing cleanup..." << endl;
    
    if (updateTimer && updateTimer->thread() == QThread::currentThread()) {
        updateTimer->stop();
        updateTimer->deleteLater();
        updateTimer = nullptr;
    }
    
    if (messageReceiveTimer && messageReceiveTimer->thread() == QThread::currentThread()) {
        messageReceiveTimer->stop();
        messageReceiveTimer->deleteLater();
        messageReceiveTimer = nullptr;
    }
    
    if (searchTimer && searchTimer->thread() == QThread::currentThread()) {
        searchTimer->stop();
        searchTimer->deleteLater();
        searchTimer = nullptr;
    }

    if (networkManager) {
        networkManager->setChatWindow(nullptr);
        networkManager->forceDisconnect();
        if (debugMode)
            cout << "[ChatWindow] Destructor: Network forcefully disconnected" << endl;
    }

    currentChatUser.clear();
    currentHistoryUser.clear();
    loadingChatHistory = false;
    if (debugMode)
        cout << "[ChatWindow] Destructor: Cleaned up timers and connections" << endl;

}

void ChatWindow::closeEvent(QCloseEvent *event) {
    static bool cleanupInProgress = false;
    
    if (cleanupInProgress) {
        if(debugMode){
            cout << "[ChatWindow] Cleanup already in progress, ignoring..." << endl;
        }
        event->accept();
        return;
    }
    
    cleanupInProgress = true;
    if(debugMode) {
        cout << "[ChatWindow] Close event triggered - cleaning up..." << endl;
    }

    if (updateTimer && updateTimer->thread() == QThread::currentThread()) {
        updateTimer->stop();
        updateTimer->deleteLater();
        updateTimer = nullptr;
    }
    
    if (messageReceiveTimer && messageReceiveTimer->thread() == QThread::currentThread()) {
        messageReceiveTimer->stop();
        messageReceiveTimer->deleteLater();
        messageReceiveTimer = nullptr;
    }
    
    if (searchTimer && searchTimer->thread() == QThread::currentThread()) {
        searchTimer->stop();
        searchTimer->deleteLater();
        searchTimer = nullptr;
    }

    currentChatUser.clear();
    currentHistoryUser.clear();
    loadingChatHistory = false;
    if (networkManager) {
        networkManager->setChatWindow(nullptr);
        networkManager->forceDisconnect();
        if (debugMode) {
            cout << "[ChatWindow] Network forcefully disconnected" << endl;
        }
    }

    QApplication::processEvents();
    
    if (debugMode) {
        cout << "[ChatWindow] Close event: All cleanup completed" << endl;
    }

    event->accept();

    if (debugMode) {
        cout << "[ChatWindow] Calling global cleanup..." << endl;
    }
    cleanup();

    if (debugMode) {
        cout << "[ChatWindow] Terminating application immediately..." << endl;
    }
    _exit(0);  
}

void ChatWindow::userListUpdate() {
    QTimer::singleShot(0, this, &ChatWindow::updateUserListSlot);
}

void ChatWindow::updateUserListSlot() {
    populateContactedUsers();
}

void ChatWindow::setAuthManager(AuthManager* authManager) {
    this->authManager = authManager;
}

void ChatWindow::populateContactedUsers() {
    if (!networkManager) return;
    
    userList->clear();
    
    const auto& contactedUsers = networkManager->getContactedUsers();
    const auto& onlineUsers = networkManager->getConnectedUsers();
    

    for (const auto& user : contactedUsers) {
        bool isOnline = onlineUsers.find(user) != onlineUsers.end();
        addUserToList(QString::fromStdString(user), isOnline);
    }
    

    QLabel* userLabel = nullptr;
    for (int i = 0; i < layout()->count(); ++i) {
        QLayoutItem* item = layout()->itemAt(i);
        if (item && item->layout()) {
            QVBoxLayout* userLayout = qobject_cast<QVBoxLayout*>(item->layout());
            if (userLayout) {
                for (int j = 0; j < userLayout->count(); ++j) {
                    QLayoutItem* subItem = userLayout->itemAt(j);
                    if (subItem && subItem->widget()) {
                        QLabel* label = qobject_cast<QLabel*>(subItem->widget());
                        if (label && label->text().contains("Contacts")) {
                            label->setText(QString("Recent Contacts (%1)").arg(contactedUsers.size()));
                            break;
                        }
                    }
                }
                break;
            }
        }
    }
}

void ChatWindow::addUserToList(const QString& username, bool isOnline) {
    QString displayText = username;
    if (isOnline) {
        displayText += " ●";
    }
    
    QListWidgetItem* item = new QListWidgetItem(displayText);

    if (isOnline) {
        item->setForeground(QColor(0, 150, 0));
    } else {
        item->setForeground(QColor(100, 100, 100));
    }
    
    userList->addItem(item);
}

void ChatWindow::searchUsers() {
    if (!authManager) {
        if (debugMode) {
            cout << "[ChatWindow] AuthManager not set, cannot search users" << endl;
        }
        qDebug() << "AuthManager not set, cannot search users";
        return;
    }
    
    QString query = searchUserField->text().trimmed();
    if (query.length() < 2) {
        populateContactedUsers();
        return;
    }
    
    std::vector<std::string> searchResults = authManager->searchUsers(query.toStdString());
    
    userList->clear();
    
    if (searchResults.empty()) {
        QListWidgetItem* item = new QListWidgetItem("No users found");
        item->setForeground(QColor(150, 150, 150));
        item->setFlags(item->flags() & ~Qt::ItemIsSelectable);
        userList->addItem(item);
    } else {
        const auto& onlineUsers = networkManager->getConnectedUsers();
        
        for (const auto& user : searchResults) {
            bool isOnline = onlineUsers.find(user) != onlineUsers.end();
            addUserToList(QString::fromStdString(user), isOnline);
        }
    }
    
    for (int i = 0; i < layout()->count(); ++i) {
        QLayoutItem* item = layout()->itemAt(i);
        if (item && item->layout()) {
            QVBoxLayout* userLayout = qobject_cast<QVBoxLayout*>(item->layout());
            if (userLayout) {
                for (int j = 0; j < userLayout->count(); ++j) {
                    QLayoutItem* subItem = userLayout->itemAt(j);
                    if (subItem && subItem->widget()) {
                        QLabel* label = qobject_cast<QLabel*>(subItem->widget());
                        if (label && (label->text().contains("Contacts") || label->text().contains("Search"))) {
                            label->setText(QString("Search Results (%1)").arg(searchResults.size()));
                            break;
                        }
                    }
                }
                break;
            }
        }
    }
}

void ChatWindow::sendMessage() {
    if (!messageHandler || currentChatUser.isEmpty()) {
        if (debugMode) {
            cout << "[ChatWindow] Cannot send message: no recipient selected or MessageHandler not available" << endl;
        }
        qDebug() << "Cannot send message: no recipient selected or MessageHandler not available";
        return;
    }
    
    QString message = inputField->text().trimmed();
    if (message.isEmpty()) {
        return;
    }
    
    messageHandler->sendMessage(message.toStdString(), currentChatUser.toStdString());
    
    addMessageToChat("You", message, true);
    
    saveChatHistory(currentChatUser, message, true);
    
    inputField->clear();
}

void ChatWindow::onUserSelected() {
    QListWidgetItem* selectedItem = userList->currentItem();
    if (!selectedItem) return;
    
    QString selectedUser = selectedItem->text();
    if (selectedUser.endsWith(" ●")) {
        selectedUser = selectedUser.left(selectedUser.length() - 2);
    }
    
    if (debugMode) {
        cout << "[+] User selected: " << selectedUser.toStdString() << endl;
        cout << "[+] Current chat user: " << currentChatUser.toStdString() << endl;
    }

    if (selectedUser == currentChatUser) {
        if (debugMode) {
            cout << "[+] User already selected, skipping" << endl;
        }
        return;
    }
    
    currentChatUser = selectedUser;
    titleLabel->setText("Chat with " + selectedUser);
    if (debugMode) {
        cout << "[+] Loading chat history for: " << selectedUser.toStdString() << endl;
    }
    
    fetchUserPublicKey(selectedUser);
    
    loadChatHistory(selectedUser);
    
    inputField->setEnabled(true);
    sendButton->setEnabled(true);
    inputField->setPlaceholderText("Type a message to " + selectedUser + "...");
}

void ChatWindow::receiveMessages() {
    if (!messageHandler) return;
    
    std::string receivedMessage = messageHandler->receiveMessage();
    if (!receivedMessage.empty()) {
        size_t colonPos = receivedMessage.find(": ");
        if (colonPos != std::string::npos) {
            std::string sender = receivedMessage.substr(0, colonPos);
            std::string content = receivedMessage.substr(colonPos + 2);
            
            QString qSender = QString::fromStdString(sender);
            QString qContent = QString::fromStdString(content);
            
            if (qSender == currentChatUser) {
                addMessageToChat(qSender, qContent, false);
                saveChatHistory(qSender, qContent, false);
            } else {
                saveChatHistory(qSender, qContent, false);
            }
        }
    }
}

void ChatWindow::loadChatHistory(const QString& username) {
    if (username.isEmpty() || !networkManager) {
        if (debugMode) {
            cout << "[-] Cannot load chat history - username empty or no network manager" << endl;
        }
        return;
    }
    
    if (debugMode) {
        cout << "[+] Loading chat history for: " << username.toStdString() << endl;
        cout << "[+] Current username: " << networkManager->getUsername() << endl;
    }
    
    QLayoutItem* child;
    while ((child = messagesLayout->takeAt(0)) != nullptr) {
        delete child->widget();
        delete child;
    }
    
    currentHistoryUser = username;
    loadingChatHistory = true;
    
    networkManager->requestChatHistoryFromServer(username.toStdString());
    
    if (debugMode) {
        cout << "[+] Requested chat history for conversation with: " << username.toStdString() << endl;
    }
    
}

void ChatWindow::saveChatHistory(const QString& username, const QString& message, bool isOutgoing) {
    if (username.isEmpty() || message.isEmpty()) return;
    
    QString filename = QString("/tmp/snibble_chat_%1_%2.txt")
                       .arg(QString::fromStdString(networkManager->getUsername()))
                       .arg(username);
    
    QFile file(filename);
    if (file.open(QIODevice::WriteOnly | QIODevice::Append | QIODevice::Text)) {
        QTextStream out(&file);
        QString timestamp = QDateTime::currentDateTime().toString("yyyy-MM-dd hh:mm:ss");
        QString sender = isOutgoing ? "You" : username;
        out << timestamp << "|" << sender << "|" << message << "\n";
        file.close();
    }
}

void ChatWindow::addMessageToChat(const QString& sender, const QString& message, bool isOutgoing) {
    if (debugMode) {
        cout << "[+] Adding message to chat - Sender: " << sender.toStdString() << ", Message: " << message.left(50).toStdString() << "..., Outgoing: " << isOutgoing << endl;
    }
    
    QWidget* messageWidget = new QWidget();
    QHBoxLayout* messageLayout = new QHBoxLayout(messageWidget);
    
    messageWidget->setSizePolicy(QSizePolicy::Preferred, QSizePolicy::Minimum);
    messageLayout->setContentsMargins(5, 2, 5, 2);
    
    QLabel* messageLabel = new QLabel();
    QString displayText = QString("<b>%1:</b> %2").arg(sender, message);
    messageLabel->setText(displayText);
    messageLabel->setWordWrap(true);
    messageLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
    
    messageLabel->setSizePolicy(QSizePolicy::Preferred, QSizePolicy::Minimum);
    messageLabel->setMinimumHeight(30); 
    messageLabel->setMaximumWidth(400);
    
    if (isOutgoing) {
        messageLabel->setStyleSheet("QLabel { background-color: #e3f2fd; padding: 8px; border-radius: 8px; margin: 2px; color: black; }");
        messageLayout->addStretch();
        messageLayout->addWidget(messageLabel);
    } else {
        messageLabel->setStyleSheet("QLabel { background-color: #f5f5f5; padding: 8px; border-radius: 8px; margin: 2px; color: black; }");
        messageLayout->addWidget(messageLabel);
        messageLayout->addStretch();
    }
    
    messageWidget->setLayout(messageLayout);
    messagesLayout->addWidget(messageWidget);
    
    scrollToBottom();
}

void ChatWindow::scrollToBottom() {
    QTimer::singleShot(50, [this]() {
        messagesScrollArea->verticalScrollBar()->setValue(
            messagesScrollArea->verticalScrollBar()->maximum()
        );
    });
}

void ChatWindow::logout() {
    QMessageBox::StandardButton reply = QMessageBox::question(
        this,
        "Logout Confirmation",
        "Are you sure you want to logout?",
        QMessageBox::Yes | QMessageBox::No,
        QMessageBox::No
    );
    
    if (reply == QMessageBox::Yes) {
        currentChatUser.clear();
        titleLabel->setText("Chat Room");
        inputField->setEnabled(false);
        sendButton->setEnabled(false);
        inputField->setPlaceholderText("Please login to start chatting...");
        
        QLayoutItem* child;
        while ((child = messagesLayout->takeAt(0)) != nullptr) {
            delete child->widget();
            delete child;
        }
        
        userList->clear();
        
        if (authManager && networkManager) {
            std::string username = networkManager->getUsername();
            if (!username.empty()) {
                // Use quick logout to prevent UI blocking
                authManager->logoutQuick(username);
            }
        }
        
        emit logoutRequested();
        
        this->close();
    }
}

void ChatWindow::showAbout() {
    QMessageBox::about(
        this,
        "About Snibble Chat",
        "<h3>Snibble Chat v2.0.0</h3>"
        "<p>A real-time chat application built with Qt6 and C++</p>"
        "<p><b>Features:</b></p>"
        "<ul>"
        "<li>Real-time messaging</li>"
        "<li>User presence tracking</li>"
        "<li>Message persistence</li>"
        "<li>User search functionality</li>"
        "<li>Secure authentication</li>"
        "</ul>"
        "<p><b>Architecture:</b></p>"
        "<ul>"
        "<li>PostgreSQL for message storage</li>"
        "<li>Redis for user presence</li>"
        "<li>JWT token authentication</li>"
        "<li>TCP socket communication</li>"
        "</ul>"
        "<p>© 2025 Snibble Team</p>"
    );
}

void ChatWindow::processChatHistoryMessage(const QString& message) {
    if (debugMode) {
        cout << "[ChatWindow] Processing chat history message: " << message.toStdString() << endl;
    }
    
    if (message.startsWith("CHAT_HISTORY_START:")) {
        QStringList parts = message.split(":");
        if (parts.size() >= 3) {
            QString otherUser = parts[2].trimmed();
            currentHistoryUser = otherUser;
            loadingChatHistory = true;
            if (debugMode) {
                cout << "[+] Starting to load chat history for: " << otherUser.toStdString() << endl;
            }
            
            addMessageToChat("System", "Loading chat history...", false);
        }
    }
    else if (message.startsWith("CHAT_HISTORY_MSG:")) {
        if (debugMode) {
            cout << "[ChatWindow] ===== PROCESSING CHAT_HISTORY_MSG =====" << endl;
            cout << "[ChatWindow] Full message: " << message.toStdString() << endl;
        }
        
        if (currentHistoryUser.isEmpty()) {
            if (debugMode) {
                cout << "[-] Received chat history message but no current history user set" << endl;
            }
            return;
        }
        if (debugMode) {
            cout << "[+] Current history user: " << currentHistoryUser.toStdString() << endl;
            cout << "[+] Current network username: " << networkManager->getUsername() << endl;
        }

        QStringList parts = message.split(":", Qt::KeepEmptyParts);
        if (debugMode) {
            cout << "[+] Split message into " << parts.size() << " parts" << endl;
        }
        
        if (parts.size() >= 6) {
            QString sender = parts[1];
            QString recipient = parts[2]; 
            
            QString delivered = parts[parts.size() - 1];
            QString timestamp = parts[parts.size() - 2];
            
            QStringList messageParts;
            for (int i = 3; i < parts.size() - 2; i++) {
                messageParts.append(parts[i]);
            }
            QString messageContent = messageParts.join(":");
            if (debugMode) {
                cout << "[+] Reconstructed message content: " << messageContent.left(100).toStdString() << "..." << endl;
                
                cout << "[+] Parsed message parts:" << endl;
                cout << "    Sender: " << sender.toStdString() << endl;
                cout << "    Recipient: " << recipient.toStdString() << endl;
                cout << "    Content: " << messageContent.toStdString() << endl;
                cout << "    Timestamp: " << timestamp.toStdString() << endl;
                cout << "    Delivered: " << delivered.toStdString() << endl;
                
                cout << "[+] Processing message from " << sender.toStdString() 
                     << " to " << recipient.toStdString() 
                     << ": " << messageContent.left(30).toStdString() << "..." << endl;
            }
            
            bool senderMatch = (sender == currentHistoryUser || sender == QString::fromStdString(networkManager->getUsername()));
            bool recipientMatch = (recipient == currentHistoryUser || recipient == QString::fromStdString(networkManager->getUsername()));
            if (debugMode) {
                cout << "[+] Conversation check:" << endl;
                cout << "    Sender match: " << senderMatch << endl;
                cout << "    Recipient match: " << recipientMatch << endl;
                cout << "    Both should be true for message to display" << endl;
            }
            
            if (senderMatch && recipientMatch) {
                
                bool isOutgoing = (sender == QString::fromStdString(networkManager->getUsername()));
                QString displaySender = isOutgoing ? "You" : sender;
                if (debugMode) {
                    cout << "[+] Message is outgoing: " << isOutgoing << endl;
                    cout << "[+] Display sender: " << displaySender.toStdString() << endl;
                }
                
                QString displayMessage = messageContent;
                if (debugMode) {
                    cout << "[DEBUG] Original message content: '" << messageContent.toStdString() << "'" << endl;
                    cout << "[DEBUG] Message length: " << messageContent.length() << endl;
                }
                
                if (messageContent == "ENCRYPTED") {
                    if (debugMode) {
                        cout << "[DEBUG] Message is literally 'ENCRYPTED' - this is likely a placeholder" << endl;
                    }
                    displayMessage = "[Message cannot be decrypted - stored as placeholder]";
                }

                else if (messageContent.startsWith("ENCRYPTED:")) {

                    QString encryptedPart = messageContent.mid(10);
                    QRegularExpression timestampRegex(":20\\d{2}-\\d{2}-\\d{2} \\d{2}:\\d{2}$");
                    QRegularExpressionMatch match = timestampRegex.match(encryptedPart);
                    
                    if (match.hasMatch()) {
                        QString fullTimestamp = match.captured(0);
                        if (debugMode) {
                            cout << "[DEBUG] Found timestamp pattern: '" << fullTimestamp.toStdString() << "'" << endl;
                        }

                        encryptedPart = encryptedPart.left(encryptedPart.length() - fullTimestamp.length());
                        if (debugMode) {
                            cout << "[DEBUG] Cleaned encrypted part: '" << encryptedPart.toStdString() << "'" << endl;
                        }

                    } else {
                        if (debugMode) {
                            cout << "[DEBUG] No timestamp pattern found at end" << endl;
                        }
                    }
                    
                    if (messageHandler) {
                        if (debugMode) {
                            cout << "[DEBUG] About to decrypt with:" << endl;
                            cout << "[DEBUG] - Encrypted part: '" << encryptedPart.toStdString() << "'" << endl;
                            cout << "[DEBUG] - Encrypted part length: " << encryptedPart.length() << endl;
                            cout << "[DEBUG] - Sender: '" << sender.toStdString() << "'" << endl;
                        }
                        
                        std::string decryptedMsg = messageHandler->decryptMessage(
                            encryptedPart.toStdString(), 
                            sender.toStdString()
                        );
                        if (debugMode) {
                            cout << "[DEBUG] Decrypting message for sender: " << sender.toStdString() << endl;
                        }
                        
                        if (!decryptedMsg.empty() && 
                            decryptedMsg != "Failed to decrypt message" && 
                            decryptedMsg != "Error decrypting message") {
                            displayMessage = QString::fromStdString(decryptedMsg);
                            if (debugMode) {
                                cout << "[DEBUG] Successfully decrypted message: " << displayMessage.left(50).toStdString() << "..." << endl;
                            }
                        } else {
                            if (debugMode) {
                                cout << "[DEBUG] Decryption failed: " << decryptedMsg << endl;
                            }
                            displayMessage = "[Failed to decrypt message]";
                        }
                    }
                } else {

                    if (messageHandler && messageContent.length() > 50) {
                        bool looksLikeBase64 = true;
                        for (QChar c : messageContent) {
                            if (!c.isLetterOrNumber() && c != '+' && c != '/' && c != '=') {
                                looksLikeBase64 = false;
                                break;
                            }
                        }
                        
                        if (looksLikeBase64) {
                            std::string decryptedMsg = messageHandler->decryptMessage(
                                messageContent.toStdString(), 
                                sender.toStdString()
                            );
                            if (!decryptedMsg.empty() && 
                                decryptedMsg != "Failed to decrypt message" && 
                                decryptedMsg != "Error decrypting message") {
                                displayMessage = QString::fromStdString(decryptedMsg);
                            }
                        }
                    }
                }
                
                if (delivered == "false") {
                    displayMessage = "[OFFLINE] " + displayMessage;
                    if (debugMode) {
                        cout << "[DEBUG] Message marked as offline" << endl;
                    }
                }
                
                if (debugMode) {
                    cout << "[DEBUG] Final display message: " << displayMessage.toStdString() << endl;
                    cout << "[DEBUG] About to call addMessageToChat..." << endl;
                }
                
                addMessageToChat(displaySender, displayMessage, isOutgoing);
                if (debugMode) {
                    cout << "[+] Successfully added message to chat" << endl;
                }
            } else {
                if (debugMode) {
                    cout << "[-] Message NOT for current conversation:" << endl;
                    cout << "    Sender: " << sender.toStdString() << endl;
                    cout << "    Recipient: " << recipient.toStdString() << endl;
                    cout << "    Current history user: " << currentHistoryUser.toStdString() << endl;
                    cout << "    Network username: " << networkManager->getUsername() << endl;
                    cout << "    Sender match (should be true): " << senderMatch << endl;
                    cout << "    Recipient match (should be true): " << recipientMatch << endl;
                }
            }
        } else {
            if (debugMode) {
                cout << "[-] Invalid chat history message format: " << message.toStdString() << endl;
            }
        }
    }
    else if (message.startsWith("CHAT_HISTORY_END:")) {
        QStringList parts = message.split(":");
        if (parts.size() >= 3) {
            QString otherUser = parts[2].trimmed();
            if (debugMode) {
                cout << "[+] Received CHAT_HISTORY_END for: " << otherUser.toStdString() << endl;
                cout << "[+] Current history user: " << currentHistoryUser.toStdString() << endl;
            }
            
            if (otherUser == currentHistoryUser || currentHistoryUser.isEmpty()) {
                loadingChatHistory = false;
                currentHistoryUser.clear();
                
                if (messagesLayout->count() > 0) {
                    QLayoutItem* firstItem = messagesLayout->itemAt(0);
                    if (firstItem && firstItem->widget()) {
                        QWidget* widget = firstItem->widget();
                        QLabel* label = widget->findChild<QLabel*>();
                        if (label && label->text().contains("Loading chat history...")) {
                            messagesLayout->removeWidget(widget);
                            delete widget;
                        }
                    }
                }
                
                scrollToBottom();
                if (debugMode) {
                    cout << "[+] Finished loading chat history for: " << otherUser.toStdString() << endl;
                }
                
                if (messagesLayout->count() == 0) {
                    addMessageToChat("System", "No previous messages found.", false);
                }
            }
        }
    }
    else if (message.startsWith("CHAT_HISTORY_ERROR:")) {
        QString errorMsg = message.mid(19);
        if (debugMode) {
            cout << "[ChatWindow] Error loading chat history: " << errorMsg.toStdString() << endl;
        }
        loadingChatHistory = false;
        currentHistoryUser.clear();
        
        addMessageToChat("System", "Error loading chat history: " + errorMsg, false);
    }
    else {
        if (debugMode) {
            cout << "[ChatWindow] Unknown chat history message type: " << message.left(100).toStdString() << endl;
        }
    }
}

void ChatWindow::fetchUserPublicKey(const QString& username) {
    if (debugMode) {
        cout << "[+] Fetching public key for user: " << username.toStdString() << endl;
    }
    
    if (!messageHandler) {
        if (debugMode) {
            cout << "[-] MessageHandler not available for encryption" << endl;
        }
        return;
    }
    

    QTimer::singleShot(0, [this, username]() {
        if (messageHandler && networkManager) {
            if (debugMode) {
                cout << "[+] Ready to fetch public key for: " << username.toStdString() << " when needed" << endl;
            }
        }
    });
}