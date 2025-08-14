#ifndef CHAT_WINDOW_H
#define CHAT_WINDOW_H

#include <QWidget>
#include <QTextEdit>
#include <QPushButton>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QListWidget>
#include <QScrollArea>
#include <QTimer>
#include <QObject>
#include <QMenuBar>
#include <QMenu>
#include <QAction>
#include <QMessageBox>
#include <QCloseEvent>

class NetworkManager; 
class MessageHandler;
class AuthManager;

class ChatWindow : public QWidget {
    Q_OBJECT

public:
    ChatWindow(NetworkManager *networkManager, MessageHandler *messageHandler, QWidget *parent = nullptr);
    ~ChatWindow();
    void userListUpdate();
    void messageScreenUpdate();
    void setAuthManager(AuthManager* authManager);
    void processChatHistoryMessage(const QString& message);

private Q_SLOTS:
    void updateUserListSlot();
    void searchUsers();
    void sendMessage();
    void onUserSelected();
    void receiveMessages();
    void logout();
    void showAbout();

Q_SIGNALS:
    void logoutRequested();

protected:
    void closeEvent(QCloseEvent *event) override;

private:
    bool debugMode = false;
    QMenuBar *menuBar;
    QMenu *accountMenu;
    QMenu *helpMenu;
    QAction *logoutAction;
    QAction *aboutAction;
    QTextEdit *chatArea;
    QLineEdit *inputField;
    QLineEdit *searchUserField;
    QPushButton *searchButton;
    QVBoxLayout *messagesLayout;
    QScrollArea *messagesScrollArea;
    QPushButton *sendButton;
    QVBoxLayout *mainLayout;
    QHBoxLayout *inputLayout;
    QLabel *titleLabel;
    QListWidget *userList;
    QScrollArea *scrollArea;
    NetworkManager *networkManager;
    MessageHandler *messageHandler;
    AuthManager *authManager;
    QTimer *updateTimer;
    QTimer *messageReceiveTimer;
    QTimer *searchTimer;
    QString currentChatUser;
    QString currentHistoryUser; 
    bool loadingChatHistory; 
    
    void populateContactedUsers();
    void addUserToList(const QString& username, bool isOnline = false);
    void loadChatHistory(const QString& username);
    void saveChatHistory(const QString& username, const QString& message, bool isOutgoing);
    void addMessageToChat(const QString& sender, const QString& message, bool isOutgoing);
    void scrollToBottom();
    void fetchUserPublicKey(const QString& username);
};


#endif