#ifndef NETWORK_MANAGER_H
#define NETWORK_MANAGER_H

#include <string>
#include <vector>
#include <memory>
#include <sys/socket.h>
#include <iostream>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>
#include <set>
#include <cstring>
#include <hiredis/hiredis.h>
#include <pthread.h>
#include <fstream>
#include <sstream>

class ChatWindow;

class NetworkManager {
    friend class MessageHandler;
private:
    bool debugMode = false;
    std::string username;
    int socket_fd;
    struct sockaddr_in server_addr;
    std::string host;
    int port;
    redisContext* redis_context = nullptr;
    redisContext* subscriber_context = nullptr;
    pthread_t subscriber_thread;
    bool subscriber_running = false;
    ChatWindow* chatWindow = nullptr;
    
    void connectToRedis();
    void startRedisSubscriber();
    static void* redisSubscriberThread(void* arg);
    void processRedisMessage(const std::string& channel, const std::string& message);
    
public:
    std::set<std::string> connectedUsers;
    std::set<std::string> contactedUsers;
    NetworkManager(std::string username, std::string host, int port);
    ~NetworkManager();

    bool connectToServer();
    void disconnect();
    void forceDisconnect();
    void setChatWindow(ChatWindow* window);
    const std::set<std::string>& getConnectedUsers() const;
    const std::set<std::string>& getContactedUsers() const;
    const std::string& getUsername() const;
    void addContactedUser(const std::string& username);
    void loadContactedUsers();
    void saveContactedUsers();
    void requestContactedUsersFromServer();
    void requestChatHistoryFromServer(const std::string& otherUser);
    void processServerMessage(const std::string& message);

};

#endif