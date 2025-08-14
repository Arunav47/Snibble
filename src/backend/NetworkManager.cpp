#include "NetworkManager.h"
#include "../ui/ChatWindow.h"
#include <sstream>
#include <algorithm>
#include <cctype>
#include <sys/socket.h>
#include <pthread.h>
#include <time.h> 
using namespace std;


NetworkManager::NetworkManager(string username, string host, int port) : username(username), host(host), port(port) {
    connectToServer();
    connectToRedis();
    startRedisSubscriber();
    requestContactedUsersFromServer();
}

NetworkManager::~NetworkManager() {
    saveContactedUsers();
    subscriber_running = false;
    if (subscriber_thread) {
        pthread_join(subscriber_thread, nullptr);
    }
    if (subscriber_context) {
        redisFree(subscriber_context);
    }
    if (redis_context) {
        redisFree(redis_context);
    }
    disconnect();
}

bool NetworkManager::connectToServer() {
    socket_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (socket_fd < 0) {
        if (debugMode) {
            cerr << "[-] Error creating socket: " << strerror(errno) << endl;
        }
        return false;
    }
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    if (inet_pton(AF_INET, host.c_str(), &server_addr.sin_addr) <= 0) {
        if (debugMode) {
            cerr << "[-] Invalid address/Address not supported: " << host << endl;
        }
        close(socket_fd);
        return false;
    }
    if (connect(socket_fd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        if (debugMode) {
            cerr << "[-] Connection failed: " << strerror(errno) << endl;
        }
        close(socket_fd);
        return false;
    }
    send(socket_fd, username.c_str(), username.size(), 0);
    if (debugMode) {
        cout << "[+] Connected to server: " << host << ":" << port << " as user: " << username << endl;
    }
    return true;
}

void NetworkManager::disconnect() {
    if (socket_fd >= 0) {
        close(socket_fd);
        socket_fd = -1;
        if (debugMode) {
            cout << "[+] Disconnected from server." << endl;
        }
    } else {
        if (debugMode) {
            cout << "[-] No active connection to disconnect." << endl;
        }
    }
}

void NetworkManager::forceDisconnect() {
    if (debugMode) {
        cout << "[NetworkManager] Force disconnect called" << endl;
    }
    

    subscriber_running = false;
    

    if (socket_fd >= 0) {
        shutdown(socket_fd, SHUT_RDWR);
        close(socket_fd);
        socket_fd = -1;
        if (debugMode) {
            cout << "[+] Force disconnected from server." << endl;
        }
    }
    

    if (subscriber_context) {
        if (debugMode) {
            cout << "[NetworkManager] Freeing subscriber context..." << endl;
        }
        redisFree(subscriber_context);
        subscriber_context = nullptr;
    }
    
    if (redis_context) {
        if (debugMode) {
            cout << "[NetworkManager] Freeing redis context..." << endl;
        }
        redisFree(redis_context);
        redis_context = nullptr;
    }
    

    if (subscriber_thread) {
        if (debugMode) {
            cout << "[NetworkManager] Waiting for subscriber thread to finish..." << endl;
        }

        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        ts.tv_sec += 2; 
        
        void* thread_result;
        int join_result = pthread_join(subscriber_thread, &thread_result);
        
        if (join_result == 0) {
            if (debugMode) {
                cout << "[NetworkManager] Subscriber thread finished successfully" << endl;
            }
        } else {
            if (debugMode) {
                cout << "[!] Subscriber thread join failed: " << join_result << ", forcing cancellation" << endl;
            }
            pthread_cancel(subscriber_thread);
            pthread_detach(subscriber_thread);
        }
        subscriber_thread = 0;
    }

    if (debugMode) {
        cout << "[NetworkManager] Force disconnect completed" << endl;
    }
}

void NetworkManager::connectToRedis() {
    redis_context = redisConnect("127.0.0.1", 6379);
    if (redis_context == nullptr || redis_context->err) {
        if (redis_context) {
            if (debugMode) {
                cerr << "[-] Error connecting to Redis: " << redis_context->errstr << endl;
            }
            redisFree(redis_context);
            redis_context = nullptr;
        } else {
            if (debugMode) {
                cerr << "[-] Can't allocate redis context" << endl;
            }
        }
    } else {
        if (debugMode) {
            cout << "[+] Connected to Redis successfully." << endl;
        }
    }
}

void NetworkManager::startRedisSubscriber() {
    subscriber_context = redisConnect("127.0.0.1", 6379);
    if (subscriber_context == nullptr || subscriber_context->err) {
        if (subscriber_context) {
            if (debugMode) {
                cerr << "[-] Error connecting to Redis subscriber: " << subscriber_context->errstr << endl;
            }
            redisFree(subscriber_context);
            subscriber_context = nullptr;
        } else {
            if (debugMode) {
                cerr << "[-] Can't allocate redis subscriber context" << endl;
            }
        }
        return;
    }
    
    subscriber_running = true;
    if (pthread_create(&subscriber_thread, nullptr, redisSubscriberThread, this) != 0) {
        if (debugMode) {
            cerr << "[-] Error creating subscriber thread" << endl;
        }
        subscriber_running = false;
        redisFree(subscriber_context);
        subscriber_context = nullptr;
    } else {
        if (debugMode) {
            cout << "[+] Redis subscriber thread started" << endl;
        }
    }
}

void* NetworkManager::redisSubscriberThread(void* arg) {
    NetworkManager* nm = static_cast<NetworkManager*>(arg);
    
    redisReply* reply = (redisReply*)redisCommand(nm->subscriber_context, "PSUBSCRIBE *");
    if (reply) freeReplyObject(reply);
    
    while (nm->subscriber_running) {
        reply = nullptr;
        if (redisGetReply(nm->subscriber_context, (void**)&reply) == REDIS_OK && reply) {
            if (reply->type == REDIS_REPLY_ARRAY && reply->elements >= 3) {
                string msgType = reply->element[0]->str;
                if (msgType == "pmessage") {
                    string channel = reply->element[2]->str; 
                    string message = reply->element[3]->str; 
                    nm->processRedisMessage(channel, message);
                }
            }
            freeReplyObject(reply);
        } else {
            break;
        }
    }
    
    return nullptr;
}

void NetworkManager::processRedisMessage(const string& channel, const string& message) {
    if (message == "joined") {
        connectedUsers.insert(channel);
        if (debugMode) {
            cout << "[+] User " << channel << " joined" << endl;
        }
    } else if (message == "left") {
        connectedUsers.erase(channel);
        if (debugMode) {
            cout << "[+] User " << channel << " left" << endl;
        }
    }
    
    if (chatWindow) {
        chatWindow->userListUpdate();
    }
}

void NetworkManager::setChatWindow(ChatWindow* window) {
    chatWindow = window;
}

const set<string>& NetworkManager::getConnectedUsers() const {
    return connectedUsers;
}

const set<string>& NetworkManager::getContactedUsers() const {
    return contactedUsers;
}

const string& NetworkManager::getUsername() const {
    return username;
}

void NetworkManager::addContactedUser(const string& username) {
    if (username != this->username && !username.empty()) {
        contactedUsers.insert(username);

        if (debugMode) {
            cout << "[+] Added contacted user: " << username << endl;
        }

        if (chatWindow) {
            chatWindow->userListUpdate();
        }
    }
}

void NetworkManager::loadContactedUsers() {

    if (debugMode) {
        cout << "[+] Loading contacted users from server instead of file..." << endl;
    }
}

void NetworkManager::requestContactedUsersFromServer() {
    if (socket_fd >= 0) {
        string request = "GET_CONTACTS_FOR:" + username;
        send(socket_fd, request.c_str(), request.length(), 0);
        if (debugMode) {
            cout << "[+] Requesting contacted users from server for: " << username << endl;
        }
    } else {
        if (debugMode) {
            cout << "[-] Cannot request contacted users: not connected to server" << endl;
        }
    }
}

void NetworkManager::requestChatHistoryFromServer(const std::string& otherUser) {
    if (socket_fd >= 0) {
        string request = "GET_CHAT_HISTORY:" + username + ":" + otherUser;
        send(socket_fd, request.c_str(), request.length(), 0);
        if (debugMode) {
            cout << "[+] Requested chat history from server for: " << username << " with " << otherUser << endl;
        }
    } else {
        if (debugMode) {
            cout << "[-] Cannot request chat history: not connected to server" << endl;
        }
    }
}

void NetworkManager::processServerMessage(const string& message) {
    if (debugMode) {
        cout << "[NetworkManager::processServerMessage] Processing: " << message.substr(0, 50) << "..." << endl;
    }
    
    if (message.substr(0, 16) == "CONTACTED_USERS:") {
        string users_list = message.substr(16);
        contactedUsers.clear();
        
        if (!users_list.empty() && users_list != "\n") {
            stringstream ss(users_list);
            string user;
            while (getline(ss, user, ',')) {
                user.erase(remove_if(user.begin(), user.end(), ::isspace), user.end());
                if (!user.empty() && user != username) {
                    contactedUsers.insert(user);
                }
            }
        }
        if (debugMode) {
            cout << "[+] Loaded " << contactedUsers.size() << " contacted users from server" << endl;
        }
        

        if (chatWindow) {
            chatWindow->userListUpdate();
        }
    }
    else if (message.substr(0, 19) == "CHAT_HISTORY_START:" || 
             message.substr(0, 17) == "CHAT_HISTORY_MSG:" || 
             message.substr(0, 17) == "CHAT_HISTORY_END:" ||
             message.substr(0, 19) == "CHAT_HISTORY_ERROR:") {
        if (debugMode) {
            cout << "[NetworkManager] Received chat history message: " << message.substr(0, 50) << "..." << endl;
        }
        if (chatWindow) {
            if (debugMode) {
                cout << "[NetworkManager] Forwarding to ChatWindow" << endl;
            }
            chatWindow->processChatHistoryMessage(QString::fromStdString(message));
        } else {
            if (debugMode) {
                cout << "[NetworkManager] No ChatWindow set!" << endl;
            }
        }
    }
}

void NetworkManager::saveContactedUsers() {
    string filename = "/tmp/snibble_contacts_" + username + ".txt";
    ofstream file(filename);
    if (file.is_open()) {
        for (const auto& user : contactedUsers) {
            file << user << "\n";
        }
        file.close();
    } else {
        if (debugMode) {
            cerr << "[-] Failed to save contacted users to " << filename << endl;
        }
    }
}
