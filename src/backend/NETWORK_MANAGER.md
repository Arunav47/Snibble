# NETWORK_MANAGER (Client)

**This documentation is for the functions of the NetworkManager class in the client if ever needed to change in future**

- Handles client-side network connectivity to chat server
- Manages Redis integration for real-time messaging
- Maintains user connection state and user lists
- Coordinates with ChatWindow for UI updates

## Constructor
- **Takes username, host, and port parameters**
- **Initializes socket connection parameters**
- **Sets up Redis connection variables**
- **Initializes user lists and connection state**

## Destructor
- **Cleans up socket connections**
- **Disconnects from Redis**
- **Stops subscriber threads**
- **Saves contacted users to persistent storage**

## Connect To Server
- **Establishes TCP connection to chat server**
- **Sends authentication information**
- **Handles connection errors and retries**
- **Returns true if connection successful**

## Disconnect
- **Gracefully disconnects from chat server**
- **Stops Redis subscriber thread**
- **Closes socket connections**
- **Saves current state before disconnection**

## Force Disconnect
- **Performs immediate disconnection without graceful shutdown**
- **Used for emergency disconnection scenarios**
- **Cleans up all network resources**

## Connect To Redis
- **Establishes connection to Redis server for real-time messaging**
- **Creates both publisher and subscriber contexts**
- **Handles Redis connection errors**
- **Sets up Redis authentication if required**

## Start Redis Subscriber
- **Starts background thread for Redis message subscription**
- **Subscribes to user-specific message channels**
- **Processes incoming real-time messages**
- **Maintains continuous connection to Redis**

## Redis Subscriber Thread
- **Static thread function for Redis message processing**
- **Runs in background to listen for incoming messages**
- **Parses Redis messages and forwards to UI**
- **Handles Redis connection errors and reconnection**

## Process Redis Message
- **Processes incoming messages from Redis**
- **Parses message format and extracts content**
- **Updates UI with new messages**
- **Triggers message notifications**

## Set Chat Window
- **Associates ChatWindow with NetworkManager**
- **Enables UI updates for incoming messages**
- **Sets up callback for message notifications**

## Get Connected Users
- **Returns set of currently online users**
- **Updates from server status messages**
- **Used by UI to show online user list**

## Get Contacted Users
- **Returns set of users that have been communicated with**
- **Persists across application sessions**
- **Loaded from server and local storage**

## Add Contacted User
- **Adds user to contacted users list**
- **Persists addition to local storage**
- **Updates UI user list**

## Load Contacted Users
- **Loads contacted users from local file storage**
- **Restores user list between application sessions**
- **Handles file reading errors gracefully**

## Save Contacted Users
- **Saves contacted users to local file storage**
- **Ensures persistence between application sessions**
- **Handles file writing errors**

## Request Contacted Users From Server
- **Requests updated contacted users list from server**
- **Synchronizes local list with server records**
- **Updates UI with server response**

## Request Chat History From Server
- **Requests message history for specific user**
- **Sends request to server with user identifier**
- **Coordinates with UI for history display**

## Process Server Message
- **Processes various types of messages from server**
- **Handles user list updates, chat history, and status changes**
- **Routes messages to appropriate handlers**
- **Updates UI based on message type**
