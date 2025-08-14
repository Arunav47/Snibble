# CHAT_WINDOW

**This documentation is for the functions of the ChatWindow class if ever needed to change in future**

- Main chat interface using Qt widgets
- Manages user interface for messaging and user lists
- Handles real-time message display and user interactions
- Integrates with NetworkManager, MessageHandler, and AuthManager

## Constructor
- **Takes NetworkManager and MessageHandler pointers as parameters**
- **Initializes Qt UI components (text areas, buttons, lists)**
- **Sets up menu bar with account and help menus**
- **Creates timers for periodic updates**
- **Establishes signal-slot connections for UI events**

## Destructor
- **Cleans up Qt UI resources**
- **Stops running timers**
- **Ensures proper widget cleanup**

## User List Update
- **Updates the user list display**
- **Refreshes online and contacted users**
- **Triggers UI refresh for user list widget**

## Message Screen Update
- **Refreshes the message display area**
- **Updates chat area with new messages**
- **Scrolls to latest messages**

## Set Auth Manager
- **Associates AuthManager with ChatWindow**
- **Enables authentication-related UI operations**
- **Required for logout and user management**

## Process Chat History Message
- **Processes incoming chat history from server**
- **Parses message format and displays in chat area**
- **Handles chronological ordering of messages**
- **Updates UI with historical conversation data**

## Update User List Slot
- **Qt slot for updating user list display**
- **Called by timer for periodic updates**
- **Refreshes both online and contacted user lists**
- **Handles user list changes and notifications**

## Search Users
- **Handles user search functionality**
- **Triggered by search button or text field changes**
- **Sends search query to AuthManager**
- **Updates user list with search results**
- **Implements delayed search to avoid excessive requests**

## Send Message
- **Handles message sending from input field**
- **Validates message content and recipient**
- **Calls MessageHandler to encrypt and send message**
- **Updates chat display with sent message**
- **Clears input field after sending**

## On User Selected
- **Handles user selection from user list**
- **Switches chat context to selected user**
- **Requests chat history for selected user**
- **Updates chat display title and content**

## Receive Messages
- **Processes incoming messages from network**
- **Updates chat display with new messages**
- **Handles message decryption and formatting**
- **Provides real-time message updates**

## Logout
- **Handles user logout process**
- **Calls AuthManager logout function**
- **Clears UI state and user data**
- **Emits logout signal to parent application**

## Show About
- **Displays application about dialog**
- **Shows version and developer information**
- **Handles help menu functionality**

## Close Event
- **Handles window close event**
- **Ensures proper cleanup before closing**
- **Saves application state**
- **Triggers logout process if needed**

## Populate Contacted Users
- **Private function to populate contacted users list**
- **Loads users from NetworkManager**
- **Updates UI list widget with contacted users**
- **Handles empty list and error cases**
