# MESSAGE_HANDLER (Client)

**This documentation is for the functions of the MessageHandler class in the client if ever needed to change in future**

- Handles message encryption, decryption, and transmission
- Manages message encoding for network transmission
- Coordinates with NetworkManager and EncryptionDecryption
- Provides secure messaging functionality

## Constructor
- **Takes NetworkManager and EncryptionDecryption pointers as parameters**
- **Initializes references to network and encryption components**
- **Sets up debug mode for troubleshooting**

## Destructor
- **Cleans up any resources**
- **Network and encryption managers handled separately**

## Base64 Encode
- **Private helper function for encoding binary data**
- **Converts binary data to base64 string**
- **Used for transmitting encrypted messages over network**
- **Handles encoding errors and edge cases**

## Base64 Decode
- **Private helper function for decoding base64 data**
- **Converts base64 string back to binary data**
- **Used for processing received encrypted messages**
- **Handles decoding errors and invalid input**

## Send Message
- **Main function for sending messages to other users**
- **Encrypts message content using recipient's public key**
- **Encodes encrypted message for network transmission**
- **Sends message through NetworkManager**
- **Handles encryption and transmission errors**
- **Formats message with sender and recipient information**

## Receive Message
- **Receives messages from network connection**
- **Reads message data from socket**
- **Returns raw message data for further processing**
- **Handles network errors and connection issues**
- **Manages message buffering and partial reads**

## Decrypt Message
- **Decrypts received messages using private key**
- **Takes encrypted message and sender information**
- **Decodes base64-encoded message data**
- **Decrypts using EncryptionDecryption class**
- **Returns plain text message content**
- **Handles decryption errors and invalid messages**
