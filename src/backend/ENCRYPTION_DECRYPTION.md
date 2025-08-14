# ENCRYPTION_DECRYPTION (Client)

**This documentation is for the functions of the EncryptionDecryption class in the client if ever needed to change in future**

- Handles end-to-end encryption for client messages
- Manages RSA key pair generation and storage
- Fetches and caches public keys from other users
- Provides secure message encryption and decryption

## Constructor
- **Takes auth server host and port parameters**
- **Initializes OpenSSL encryption components**
- **Loads or generates RSA key pair**
- **Sets up public key cache**

## Destructor
- **Cleans up OpenSSL key resources**
- **Frees EVP_PKEY structures**
- **Clears public key cache**

## Load My Keys
- **Private function to load user's RSA key pair from storage**
- **Reads private and public keys from PEM files**
- **Creates keys if they don't exist**
- **Returns true if keys loaded successfully**

## Fetch Public Key
- **Private function to retrieve public key from auth server**
- **Downloads public key for specified recipient**
- **Caches public key for future use**
- **Returns true if key fetched successfully**

## Save My Keys
- **Private function to save key pair to local storage**
- **Writes private and public keys to PEM files**
- **Ensures secure file permissions**
- **Handles file write errors**

## Generate Keys
- **Private function to generate new RSA key pair**
- **Creates 2048-bit RSA keys using OpenSSL**
- **Generates both private and public key components**
- **Saves generated keys to local storage**

## Upload Public Key
- **Private function to upload public key to auth server**
- **Sends public key to server for other users to access**
- **Returns true if upload successful**
- **Required for other users to encrypt messages**

## Needs Public Key Upload
- **Private function to check if public key upload is required**
- **Verifies if key is already on server**
- **Returns true if upload needed**

## Encrypt
- **Main encryption function for outgoing messages**
- **Takes message data and recipient username**
- **Fetches recipient's public key if not cached**
- **Encrypts message using RSA public key encryption**
- **Returns encrypted message as base64 string**
- **Handles encryption errors and missing keys**

## Decrypt
- **Main decryption function for incoming messages**
- **Takes encrypted message data**
- **Decrypts using user's private key**
- **Returns plain text message content**
- **Handles decryption errors and invalid data**

## Load User Public Key
- **Loads public key for specific user**
- **Fetches from server if not in cache**
- **Stores in cache for future use**
- **Returns true if key loaded successfully**

## Get My Public Key
- **Returns user's public key in PEM format**
- **Used for sharing with auth server**
- **Required for other users to encrypt messages**
