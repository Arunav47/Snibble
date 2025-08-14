# AUTH_MANAGER (Client)

**This documentation is for the functions of the AuthManager class in the client if ever needed to change in future**

- Handles client-side authentication with auth server
- Manages JWT tokens and secure credential storage
- Provides user search and public key management
- Integrates with libsecret for secure storage

## Constructor
- **Takes verbose flag, host, and port parameters**
- **Initializes CURL for HTTP communication**
- **Sets up connection parameters for auth server**
- **Loads environment variables using dotenv**

## Destructor
- **Cleans up CURL resources**
- **Ensures proper cleanup of HTTP connections**

## Store Credentials Securely
- **Private helper function for secure credential storage**
- **Uses libsecret to store username and token**
- **Integrates with system keyring/credential manager**
- **Returns true if storage successful**

## Load Credentials From Storage
- **Private helper function to retrieve stored credentials**
- **Loads username and token from secure storage**
- **Verifies token validity before use**
- **Returns true if valid credentials found**

## Clear Stored Credentials
- **Private helper function to remove stored credentials**
- **Clears credentials from secure storage on logout**
- **Ensures complete credential cleanup**

## Write Callback
- **Static callback function for CURL response handling**
- **Processes HTTP response data**
- **Accumulates response data for processing**
- **Required for CURL HTTP operations**

## Login
- **Authenticates user with auth server**
- **Sends username and password via HTTP POST**
- **Receives and validates JWT token**
- **Stores credentials securely on successful login**
- **Returns true if login successful, false otherwise**

## Signup
- **Registers new user with auth server**
- **Sends username and password for account creation**
- **Handles registration validation and errors**
- **Returns true if signup successful, false otherwise**

## Logout
- **Logs out user and clears stored credentials**
- **Invalidates current session**
- **Clears tokens from secure storage**
- **Resets current user state**
- **Returns true if logout successful**

## Search Users
- **Searches for users by username pattern**
- **Sends search query to auth server**
- **Returns vector of matching usernames**
- **Handles search errors and empty results**

## Upload Public Key
- **Uploads user's public key to auth server**
- **Associates public key with username**
- **Required for end-to-end encryption**
- **Returns true if upload successful**

## Verify Token
- **Verifies JWT token validity**
- **Checks token expiration and signature**
- **Returns true if token is valid**
- **Used for session validation**

## Is Token Valid
- **Checks if current stored token is still valid**
- **Validates expiration time**
- **Returns true if token can be used for authentication**

## Get Current Token
- **Returns the current JWT token**
- **Used for authenticated requests**
- **Returns empty string if no valid token**

## Get Current Username
- **Returns the current authenticated username**
- **Used for identifying current user**
- **Returns empty string if not authenticated**

## Restore Session
- **Attempts to restore previous session from stored credentials**
- **Loads credentials from secure storage**
- **Validates token and restores user state**
- **Returns true if session successfully restored**
