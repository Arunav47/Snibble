# AUTH_WINDOW

**This documentation is for the functions of the AuthWindow class if ever needed to change in future**

- Provides login and signup interface using Qt widgets
- Manages authentication form validation and user input
- Switches between login and signup modes dynamically
- Integrates with AuthManager for authentication operations

## Constructor
- **Takes isLoggedIn flag, AuthManager pointer, and input field references**
- **Initializes Qt UI components for authentication**
- **Sets up form layouts for login/signup**
- **Establishes signal-slot connections for UI interactions**
- **Calls setupUI to create interface elements**

## Destructor
- **Cleans up Qt UI resources**
- **Releases any allocated memory for UI components**

## Setup UI
- **Private function to create and arrange UI elements**
- **Creates input fields for username, password, and confirmation**
- **Sets up primary and mode switching buttons**
- **Arranges layout with proper spacing and alignment**
- **Loads and displays application logo if available**

## Update UI For Mode
- **Private function to update UI based on current mode (login/signup)**
- **Shows/hides password confirmation field for signup**
- **Updates button text and labels**
- **Adjusts form validation requirements**

## On Primary Button Clicked
- **Handles primary button click (Login or Signup)**
- **Validates input fields based on current mode**
- **Calls appropriate AuthManager function (login/signup)**
- **Handles authentication responses and errors**
- **Shows success/failure messages to user**
- **Emits loginSuccessful signal on successful authentication**

## Switch To Signup Mode
- **Changes interface to signup mode**
- **Shows password confirmation field**
- **Updates button text to "Sign Up"**
- **Changes mode switch button to "Switch to Login"**
- **Updates form validation for signup requirements**

## Switch To Login Mode
- **Changes interface to login mode**
- **Hides password confirmation field**
- **Updates button text to "Login"**
- **Changes mode switch button to "Switch to Sign Up"**
- **Updates form validation for login requirements**
