#include <QApplication>
#include "AuthWindow.h"
#include "../src/backend/AuthManager.h"
using namespace std;

QHBoxLayout *usernameLayout;
QHBoxLayout *passwordLayout;
QHBoxLayout *confirmPasswordLayout;
QHBoxLayout *buttonLayout;
QLabel *logoLabel;
QLabel *confirmPasswordLabel;
QLabel *usernameLabel;
QLabel *passwordLabel;

AuthWindow::AuthWindow(bool *isLoggedIn, AuthManager* authManager, QLineEdit *usernameLineEdit, QLineEdit *passwordLineEdit, QWidget *parent) : QWidget(parent){
    this->authManager = authManager;
    this->usernameLineEdit = usernameLineEdit;
    this->passwordLineEdit = passwordLineEdit;
    this->confirmPasswordLineEdit = new QLineEdit(this);
    this->confirmPasswordLineEdit->setEchoMode(QLineEdit::Password);
    this->confirmPasswordLineEdit->setPlaceholderText("Confirm Password");
    this->isLoggedIn = isLoggedIn;
    
    currentMode = LOGIN;
    
    setupUI();
    updateUIForMode();
}

void AuthWindow::setupUI() {
    layout = new QVBoxLayout(this);
    layout->setAlignment(Qt::AlignHCenter);
    
    // Logo section
    QString logoPath = "../src/assets/images/Snibble_logo.png";
    logoImage = new QImage(logoPath);
    
    if (logoImage->isNull()) {
        logoPath = "/home/arunav/Documents/Dev/CN/Cryptalk/client/src/assets/images/Snibble_logo.png";
        logoImage = new QImage(logoPath);
    }
    
    if (!logoImage->isNull()) {
        QLabel *logoLabel = new QLabel(this);
        QPixmap logoPixmap = QPixmap::fromImage(*logoImage);
        logoPixmap = logoPixmap.scaled(200, 100, Qt::KeepAspectRatio, Qt::SmoothTransformation);
        logoLabel->setPixmap(logoPixmap);
        logoLabel->setAlignment(Qt::AlignCenter);
        layout->addWidget(logoLabel);
        layout->addSpacing(10);
    }
    
    usernameLayout = new QHBoxLayout();
    usernameLabel = new QLabel("Username:", this);
    usernameLabel->setFixedWidth(80);
    usernameLineEdit->setFixedWidth(200);
    usernameLayout->addWidget(usernameLabel);
    usernameLayout->addWidget(usernameLineEdit);
    layout->addLayout(usernameLayout);
    
    passwordLayout = new QHBoxLayout();
    passwordLabel = new QLabel("Password:", this);
    passwordLabel->setFixedWidth(80);
    passwordLineEdit->setFixedWidth(200);
    passwordLayout->addWidget(passwordLabel);
    passwordLayout->addWidget(passwordLineEdit);
    layout->addLayout(passwordLayout);
    
    confirmPasswordLayout = new QHBoxLayout();
    confirmPasswordLabel = new QLabel("Confirm:", this);
    confirmPasswordLabel->setFixedWidth(80);
    confirmPasswordLineEdit->setFixedWidth(200);
    confirmPasswordLayout->addWidget(confirmPasswordLabel);
    confirmPasswordLayout->addWidget(confirmPasswordLineEdit);
    layout->addLayout(confirmPasswordLayout);
    
    layout->addSpacing(20);
    
    buttonLayout = new QHBoxLayout();
    primaryButton = new QPushButton(this);
    primaryButton->setFixedSize(100, 30);
    switchModeButton = new QPushButton(this);
    switchModeButton->setFixedSize(100, 30);
    
    buttonLayout->addWidget(primaryButton);
    buttonLayout->addWidget(switchModeButton);
    layout->addLayout(buttonLayout);


    connect(primaryButton, &QPushButton::clicked, this, &AuthWindow::onPrimaryButtonClicked);
    connect(switchModeButton, &QPushButton::clicked, [this]() {
        if (currentMode == LOGIN) {
            switchToSignupMode();
        } else {
            switchToLoginMode();
        }
    });
}

void AuthWindow::updateUIForMode() {
    if (currentMode == LOGIN) {
        primaryButton->setText("Login");
        switchModeButton->setText("Sign Up");
        confirmPasswordLineEdit->hide();
        confirmPasswordLabel->hide();
        this->setWindowTitle("Login");
    } else {
        primaryButton->setText("Sign Up");
        switchModeButton->setText("Back to Login");
        confirmPasswordLineEdit->show();
        confirmPasswordLabel->show();
        this->setWindowTitle("Sign Up");
    }
}

AuthWindow::~AuthWindow() {
    delete usernameLineEdit;
    delete passwordLineEdit;
    delete confirmPasswordLineEdit;
    delete primaryButton;
    delete switchModeButton;
    delete layout;
}

void AuthWindow::switchToSignupMode() {
    currentMode = SIGNUP;
    updateUIForMode();
    usernameLineEdit->clear();
    passwordLineEdit->clear();
    confirmPasswordLineEdit->clear();
}

void AuthWindow::switchToLoginMode() {
    currentMode = LOGIN;
    updateUIForMode();
    usernameLineEdit->clear();
    passwordLineEdit->clear();
    confirmPasswordLineEdit->clear();
}

void AuthWindow::onPrimaryButtonClicked() {
    if (currentMode == LOGIN) {
        QString username = usernameLineEdit->text();
        QString password = passwordLineEdit->text();
        string usernameStr = username.toStdString();
        string passwordStr = password.toStdString();
        
        if (username.isEmpty() || password.isEmpty()) {
            QMessageBox::warning(this, "Login Failed", "Username and password cannot be empty.");
            return;
        }
        bool loginSuccess = authManager->login(usernameStr, passwordStr);
        if (!loginSuccess) {
            QMessageBox::warning(this, "Login Failed", "Invalid username or password.");
            return;
        } else {
            QMessageBox::information(this, "Login Successful", "Welcome, " + username + "!");
            *isLoggedIn = true;
            Q_EMIT loginSuccessful();
            this->close();
        }
    } else {
        QString username = usernameLineEdit->text();
        QString password = passwordLineEdit->text();
        QString confirmPassword = confirmPasswordLineEdit->text();
        
        if (username.isEmpty() || password.isEmpty() || confirmPassword.isEmpty()) {
            QMessageBox::warning(this, "Signup Failed", "All fields are required.");
            return;
        }
        
        if (password != confirmPassword) {
            QMessageBox::warning(this, "Signup Failed", "Passwords do not match.");
            return;
        }
        
        string usernameStr = username.toStdString();
        string passwordStr = password.toStdString();
        
        if (!authManager->signup(usernameStr, passwordStr)) {
            QMessageBox::warning(this, "Signup Failed", "Username already exists or signup failed.");
            return;
        } else {
            QMessageBox::information(this, "Signup Successful", "Account created successfully! Please login.");
            switchToLoginMode();
        }
    }
}
