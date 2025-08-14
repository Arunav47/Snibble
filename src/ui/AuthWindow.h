#ifndef AUTH_WINDOW_H
#define AUTH_WINDOW_H

#include <QWidget>
#include <QLineEdit>
#include <QPushButton>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QMessageBox>
#include <QLabel>
#include <QSizePolicy>

class AuthManager;

class AuthWindow : public QWidget {
    Q_OBJECT

public:
    AuthWindow(bool *isLoggedIn, AuthManager* authManager, QLineEdit *usernameLineEdit, QLineEdit *passwordLineEdit, QWidget *parent = nullptr);
    ~AuthWindow();
    void onPrimaryButtonClicked();
    void switchToSignupMode();
    void switchToLoginMode();

Q_SIGNALS:
    void loginSuccessful();

private:
    enum Mode { LOGIN, SIGNUP };
    Mode currentMode;
    bool *isLoggedIn;
    QLineEdit *usernameLineEdit;
    QLineEdit *passwordLineEdit;
    QLineEdit *confirmPasswordLineEdit; 
    QPushButton *primaryButton; 
    QPushButton *switchModeButton; 
    AuthManager *authManager;
    QImage *logoImage;
    QVBoxLayout *layout;
    
    void setupUI();
    void updateUIForMode();
};

#endif