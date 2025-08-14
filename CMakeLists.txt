cmake_minimum_required(VERSION 3.16)

project(Snibble VERSION 0.1 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(Qt6 REQUIRED COMPONENTS Widgets)
find_package(laserpants_dotenv REQUIRED)
find_package(CURL REQUIRED)
# Find jsoncpp
find_package(PkgConfig REQUIRED)
find_package(OpenSSL REQUIRED)
pkg_check_modules(JSONCPP REQUIRED jsoncpp)

# Find libsecret
pkg_check_modules(LIBSECRET REQUIRED libsecret-1)

# Find hiredis
pkg_check_modules(HIREDIS REQUIRED hiredis)

# Note: jwt-cpp is no longer needed on client side - JWT verification happens server-side

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/src)
include_directories(/usr/local/include/laserpants/dotenv-0.9.3)
include_directories(${LIBSECRET_INCLUDE_DIRS})
include_directories(${JSONCPP_INCLUDE_DIRS})
include_directories(${HIREDIS_INCLUDE_DIRS})
qt_standard_project_setup()

qt_add_executable(Snibble
        src/main.cpp
        src/mainwindow.cpp
        src/mainwindow.h
        src/mainwindow.ui
        src/backend/AuthManager.cpp
        src/backend/AuthManager.h
        src/backend/NetworkManager.cpp
        src/backend/NetworkManager.h
        src/backend/MessageHandler.cpp
        src/backend/MessageHandler.h
        src/backend/Encryption_Decryption.cpp
        src/backend/Encryption_Decryption.h
        src/ui/AuthWindow.cpp
        src/ui/AuthWindow.h
        src/ui/ChatWindow.cpp
        src/ui/ChatWindow.h
)
target_link_libraries(Snibble PRIVATE 
    Qt${QT_VERSION_MAJOR}::Widgets 
    CURL::libcurl 
    ${JSONCPP_LIBRARIES}
    ${LIBSECRET_LIBRARIES}
    ${HIREDIS_LIBRARIES}
    OpenSSL::SSL
    OpenSSL::Crypto
    pthread
)

# Add compile definitions to handle Qt/GLib conflicts
target_compile_definitions(Snibble PRIVATE 
    QT_NO_SIGNALS_SLOTS_KEYWORDS
)

# Add additional compiler flags for libsecret and jsoncpp
target_compile_options(Snibble PRIVATE 
    ${LIBSECRET_CFLAGS_OTHER}
    ${JSONCPP_CFLAGS_OTHER}
    ${HIREDIS_CFLAGS_OTHER}
)

set_target_properties(Snibble PROPERTIES
    MACOSX_BUNDLE_BUNDLE_VERSION ${PROJECT_VERSION}
    MACOSX_BUNDLE_SHORT_VERSION_STRING ${PROJECT_VERSION_MAJOR}.${PROJECT_VERSION_MINOR}
    MACOSX_BUNDLE TRUE
    WIN32_EXECUTABLE TRUE
)

include(GNUInstallDirs)
install(TARGETS Snibble
    BUNDLE DESTINATION .
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)
