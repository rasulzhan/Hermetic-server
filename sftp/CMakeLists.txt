cmake_minimum_required(VERSION 3.10)

project(sftplib)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

string( TOLOWER "${CMAKE_SYSTEM_NAME}" system_name_lower)
message( "sftplib target system: ${system_name_lower}" )

add_library(sftp
    sshchannel.cpp
    sshlog.cpp
    sshpacket.cpp
    sshsftp.cpp
    sshtools.cpp
    sshtransport.cpp
    sshutils.cpp
    tcpclient_bom.cpp
    tcpclient.cpp
    utils.cpp
    bcrypt/bcrypt_pbkdf.cpp
    bcrypt/blowfish.cpp
    zip/crc32.cpp
    zip/deflate.cpp
    zip/huffman.cpp
    zip/lz77.cpp
    zip/tables.cpp
    zip/zip.cpp
)

target_include_directories(sftp PUBLIC
    .
    ./zip
    ./bcrypt
)
target_link_libraries(sftp
                    crypto
                    ssh2
)

if (${system_name_lower} STREQUAL "windows")
    target_link_libraries(sftp ws2_32 wsock32)
endif()

find_package(OpenSSL REQUIRED)
