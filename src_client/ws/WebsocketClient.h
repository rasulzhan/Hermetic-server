//
// Created by viktor on 25.02.23.
//

#ifndef SERVER_WEBSOCKETCLIENT_H
#define SERVER_WEBSOCKETCLIENT_H


#define ASIO_STANDALONE

#include <string>
#include <vector>
#include <map>
#include <utility>
#include <fstream>
#include "websocketpp/config/asio_no_tls_client.hpp"
#include "websocketpp/client.hpp"
#include "asio/io_service.hpp"
#include "../../common/json_worker.h"
#include "../../common/enc_dec_AES.h"
#include "../../common/common.h"
#include <mutex>



typedef websocketpp::client<websocketpp::config::asio_client> ws_client;
typedef websocketpp::config::asio_client::message_type::ptr msg;
typedef websocketpp::connection_hdl ClientConnection;
using websocketpp::lib::bind;

using std::string;
using std::vector;
using std::map;

class FileUploader;

class WebsocketClient
{
protected:
    asio::io_service eventLoop;
    std::thread* eventLoopThread;

    ClientConnection m_connInfo;
    ClientConnection m_connData;
    bool m_isConnectionDataEstablished = false;
    std::vector<ClientConnection> m_allDataConnections;

    ws_client m_wsClientInfo;
    ws_client m_wsClientData;

    string m_uuid;
    string private_password;
    string local_key;
    string m_aesKey;
    string m_uriInfo, m_uriData;

    vector<uint8_t> m_binData;
    vector<string> m_filesList;

    FileUploader* uploader;

    std::string message_;
    std::string pass_;
    std::string user_;
    std::string register_pass_;
    std::string register_user_;

    std::map<std::string, std::string> temporal_password;

    bool online = false;

public:

    bool isOnline() {return online; }

    WebsocketClient(string& uri_info, string& uri_data);

    void run();
    void close();
    static void command(WebsocketClient* client, int command_type, Json& options, const string& password = "");
    static std::string uploading_filename;
    static int uploading_file_size;
    static int uploaded_size;

    std::string message();

    void SetPassword(const char*);
    void SetUsername(const char*);
    void SetRegistrationPassword(const char*);
    void SetRegistrationUsername(const char*);

    void SetFileUploader(FileUploader*);

    std::string m_macAddress;

protected:

    void websocket_on_http_mes(ClientConnection hdl);
    void websocket_on_http_dat(ClientConnection hdl);

    // all bindings method for info socket
    void onOpenInfo(const ClientConnection& conn);
    void onFailInfo(const ClientConnection& conn);
    void onMessageInfo(const ClientConnection& conn, const msg& msg);
    void onCloseInfo(const ClientConnection& conn);

    // all bindings method for data socket
    void onOpenData(const ClientConnection& conn);
    void onFailData(const ClientConnection& conn);
    void onMessageData(const ClientConnection& conn, const msg& msg);
    void onCloseData(const ClientConnection& conn);

    // implementation of all client's command
    void commandSendFile(Json &options, const string& password = "");
    void commandDownloadFile(Json &options, const string& password = "");
//    void commandRecieveFile(Json &options);
//    void commandRemoveFile(Json &options);
    void sendMessageInfo(const ClientConnection& conn, EClientMessageType messageType, Json& arguments);

    // save recieved file from server
    void saveFile(const string& str_path, const string& hash);

    string generate_secret(const string& password);

    void Encrypt(void *input_data, void* output_data, size_t data_size, void* key);

    void Decrypt(void *input_data, void* output_data, size_t data_size, void* key);

    void SendBigFileAndEndFileUpload(const std::filesystem::path &path_from_file, Json &options, const string &password);

private:
    void SendBigFile(const std::filesystem::path &path_from_file, Json& options, const string& password);

    void UserRegStep1(const Json &json);

    bool m_uploadInProcess = false;
    bool m_downloadInProcess = false;

    FILE *m_downloadFile;
    std::mutex m_fileMutex;
};

#endif //SERVER_WEBSOCKETCLIENT_H
