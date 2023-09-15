#ifndef _WEBSOCKET_SERVER
#define _WEBSOCKET_SERVER

#include <mutex>
#include <functional>
#include <unordered_map>


#include "src_server/additional/common_server.h"
#include "common/json_worker.h"
#include "src_server/client/client_copy.h"


class WebsocketServer
{
public:

    WebsocketServer();
    void run(int port);

protected:
    void websocket_on_http_mes(ClientConnection hdl);
    void websocket_on_http_dat(ClientConnection hdl);

    static bool CheckUser(const std::string &user_name, const std::string &user_password);
    static std::string CreateNewUser(const std::string &user_name, const std::string &user_password);

    // all bindings method for info socket
    void onOpenInfo(const ClientConnection& conn);
    void onCloseInfo(const ClientConnection& conn);
    void onMessageInfo(const ClientConnection& conn, const WebsocketEndpoint::message_ptr& msg);

    // all bindings method for data socket
    void onOpenData(const ClientConnection& conn);
    void onCloseData(const ClientConnection& conn);
    void onMessageData(const ClientConnection& conn, const WebsocketEndpoint::message_ptr& msg);

    // sends a message to an individual client
    void sendMessageInfo(const ClientConnection& conn, EServerMessageType messageType, Json& arguments);
    void sendMessageData(const ClientConnection& conn, const void* payload, size_t len);
    void sendMessageData(const ClientConnection& conn, EServerMessageType messageType, Json& arguments);

    // ends a message to all connected clients
    void broadcastMessage(EServerMessageType messageType, Json& arguments);

    //Returns the number of currently connected clients
    size_t numConnections();

    // get instance of class OneClient from connection_hdl
    std::shared_ptr<OneClient> GetClient(const ClientConnection& conn);

    // command to sending file on client
    void commandSendFile(const ClientConnection& conn, Json& options);


    void Encrypt(std::shared_ptr<OneClient> client, void *input_data, void* output_data, size_t data_size, void* key);

    void Decrypt(std::shared_ptr<OneClient> client, void *input_data, void* output_data, size_t data_size, void* key);

    std::mutex connectionListMutex;
    asio::io_service eventLoop;
    WebsocketEndpoint endpointInfo;
    WebsocketEndpoint endpointData;
    vector<ClientConnection> openConnections;

    typedef std::string connection_id;
    typedef std::string user_id;
    std::unordered_map<user_id, std::shared_ptr<OneClient>> m_UUIDToClient;
    std::unordered_map<connection_id, std::shared_ptr<OneClient>> m_connectionToClient;
};

#endif
