#include "WebsocketServer.h"
#include <common/asymmetric.h>
#include <exception>
#include "common/WLoger/Include/WLoger.h"


// sockjs emulation
void WebsocketServer::websocket_on_http_mes(websocketpp::connection_hdl hdl) {
    auto con = endpointInfo.get_con_from_hdl(hdl);

    WLI << "HTTP mes";

	con->set_status(websocketpp::http::status_code::ok);
	con->append_header("access-control-allow-origin", "*");

}

void WebsocketServer::websocket_on_http_dat(websocketpp::connection_hdl hdl) {
    auto con = endpointData.get_con_from_hdl(hdl);

    WLI << "HTTP dat";

	con->set_status(websocketpp::http::status_code::ok);
	con->append_header("access-control-allow-origin", "*");

}

typedef std::string connection_id;
connection_id GetConnectionId(const ClientConnection &connection)
{
    std::stringstream ss;
    ss << reinterpret_cast<uintptr_t>(connection.lock().get());

    return ss.str();
}

WebsocketServer::WebsocketServer()
{
    /* binding info socket */
	endpointInfo.set_open_handler([this](auto && PH1) { onOpenInfo(std::forward<decltype(PH1)>(PH1)); });
	endpointInfo.set_close_handler([this](auto && PH1) { onCloseInfo(std::forward<decltype(PH1)>(PH1)); });
	endpointInfo.set_message_handler([this](auto && PH1, auto && PH2) { onMessageInfo(std::forward<decltype(PH1)>(PH1), std::forward<decltype(PH2)>(PH2)); });
    endpointInfo.set_http_handler([this](auto && PH1) { websocket_on_http_mes(std::forward<decltype(PH1)>(PH1)); });

	endpointInfo.init_asio(&(eventLoop));

    /* binding data socket */
    endpointData.set_open_handler([this](auto && PH1) { onOpenData(std::forward<decltype(PH1)>(PH1)); });
    endpointData.set_close_handler([this](auto && PH1) { onCloseData(std::forward<decltype(PH1)>(PH1)); });
    endpointData.set_message_handler([this](auto && PH1, auto && PH2) { onMessageData(std::forward<decltype(PH1)>(PH1), std::forward<decltype(PH2)>(PH2)); });
    endpointData.set_http_handler([this](auto && PH1) { websocket_on_http_dat(std::forward<decltype(PH1)>(PH1)); });

    endpointData.init_asio(&(eventLoop));

    endpointInfo.clear_access_channels(0xffffffff);
    endpointInfo.set_error_channels(0xffffffff);

    endpointData.clear_access_channels(0xffffffff);
    endpointData.set_error_channels(0xffffffff);
}

void WebsocketServer::Encrypt(std::shared_ptr<OneClient> client, void *input_data, void* output_data, size_t data_size, void* key)
{
    ::encrypt(
        (unsigned char*)input_data,
        data_size,
        reinterpret_cast<unsigned char *>(client->m_uuid.data()),
        (int)client->m_uuid.size(),
        (unsigned char*)key,
        const_cast<unsigned char *>(example_aes_iv),
        (unsigned char*)output_data,
        example_aes_tag);
}



void WebsocketServer::Decrypt(std::shared_ptr<OneClient> client, void *input_data, void* output_data, size_t data_size, void* key)
{
    ::decrypt(
        (unsigned char*)input_data,
        data_size,
        reinterpret_cast<unsigned char *>(client->m_uuid.data()),
        (int)client->m_uuid.size(),
        example_aes_tag,
        (unsigned char*)key,
        const_cast<unsigned char *>(example_aes_iv),
        (unsigned char*)output_data);
}

bool WebsocketServer::CheckUser(const std::string &user_name, const std::string &user_password)
{
    if(user_name.size() == 0)
        return false;

    std::filesystem::create_directory(".users");
    auto m_userPath = ".users/" + user_name + ".usri";
    if (std::filesystem::exists(m_userPath)) {
        std::ifstream user_info(m_userPath, std::ios::in);
        std::ostringstream sstr;
        sstr << user_info.rdbuf();
        std::string str = sstr.str();
        Json json = JsonWorker::Deserialize(str);
        std::string current_password = JsonWorker::FindStringVal(json, "password");

        return user_password == current_password;
    }
   else
   {
       std::ofstream user_info(m_userPath, std::ios::out);
       Json json = JsonWorker::CreateJsonObject();
       JsonWorker::AddToJsonVal(json, "password", user_password);
       std::string str = JsonWorker::Serialize(json);
       user_info.write(reinterpret_cast<const char*>(str.data()), (int)str.size());
       user_info.close();
   }

    return false;
}


std::string WebsocketServer::CreateNewUser(const std::string &user_name, const std::string &user_password)
{
    if (user_name.size() == 0)
        return "user_name is empty";

    std::filesystem::create_directory(".users");
    auto m_userPath = ".users/" + user_name + ".usri";

    if (std::filesystem::exists(m_userPath)) {
        return "User with this name already exists!";
    }
    std::ofstream user_info(m_userPath, std::ios::out);
    Json json = JsonWorker::CreateJsonObject();
    JsonWorker::AddToJsonVal(json, "password", user_password);
    std::string str = JsonWorker::Serialize(json);
    user_info.write(reinterpret_cast<const char*>(str.data()), (int)str.size());
    user_info.close();

    return "";
}

void WebsocketServer::run(int port)
{
    /* connect info socket */
    this->endpointInfo.reset();
	this->endpointInfo.listen(port);
	this->endpointInfo.start_accept();

    /* connect data socket */
    this->endpointData.reset();
    this->endpointData.listen(port + 1);
    this->endpointData.start_accept();

    eventLoop.run();
}

/** return count of connect sockets */
size_t WebsocketServer::numConnections()
{
	/* prevent concurrent access to the list of open connections from multiple threads */
	std::lock_guard<std::mutex> lock(this->connectionListMutex);

	return this->openConnections.size();
}

/** send message to client's info socket */
void WebsocketServer::sendMessageInfo(const ClientConnection& conn, EServerMessageType messageType, Json& arguments)
{
	/* copy the argument values, and bundle the message type into the object */
    if (JsonWorker::FindStringVal(arguments, MESSAGE_FIELD).empty())
        JsonWorker::AddToJsonVal(arguments, MESSAGE_FIELD, std::to_string((int)messageType));
    else
        JsonWorker::ChangeVal(arguments, MESSAGE_FIELD, std::to_string((int)messageType));

    /* send the JSON data to the client (will happen on the networking thread's event loop) */
	this->endpointInfo.send(conn, JsonWorker::Serialize(arguments), websocketpp::frame::opcode::text);
}

/** send message to client's data socket */
void WebsocketServer::sendMessageData(const ClientConnection& conn, const void* payload, size_t len)
{
    /* send the JSON data to the client (will happen on the networking thread's event loop) */
    this->endpointData.send(conn, payload, len, websocketpp::frame::opcode::binary);
}


/** send message to client's data socket */
void WebsocketServer::sendMessageData(const ClientConnection& conn, EServerMessageType messageType, Json& arguments)
{
    if (JsonWorker::FindStringVal(arguments, MESSAGE_FIELD).empty())
        JsonWorker::AddToJsonVal(arguments, MESSAGE_FIELD, std::to_string((int)messageType));
    else
        JsonWorker::ChangeVal(arguments, MESSAGE_FIELD, std::to_string((int)messageType));

    /* send the JSON data to the client (will happen on the networking thread's event loop) */
    this->endpointData.send(conn, JsonWorker::Serialize(arguments), websocketpp::frame::opcode::text);
}

/** broadcast message to all sockets */
void WebsocketServer::broadcastMessage(EServerMessageType messageType, Json& arguments)
{
    /* prevent concurrent access to the list of open connections from multiple threads */
    std::lock_guard<std::mutex> lock(this->connectionListMutex);

    for (const auto& conn : this->openConnections) {
        this->sendMessageInfo(conn, messageType, arguments);
    }
}

/** get instance of class OneClient from connection_hdl */
std::shared_ptr<OneClient> WebsocketServer::GetClient(const ClientConnection& conn)
{
    try {
        std::ostringstream oss;
        oss << reinterpret_cast<uintptr_t>(conn.lock().get());
        std::string uid = oss.str();
        auto        c = m_connectionToClient.find(uid);
        if (c != m_connectionToClient.end()) {
            return c->second;
        }
#if 0
        if (connUUID.find(uid) != connUUID.end()) {
            std::string cuid = connUUID[uid];
            if (uuidClient.find(cuid) != uuidClient.end())
                return uuidClient[cuid];
        }
#endif
    } catch (const std::exception &e) {
        WLI << e.what() << std::endl;
    }

    return nullptr;
}

/**
** @brief sending file to a client
**
** @todo rewrite for chunk reading\loading
** @param conn
** @param options
** @return ****** sending
*/
void WebsocketServer::commandSendFile(const ClientConnection& conn, Json& options)
{
    WLI << "enter commandSendFile" << std::endl;
    auto client = GetClient(conn);
    if (!client) {
        WLI << "Invalid client" << std::endl;
        return;
    }
    std::string path = JsonWorker::FindStringVal(options, "path");
    std::string hash = JsonWorker::FindStringVal(options, "hash");

    std::string path_from_file = client->GetPathToFile(File(path, hash));
    if (!path_from_file.empty() && std::filesystem::exists(path_from_file) &&
        !std::filesystem::is_directory(path_from_file)) {
        // char key[] = ___key;

        size_t file_size = std::filesystem::file_size(path_from_file);
        JsonWorker::AddToJsonVal(options, "file_size", file_size);
        auto conn_id = GetConnectionId(conn);
        auto client = m_connectionToClient[conn_id];

        client->StartDownloadFile(path_from_file);
        /* send info about the start of sending the file */

        sendMessageInfo(client->m_connInfo, EServerMessageType::START_RECEIVE_FILE, options);

#if 0
        /* send binary data of file */
        std::ifstream input(path_from_file, std::ios::binary );
        vector<uint8_t> m_data(std::istreambuf_iterator<char>(input), {});

        auto * decryptedtext = new unsigned char [m_data.size()];
        auto * encryptedtext = new unsigned char [m_data.size()];
        std::size_t ciphertext_len;

        Decrypt(client, m_data.data(), decryptedtext, (int)m_data.size(), key);

        /* Buffer for the decrypted text */

        /* encrypt data */
        Encrypt(client, decryptedtext, encryptedtext, (int)m_data.size(), client->m_aesKey.data());
        ciphertext_len = (int)m_data.size();

        /* sending data */
        size_t mess_size = 1024, pointer = 0, curLen;
        while (pointer != ciphertext_len) {
            curLen = std::min(mess_size, ciphertext_len - pointer);
            sendMessageData(client->m_connData, encryptedtext + pointer, curLen);
            pointer += curLen;
            //float ans = (float)pointer/(float)ciphertext_len;
            //setUploadFileProgress(ans*100);
        }

        delete[] encryptedtext;

        /* send info about the end of sending the file */
        sendMessageData(client->m_connData, EServerMessageType::FILE_RECEIVED, options);
#endif
    } else {
        WLI << "path_from_file is empty, doesn't exist or directory" << std::endl;
        WLI << "path_from_file is " << path_from_file << std::endl;
    }
}

/** event to opening info socket */
void WebsocketServer::onOpenInfo(const ClientConnection& conn)
{
    /* prevent concurrent access to the list of open connections from multiple threads */
    std::lock_guard<std::mutex> lock(this->connectionListMutex);

    /* add the connection handle to our list of open connections */
    this->openConnections.push_back(conn);
    std::string uuid = std::to_string(m_UUIDToClient.size());
    std::shared_ptr<OneClient> client = std::make_shared<OneClient>(uuid);
    client->m_connInfo = conn;
    // NOTE(Sedenkov): won't it eventually overlap available memory?
    // uuidClient[uuid] = client;

    m_UUIDToClient[uuid] = client;

    Json newJson = JsonWorker::CreateJsonObject();
    JsonWorker::AddToJsonVal(newJson, "uuid", uuid);

    string key = generateEncodeKey();
    client->m_aesKey = key;
    //JsonWorker::AddToJsonVal(newJson, "aesKey", key);

    WLI << "open info client " << uuid << std::endl;
    sendMessageInfo(conn, EServerMessageType::USER_REG_STEP_1, newJson);

    std::ostringstream oss;
    oss << reinterpret_cast<uintptr_t>(conn.lock().get());
    // connUUID[oss.str()] = uuid;

    m_connectionToClient[oss.str()] = client;
}

/** event to closing info socket */
void WebsocketServer::onCloseInfo(const ClientConnection& conn)
{
    /* prevent concurrent access to the list of open connections from multiple threads */
    std::lock_guard<std::mutex> lock(this->connectionListMutex);

    auto client = GetClient(conn);
    WLI << "client->UnloadUserFileSystem(); in onCloseInfo" << std::endl;
    client->UnloadUserFileSystem();

    /* remove the connection handle from our list of open connections */
    auto connVal = conn.lock();
    auto newEnd = std::remove_if(this->openConnections.begin(), this->openConnections.end(),
                                 [&connVal](const ClientConnection& elem)
    {
        /* if the pointer has expired, remove it from the vector */
        if (elem.expired()) {
            return true;
        }

        /* if the pointer is still valid, compare it to the handle for the closed connection */
        auto elemVal = elem.lock();
        if (elemVal.get() == connVal.get()) {
            return true;
        }

        return false;
    });

    /* truncate the connections vector to erase the removed elements */
    this->openConnections.resize(std::distance(openConnections.begin(), newEnd));
}

/** event to messaging info socket */
void WebsocketServer::onMessageInfo(const ClientConnection& conn, const WebsocketEndpoint::message_ptr& msg)
{
    auto client = GetClient(conn);
    if(!client){
        WLI << "Invalid client" << std::endl;
        return;
    }

    auto msg_strig = const_cast<string &>(msg->get_payload());
    printf(msg_strig.c_str());
    Json msgJson = JsonWorker::Deserialize(msg_strig);

    JsonWorker::print_json(msgJson, "onMessageInfo");

    if (!msgJson->HasParseError() && msgJson->HasMember(MESSAGE_FIELD)) {
        int    command = 0;
        string str_comm = JsonWorker::FindStringVal(msgJson, MESSAGE_FIELD);
        if (::isNumber(str_comm) && !str_comm.empty())
            command = stoi(str_comm);

        auto type_command = (EClientMessageType)command;

        switch (type_command) {
        case EClientMessageType::NONE: break;

        case EClientMessageType::START_SEND_BIG_FILE:
        {
            WLI << "enter case EClientMessageType::START_SEND_BIG_FILE" << std::endl;
            auto file_size = std::atol(JsonWorker::FindStringVal(msgJson, "file_size").c_str());
            auto file = JsonWorker::FindStringVal(msgJson, "file");
            auto secret = JsonWorker::FindStringVal(msgJson, "secret");

            string parents_hashs;
            File   tfile;
            tfile.FromStringNoMap(file, parents_hashs);

            // Json newJson = JsonWorker::CreateJsonObject();
            // JsonWorker::AddToJsonVal(newJson, "path", tfile.path);
            // JsonWorker::AddToJsonVal(newJson, "hash", tfile.hash);
            // sendMessageInfo(client->m_connInfo, EServerMessageType::FILE_SENT, newJson);
            {
                std::lock_guard<std::mutex> l(client->m_mutex);
                client->StartUploadFile(tfile, secret, parents_hashs, file_size);
            }

            sendMessageInfo(client->m_connInfo, EServerMessageType::FILE_INFO_RECEIVED, msgJson);
        } break;

        case EClientMessageType::START_SEND_FILE:
        {
            WLI << "enter case EClientMessageType::START_SEND_FILE" << std::endl;
            auto path = JsonWorker::FindStringVal(msgJson, "path");
            auto hash = JsonWorker::FindStringVal(msgJson, "hash");
            break;
        }
        case EClientMessageType::START_RECEIVE_FILE:
        {
            WLI << "server received EClientMessageType::START_RECEIVE_FILE" << std::endl;
            auto   path = JsonWorker::FindStringVal(msgJson, "path");
            auto   hash = JsonWorker::FindStringVal(msgJson, "hash");
            string secret = JsonWorker::FindStringVal(msgJson, "secret");

            bool has_access = true;

            if (has_access) {
                has_access = client->CheckPermision(File(path, hash), secret);
                WLI << "has access" << std::endl;
            } else {
                WLI << "no access ((" << std::endl;
            }
            if (has_access) {
                WLI << "before commandSendFile(conn, msgJson);" << std::endl;
                commandSendFile(conn, msgJson);
                WLI << "after commandSendFile(conn, msgJson);" << std::endl;
            } else {
                Json newJson = JsonWorker::CreateJsonObject();
                JsonWorker::AddToJsonVal(newJson, "path", path);
                JsonWorker::AddToJsonVal(newJson, "hash", hash);
                JsonWorker::AddToJsonVal(newJson, "what", "Access denied");
                WLI << "access denied" << std::endl;
                sendMessageInfo(client->m_connInfo, EServerMessageType::PERMISSION_ERROR, newJson);
            }

            break;
        }

        case EClientMessageType::END_FILE_DOWNLOAD:
        {
            WLI << "enter case EClientMessageType::END_FILE_DOWNLOAD:" << std::endl;
            auto client = GetClient(conn);
            fclose(client->m_currentDownloadFile);
            client->m_currentDownloadFile = 0;
            std::cout << "End File Download" << std::endl;
            sendMessageData(client->m_connData, EServerMessageType::FILE_RECEIVED, msgJson);
        } break;

        case EClientMessageType::START_RENAME_FILE:
        {
            auto old_path = JsonWorker::FindStringVal(msgJson, "old_path");
            auto old_hash = JsonWorker::FindStringVal(msgJson, "old_hash");
            auto new_path = JsonWorker::FindStringVal(msgJson, "new_path");
            auto new_hash = JsonWorker::FindStringVal(msgJson, "new_hash");
            if (true) {
                client->RenameFile(File(old_path, old_hash), File(new_path, new_hash));
                Json newJson = JsonWorker::CreateJsonObject();
                JsonWorker::AddToJsonVal(newJson, "old_path", old_path);
                JsonWorker::AddToJsonVal(newJson, "new_path", new_path);
                JsonWorker::AddToJsonVal(newJson, "old_hash", old_hash);
                JsonWorker::AddToJsonVal(newJson, "new_hash", new_hash);

                sendMessageInfo(conn, EServerMessageType::FILE_RENAMED, newJson);
            } else {
                Json newJson = JsonWorker::CreateJsonObject();
                JsonWorker::AddToJsonVal(newJson, "path", old_path);
                JsonWorker::AddToJsonVal(newJson, "hash", old_hash);
                JsonWorker::AddToJsonVal(newJson, "what", "Access denied");

                sendMessageInfo(client->m_connInfo, EServerMessageType::PERMISSION_ERROR, newJson);
            }
            break;
        }
        case EClientMessageType::START_REMOVE_FILE:
        {
            auto path = JsonWorker::FindStringVal(msgJson, "path");
            auto hash = JsonWorker::FindStringVal(msgJson, "hash");
            if (true) {
                client->RemoveFile(File(path, hash));

                Json newJson = JsonWorker::CreateJsonObject();
                JsonWorker::AddToJsonVal(newJson, "path", path);
                JsonWorker::AddToJsonVal(newJson, "hash", hash);

                sendMessageInfo(conn, EServerMessageType::FILE_REMOVED, newJson);
            } else {
                Json newJson = JsonWorker::CreateJsonObject();
                JsonWorker::AddToJsonVal(newJson, "path", path);
                JsonWorker::AddToJsonVal(newJson, "hash", hash);
                JsonWorker::AddToJsonVal(newJson, "what", "Access denied");

                sendMessageInfo(client->m_connInfo, EServerMessageType::PERMISSION_ERROR, newJson);
            }
            break;
        }
        case EClientMessageType::START_GET_FILES_LIST:
        {
            WLI << "enter case EClientMessageType::START_GET_FILES_LIST:" << std::endl;
            auto machine_id = JsonWorker::FindStringVal(msgJson, "machine_id");
            std::unordered_map<std::string, File_ptr> volume_to_send;
            for (const auto &[filename, file_ptr]: client->m_files) {
                if (machine_id == filename) {
                    volume_to_send = file_ptr->map;
                    break;
                }
            }

            std::string files = "";
            files = FileMapToString(&client->m_files);
            Json newJson = JsonWorker::CreateJsonObject();
            JsonWorker::AddToJsonVal(newJson, "files", files);
            WLI << "files : " << files << std::endl;

            sendMessageInfo(conn, EServerMessageType::GET_FILES_LIST, newJson);
            WLI << "end case EClientMessageType::START_GET_FILES_LIST:" << std::endl;
            break;
        }
        case EClientMessageType::GET_SERVER_STATUS:
        {
            std::string available_machines_list;
            for (const auto &name: client->GetCurrentUserAvailableMachineIDs()) {
                available_machines_list += name + ",";
            }
            Json newJson = JsonWorker::CreateJsonObject();
            JsonWorker::AddToJsonVal(newJson, "status", "1");
            JsonWorker::AddToJsonVal(newJson, "files", available_machines_list);
            WLI << "available_machines_list : " << available_machines_list << std::endl;

            sendMessageInfo(conn, EServerMessageType::GET_SERVER_STATUS, newJson);

            break;
        }
        case EClientMessageType::SET_MACHINE_ID:  // receive machine_id from client
        {
            WLI << "enter case EClientMessageType::SET_MACHINE_ID" << std::endl;
            auto machine_id = JsonWorker::FindStringVal(msgJson, "machine_id");
            if (!machine_id.empty()) {
                client->SetMachineId(machine_id);
                WLI << "set machine id to : " << machine_id << std::endl;
            } else {
                WLI << "set machine id unsuccessfull" << std::endl;
            }
            break;
        }
        case EClientMessageType::REGISTER_NEW_USER:
        {
            WLI << "enter case EClientMessageType::REGISTER_NEW_USER" << std::endl;
            auto user_name = JsonWorker::FindStringVal(msgJson, "user_name");
            auto user_password = JsonWorker::FindStringVal(msgJson, "user_password");

            Json newJson = JsonWorker::CreateJsonObject();
            JsonWorker::AddToJsonVal(newJson, "user_name", user_name);
            JsonWorker::AddToJsonVal(newJson, "user_password", user_password);
            if (std::string error = CreateNewUser(user_name, user_password); error.empty()) {
                sendMessageInfo(conn, EServerMessageType::USER_CREATED_SUCCEED, newJson);
                WLI << "Created user " << user_name << std::endl;
            } else {
                JsonWorker::AddToJsonVal(newJson, "error_message", error);
                sendMessageInfo(conn, EServerMessageType::USER_CREATED_FAILED, newJson);
                WLI << "User " << user_name << " creation failed with message " << error
                    << std::endl;
            }
            break;
        }
        default: break;
        }
    } else {
    }
}

/** event to opening data socket */
void WebsocketServer::onOpenData(const ClientConnection& conn)
{
    /* prevent concurrent access to the list of open connections from multiple threads */
    std::lock_guard<std::mutex> lock(this->connectionListMutex);

    /* add the connection handle to our list of open connections */
    this->openConnections.push_back(conn);
}

/** event to closing data socket */
void WebsocketServer::onCloseData(const ClientConnection& conn)
{
    /* prevent concurrent access to the list of open connections from multiple threads */
    std::lock_guard<std::mutex> lock(this->connectionListMutex);

    /* remove the connection handle from our list of open connections */
    auto connVal = conn.lock();
    auto newEnd = std::remove_if(this->openConnections.begin(), this->openConnections.end(), [&connVal](const ClientConnection& elem)
    {
        /* if the pointer has expired, remove it from the vector */
        if (elem.expired()) {
            return true;
        }

        /* if the pointer is still valid, compare it to the handle for the closed connection */
        auto elemVal = elem.lock();
        if (elemVal.get() == connVal.get()) {
            return true;
        }

        return false;
    });

    /* truncate the connections vector to erase the removed elements */
    this->openConnections.resize(std::distance(openConnections.begin(), newEnd));
}

/** event to messaging data socket */
void WebsocketServer::onMessageData(const ClientConnection& conn, const WebsocketEndpoint::message_ptr& msg)
{
    auto msg_string = const_cast<string &>(msg->get_payload());
    Json msgJson = JsonWorker::Deserialize(msg_string);

    JsonWorker::print_json(msgJson, "onMessageData");

    if (msgJson->IsObject() && !msgJson->HasParseError() && msgJson->HasMember(MESSAGE_FIELD)) {
        int command = 0;
        string str_comm = JsonWorker::FindStringVal(msgJson, MESSAGE_FIELD);
        if (::isNumber(str_comm) && !str_comm.empty())
            command = stoi(str_comm);

        auto type_command = (EClientMessageType) command;

        switch (type_command) {
            case EClientMessageType::NONE:
                break;

            case EClientMessageType::FILE_CHUNK_INFO: {
		WLI << "enter EClientMessageType::FILE_CHUNK_INFO" << std::endl;
                auto offset_str = JsonWorker::FindStringVal(msgJson, "offset");
                auto offset = std::stol(offset_str);

                auto conn_id = GetConnectionId(conn);
                auto client = m_connectionToClient[conn_id];

                int size = msg_string.size() - std::strlen(msg_string.data()) - 1;
                // {
                    // std::lock_guard<std::mutex> l(client->m_mutex);
                    client->WriteChunkToUploadFile((uint8_t *)msg->get_raw_payload().data() +
                                                        std::strlen(msg_string.data()) + 1,
                                                    offset, size);
                // }
            } break;

            case EClientMessageType::FILE_CHUNK: {

            } break;

            case EClientMessageType::END_SEND_BIG_FILE:
            {
		WLI << "enter EClientMessageType::END_SEND_BIG_FILE" << std::endl;
                auto file = JsonWorker::FindStringVal(msgJson, "file");
                auto secret = JsonWorker::FindStringVal(msgJson, "secret");

                string parents_hashs;
                File tfile;
                tfile.FromStringNoMap(file, parents_hashs);

                auto conn_id = GetConnectionId(conn);
                auto client = m_connectionToClient[conn_id];

                // {
                    // std::lock_guard<std::mutex> l(client->m_mutex);
                if (client->EndUploadFile(tfile, secret, parents_hashs, 0)) {
                    // client->SaveFile(tfile, secret, parents_hashs);
                    // }

                    Json newJson = JsonWorker::CreateJsonObject();
                    JsonWorker::AddToJsonVal(newJson, "path", tfile.path);
                    JsonWorker::AddToJsonVal(newJson, "hash", tfile.hash);

                    sendMessageInfo(client->m_connInfo, EServerMessageType::FILE_SENT, newJson);
                }
                else {
                    sendMessageInfo(client->m_connInfo, EServerMessageType::FILE_UPLOADING, msgJson);
                }

            } break;

            case EClientMessageType::MERGE_SOCKETS_STEP_1: {
		WLI << "enter EClientMessageType::MERGE_SOCKETS_STEP_1" << std::endl;
                auto uuid = JsonWorker::FindStringVal(msgJson, "uuid");
                auto user_name = JsonWorker::FindStringVal(msgJson, "user_name");
                auto user_password = JsonWorker::FindStringVal(msgJson, "user_password");
                auto ser_pub = JsonWorker::FindStringVal(msgJson, "public_password");
                auto machine_id = JsonWorker::FindStringVal(msgJson, "machine_id");
                std::string public_password(ser_pub.size() / 2, '/0');

                Deserialize(public_password.data(), ser_pub.size() / 2, ser_pub);
                //WLI << "public_password: " << public_password << std::endl;
                std::ostringstream oss;
                oss << reinterpret_cast<uintptr_t>(conn.lock().get());

                auto conn_id = GetConnectionId(conn);
                auto client = m_UUIDToClient[uuid];
                if(client == nullptr)
                    break;
                m_connectionToClient[conn_id] = client;
                client->m_connData = conn;
                if (CheckUser(user_name, user_password)) {
                    client->m_userName = user_name;
                    std::filesystem::create_directory("files");
                    auto m_userPath = "files/" + user_name + "/";
                    std::filesystem::create_directory(m_userPath);
                    client->m_userPath = m_userPath;
                    client->m_userPass = user_password;
                    client->m_machineId = machine_id;

                    client->Init();

                    Json newJson = JsonWorker::CreateJsonObject();

                    std::string encoded_key = "";

                    size_t ciphersize;

                    asymmetric::encrypt(client->m_aesKey, encoded_key, public_password, ciphersize);

                    //WLI << "aesKey: " << uuidClient[uuid]->m_aesKey << std::endl;
                    //WLI << "encoded aesKey: " << encoded_key << std::endl;

                    std::string serialize_encoded_key = "";

                    Serialize(encoded_key.data(), encoded_key.size(), serialize_encoded_key);

                    //WLI << "serialize encoded aesKey: " << serialize_encoded_key << std::endl;

                    JsonWorker::AddToJsonVal(newJson, "aesKey", serialize_encoded_key);
                    JsonWorker::AddToJsonVal(newJson, "ciphersize", std::to_string(ciphersize));
                    JsonWorker::AddToJsonVal(newJson, "user_name", user_name);

                    sendMessageInfo(client->m_connInfo, EServerMessageType::USER_REG_STEP_2, newJson);

                    WLI << "EClientMessageType::MERGE_SOCKETS_STEP_1, client->m_machineId: " << client->m_machineId << std::endl;
                    client->LoadUserFileSystem(machine_id);
                }
                else
                {
                    //WLI << "Bad password : " << user_name << std::endl;
                    Json newJson = JsonWorker::CreateJsonObject();
                    JsonWorker::AddToJsonVal(newJson, "hash", "");
                    sendMessageInfo(client->m_connInfo, EServerMessageType::LOGIN_ERROR, newJson);
                }

#if 0
                connUUID[oss.str()] = uuid;
                uuidClient[uuid]->m_connData = conn;
                if(Check_user(user_name, user_password)){
                    uuidClient[uuid]->m_userName = user_name;
                    std::filesystem::create_directory("files");
                    auto m_userPath = "files/" + user_name + "/";
                    std::filesystem::create_directory(m_userPath);
                    uuidClient[uuid]->m_userPath = m_userPath;
                    uuidClient[uuid]->m_userPass = user_password;

                    uuidClient[uuid]->Init();

                    Json newJson = JsonWorker::CreateJsonObject();

                    std::string encoded_key = "";

                    size_t ciphersize;

                    asymmetric::encrypt(uuidClient[uuid]->m_aesKey, encoded_key, public_password, ciphersize);

                    //WLI << "aesKey: " << uuidClient[uuid]->m_aesKey << std::endl;
                    //WLI << "encoded aesKey: " << encoded_key << std::endl;

                    std::string serialize_encoded_key = "";

                    Serialize(encoded_key.data(), encoded_key.size(), serialize_encoded_key);

                    //WLI << "serialize encoded aesKey: " << serialize_encoded_key << std::endl;

                    JsonWorker::AddToJsonVal(newJson, "aesKey", serialize_encoded_key);
                    JsonWorker::AddToJsonVal(newJson, "ciphersize", std::to_string(ciphersize));

                    sendMessageInfo(uuidClient[uuid]->m_connInfo, EServerMessageType::USER_REG_STEP_2, newJson);
                }
                else
                {
                    //WLI << "Bad password : " << user_name << std::endl;
                    Json newJson = JsonWorker::CreateJsonObject();
                    JsonWorker::AddToJsonVal(newJson, "hash", "");
                    sendMessageInfo(uuidClient[uuid]->m_connInfo, EServerMessageType::LOGIN_ERROR, newJson);
                }
#endif
                break;
            }

            case EClientMessageType::MERGE_SOCKETS_STEP_2:
            {
		WLI << "enter EClientMessageType::MERGE_SOCKETS_STEP_2" << std::endl;
#if 1
                // TODO(Sedenkov): mutex
                auto uuid = JsonWorker::FindStringVal(msgJson, "uuid");

                auto conn_id = GetConnectionId(conn);
                auto it = m_connectionToClient.find(conn_id);
                if (it == m_connectionToClient.end()) {
                    auto client = m_UUIDToClient[uuid];
                    client->m_allDataConnections.push_back(conn);
                    m_connectionToClient[conn_id] = client;
                }
                std::cout << "Merge step 2" << conn_id << std::endl;
#endif
            } break;

            case EClientMessageType::END_SEND_FILE: {
		WLI << "enter EClientMessageType::END_SEND_FILE" << std::endl;
                auto file = JsonWorker::FindStringVal(msgJson, "file");
                auto secret = JsonWorker::FindStringVal(msgJson, "secret");

                string parents_hashs;
                File tfile;
                tfile.FromStringNoMap(file, parents_hashs);
                //WLI << "in file : " << file << std::endl;
                //WLI << "file.path : " << tfile.path << std::endl;
                //WLI << "file.hash : " << tfile.hash << std::endl;
                //WLI << "file.formatTime : " << tfile.formatTime << std::endl;
                auto client = GetClient(conn);
                if(!client){
                    WLI << "Invalid client" << std::endl;
                    break;
                }
                client->SaveFile(tfile, secret, parents_hashs);
		        //WLI << "file saved" << std::endl;
                Json newJson = JsonWorker::CreateJsonObject();
                JsonWorker::AddToJsonVal(newJson, "path", tfile.path);
                JsonWorker::AddToJsonVal(newJson, "hash", tfile.hash);

                sendMessageInfo(client->m_connInfo, EServerMessageType::FILE_SENT, newJson);
                break;
            }

            case EClientMessageType::DOWNLOAD_FILE_BLOCK:
            {
                WLI << "enter EClientMessageType::DOWNLOAD_FILE_BLOCK on server" << std::endl;
                char key[] = ___key;

                auto client = GetClient(conn);

                int offset = std::stol(JsonWorker::FindStringVal(msgJson, "offset"));
                int size = std::stol(JsonWorker::FindStringVal(msgJson, "download_size"));
                const int chunk_size = 64 * 1024;

                // auto info = JsonWorker::CreateJsonObject();
                JsonWorker::ChangeVal(msgJson, "offset", std::to_string(0));
                JsonWorker::ChangeVal(msgJson, MESSAGE_FIELD,
                                         std::to_string((int)EServerMessageType::FILE_CHUNK_INFO));

                // std::unique_ptr<uint8_t> chunk(new uint8_t[chunk_size]);
                std::unique_ptr<uint8_t> encrypted_chunk(new uint8_t[chunk_size]);

                // size_t current_size = 0;
                std::cout << "Download file: " << offset << " -- " << size << std::endl;
                while (size > 0) {
                    size_t current_chunk_size = std::min(size, chunk_size);

                    JsonWorker::ChangeVal(msgJson, "offset", std::to_string(offset));
                    auto json_str = JsonWorker::Serialize(msgJson);
                    // NOTE(Sedenkov): additional 1 for null termination for separating json and bin
                    // data
                    size_t total_payload_size = json_str.size() + 1 + current_chunk_size;
                    std::unique_ptr<uint8_t> payload(new uint8_t[total_payload_size]);
                    std::memcpy(payload.get(), json_str.c_str(), json_str.size() + 1);

                    uint8_t *chunk = payload.get() + json_str.size() + 1;

                    /* read chunk from file */
                    {
                        std::lock_guard<std::mutex> file_lock(client->m_fileDownloadMutex);
                        fseek(client->m_currentDownloadFile, offset, SEEK_SET);
                        fread(chunk, 1, current_chunk_size, client->m_currentDownloadFile);
                    }

                    Decryption decrypt {reinterpret_cast<unsigned char *>(client->m_uuid.data()),
                                        (int)client->m_uuid.size(),
                                        reinterpret_cast<unsigned char *>(key),
                                        const_cast<unsigned char *>(example_aes_iv),
                                        0,
                                        0};

                    Encryption encrypt {reinterpret_cast<unsigned char *>(client->m_uuid.data()),
                                        (int)client->m_uuid.size(),
                                        (unsigned char *)client->m_aesKey.data(),
                                        const_cast<unsigned char *>(example_aes_iv)};

                    decrypt.DecryptNextBlock(encrypted_chunk.get(), current_chunk_size, chunk );
                    decrypt.FinishDecryption(encrypted_chunk.get(), 0);

                    // Decrypt(client, m_data.data(), decryptedtext, (int)m_data.size(), key);
                    encrypt.EncyptNextBlock(encrypted_chunk.get(), current_chunk_size, chunk);
                    unsigned char tag2[EVP_GCM_TLS_TAG_LEN];
                    encrypt.FinishEncryption(chunk, tag2);

                    websocketpp::lib::error_code ec;
                    endpointData.send(conn, payload.get(), total_payload_size,
                                        websocketpp::frame::opcode::binary, ec);
                    size -= current_chunk_size;
                    offset += current_chunk_size;
                }
            } break;

            default: break;
            }

    } else {
        for (int i=0; i < msg->get_raw_payload().size(); i++)
        {
            auto client = GetClient(conn);
            if(!client){
                WLI << "Invalid client" << std::endl;
                return;
            }
            client->m_binData.push_back((uint8_t)*(msg->get_raw_payload().data() + i));
        }
    }
}
