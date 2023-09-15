//
// Created by viktor on 26.02.23.
//

#ifndef SERVER_COMMON_SERVER_H
#define SERVER_COMMON_SERVER_H

//We need to define this when using the Asio library without Boost
#define ASIO_STANDALONE

#include "common/common.h"
#include <map>
#include <vector>
#include <string>
#include <fstream>
#include <filesystem>
#include "common/enc_dec_AES.h"
#include "websocketpp/server.hpp"
#include "websocketpp/config/asio_no_tls.hpp"

using std::map;
using std::vector;
using std::string;

typedef websocketpp::server<websocketpp::config::asio> WebsocketEndpoint;
typedef websocketpp::connection_hdl ClientConnection;


#endif //SERVER_COMMON_SERVER_H
