
#include "file_list.h"
#include "src_server/ws/WebsocketServer.h"
#include <iostream>
#include <fstream>
#include "common/WLoger/Include/WLoger.h"

//
// Created by viktor on 22.02.23.
//


static char        MainPath[256];
struct
{
    std::mutex lock;
    FileList   list;
} Files;

int main(int argc, char **argv) {
    std::ofstream log_out = std::ofstream("./server_log.log");
    ATTACH_STRAEM(WL_INFO, std::cout);
    ATTACH_STRAEM(WL_ERROR, std::cout);
    ATTACH_STRAEM(WL_WARNING, std::cout);
    ATTACH_STRAEM(WL_INFO, log_out);
    ATTACH_STRAEM(WL_ERROR, log_out);
    ATTACH_STRAEM(WL_WARNING, log_out);
    int port = 8081;
    if (std::filesystem::exists("port.txt")) {
        std::ifstream fin("port.txt");
        std::string port_str;
        std::getline(fin, port_str);
        port = std::stoi(port_str);
    } else {
        std::ofstream fout("port.txt");
        fout << std::to_string(port);
    }

    if(argc > 1)
        port = atoi(argv[1]);

    std::filesystem::create_directory("mount");


    asio::io_service mainEventLoop;

    // create info websocket
    WebsocketServer ws_server = WebsocketServer();


    //Start the networking thread
    std::thread serverThread([&ws_server, &port]() {
        ws_server.run(port);
    });

    //Start a keyboard input thread that reads from stdin
    std::thread inputThread([&ws_server, &mainEventLoop]()
    {
        string input;
        for(;;)
        {
            //Read user input from stdin
            std::getline(std::cin, input);

            if(input == "exit")
                exit(0);

            //Debug output on the main thread
            mainEventLoop.post([]() {
                WLI << "User input debug output on the main thread" << std::endl;
            });

        }

    });

    asio::io_service::work work(mainEventLoop);
    mainEventLoop.run();

    return 0;
}
