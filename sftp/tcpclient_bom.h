#ifndef __SSH_TCPCLIENT_H__
#define __SSH_TCPCLIENT_H__

#include <thread>

#if defined(WIN32) || defined(_WIN32) || defined(__WIN32__) || defined(__NT__)

#include <winsock2.h>
#include <ws2tcpip.h>

#define _WINDOWS_

#elif __APPLE__
#elif __linux__

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define INVALID_SOCKET -1
#define INVALID_HANDLE_VALUE -1
#define SOCKET_ERROR -1

#else
#   error "Unknown compiler"
#endif

class TCPClientBoomerang
{
public:
    TCPClientBoomerang();
    virtual ~TCPClientBoomerang();

    TCPClientBoomerang(const TCPClientBoomerang& src) = delete;
    TCPClientBoomerang& operator=(const TCPClientBoomerang& src) = delete;

    bool Open(const char* addr, unsigned short port);
    void Close();

protected:
    static void ThreadWrapper(void *param) {
        TCPClientBoomerang* tcp = (TCPClientBoomerang*)param;
        tcp->EventHandler();
    }
    void EventHandler();
    int Send(const unsigned char* data, size_t len);
    int Read();
    int SetAsyncMode();

    virtual void OnConnect() = 0;
    virtual void OnRead(const unsigned char* data, size_t len) = 0;
    virtual void OnClose() = 0;

    void Realloc(size_t new_size = 1024);

    void debug(const unsigned char* data, size_t len, bool direction);

protected:
    unsigned char*  m_data;

#if defined(_WINDOWS_)
    SOCKET          m_sock;
#else
    int             m_sock;
#endif

private:

#if defined(_WINDOWS_)
    HANDLE          m_wsavent;
#else
    int             m_wsavent;
#endif

    std::thread     m_thr;
    size_t          m_size;
    unsigned char*  m_debug;
    size_t          m_debugsize;
};

#endif // __SSH_TCPCLIENT_H__
