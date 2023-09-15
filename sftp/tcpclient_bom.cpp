#include "tcpclient_bom.h"
#include "sshlog.h"
#include <cstring>

#define MAX_TCP_PACKET_SIZE 102400

#if defined(_WINDOWS_)
#include <ws2tcpip.h>
#define GET_LAST_ERROR WSAGetLastError()
#elif __linux__
#include <unistd.h>
#include <poll.h>
#include <arpa/inet.h>
#define GET_LAST_ERROR errno
#endif

TCPClientBoomerang::TCPClientBoomerang()
    : m_data(NULL)
    , m_sock(INVALID_SOCKET)
    , m_wsavent(INVALID_HANDLE_VALUE)
    , m_size(0)
    , m_debug(NULL)
    , m_debugsize(0)
{
}

TCPClientBoomerang::~TCPClientBoomerang()
{
    Close();
    if (m_data) {
        delete[] m_data;
    }
    m_data = nullptr;
    if (m_debug) {
        delete[] m_debug;
    }
    m_debug = nullptr;
}

bool TCPClientBoomerang::Open(const char* addr, unsigned short port)
{
    int rc = 0;
    sockaddr_in sin = { 0 };

#if defined(_WINDOWS_)
    WSADATA wsData;
    rc = WSAStartup(MAKEWORD(2,0), &wsData);
    if (rc != NOERROR) {
        LOGERR("WSAStartup failed: %u", rc);
        goto fail;
    }
#endif

    m_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (m_sock == INVALID_SOCKET) {
        LOGERR("Create socket failed: %u", GET_LAST_ERROR);
        goto fail;
    }

    sin.sin_family = AF_INET;
    sin.sin_port = htons(port);
    rc = inet_pton(AF_INET, addr, &sin.sin_addr.s_addr);
    if (rc != 1) {
        LOGERR("InetPton failed: %u:%u", GET_LAST_ERROR, rc);
        goto fail;
    }

    rc = connect(m_sock, (const struct sockaddr*)&sin, sizeof(sin));
    if (rc == -1) {
        LOGERR("TCP: Could not connect to %s:%d, error: %u", addr, port, GET_LAST_ERROR);
        goto fail;
    }

    LOGINF("TCP: Connected %s:%d", addr, port);

    OnConnect();
    return true;

fail:
    Close();
    return false;
}

void TCPClientBoomerang::Close()
{
#if defined(_WINDOWS_)
    if (m_wsavent != INVALID_HANDLE_VALUE) {
        WSACloseEvent(m_wsavent);
        m_wsavent = INVALID_HANDLE_VALUE;
    }
#endif
    if (m_sock != INVALID_SOCKET) {
#if defined(_WINDOWS_)
        shutdown(m_sock, SD_BOTH);
        closesocket(m_sock);
#elif __linux__
        shutdown(m_sock, SHUT_RDWR);
        close(m_sock);
#endif
        m_sock = INVALID_SOCKET;
    }
    if (m_thr.joinable()) {
        m_thr.join();
    }
}

int TCPClientBoomerang::Send(const unsigned char* data, size_t len)
{
    debug(data, len, false);

    int rc = send(m_sock, (const char*)data, len, 0);
    if (rc == SOCKET_ERROR) {
        LOGERR("TCP: Send error: %u", GET_LAST_ERROR);
    }
    return rc;
}


void TCPClientBoomerang::EventHandler()
{
    LOGINF("EventHandler stared");

#if defined(_WINDOWS_)
    // TODO add support WSAPool
    DWORD rc = 0;
    WSANETWORKEVENTS net_events = { 0 };

    m_wsavent = WSACreateEvent();
    if (m_wsavent == INVALID_HANDLE_VALUE) {
        LOGERR("Could not create a WSAEvent: %u", GET_LAST_ERROR);
        return;
    }
    rc = WSAEventSelect(m_sock, m_wsavent, FD_READ | /*FD_WRITE | FD_CONNECT |*/ FD_CLOSE);
    if (rc != NOERROR) {
        LOGERR("WSAEventSelect Failed: %u : %u", GET_LAST_ERROR, rc);
        return;
    }

    while (m_sock != INVALID_SOCKET) {
        rc = WSAWaitForMultipleEvents(1, &m_wsavent, TRUE, 1000, FALSE);
        if (rc == WSA_WAIT_TIMEOUT) {
            continue;
        }
        if (rc != WSA_WAIT_EVENT_0) {
            LOGERR("EventHandler error: %u", rc);
            continue;
        }

        net_events = { 0 };
        rc = WSAEnumNetworkEvents(m_sock, m_wsavent, &net_events);
        if (rc != NOERROR) {
            LOGERR("WSAEnumNetworkEvents error: %u", GET_LAST_ERROR);
        }
        if (net_events.lNetworkEvents & FD_CONNECT) {
            LOGINF("TCP: Connected");
            OnConnect();
        }
        if (net_events.lNetworkEvents & FD_READ) {
            int read = Read();
            if (read > 0) {
                debug(m_data, read, true);
                OnRead(m_data, read);
            }
        }
        if (net_events.lNetworkEvents & FD_WRITE) {
        }
        if (net_events.lNetworkEvents & FD_CLOSE) {
            LOGINF("TCP: Connection closed");
            OnClose();
            break;
        }
    }

    if (m_wsavent != INVALID_HANDLE_VALUE) {
        WSACloseEvent(m_wsavent);
        m_wsavent = INVALID_HANDLE_VALUE;
    }

#elif __linux__
    struct pollfd fds[1];

    fds[0].fd = m_sock;
    fds[0].events = POLLIN | POLLERR | POLLHUP | POLLNVAL;

    while (m_sock != INVALID_SOCKET) {
        int rc = poll(fds, 1, 1000);
        if (rc == -1) {
            LOGERR("EventHandler error: %u", errno);
            continue;
        }
        if (rc == 0) {
            // timeout
            continue;
        }
        if (fds[0].revents & POLLIN) {
            int read = Read();
            if (read > 0) {
                debug(m_data, read, true);
                OnRead(m_data, read);
            }
        }
        if ((fds[0].revents & POLLERR) || (fds[0].revents & POLLHUP) || (fds[0].revents & POLLNVAL)) {
            LOGINF("TCP: Connection closed (revents:%u), error: %u", fds[0].revents, errno);
            OnClose();
            break;
        }
        fds[0].revents = 0;
    }
#endif

    if (m_sock != INVALID_SOCKET) {
#if defined(_WINDOWS_)
        shutdown(m_sock, SD_BOTH);
        closesocket(m_sock);
#elif __linux__
        shutdown(m_sock, SHUT_RDWR);
        close(m_sock);
#endif
        m_sock = INVALID_SOCKET;
    }

    LOGINF("EventHandler finished");
}

void TCPClientBoomerang::Realloc(size_t new_size/*=1024*/)
{
    new_size += m_size;
    unsigned char* tmp = new unsigned char[new_size];
    memset(tmp, 0, new_size);
    if (m_data) {
        memcpy(tmp, m_data, m_size);
        delete[] m_data;
    }
    m_data = tmp;
    m_size = new_size;
}

void TCPClientBoomerang::debug(const unsigned char* data, size_t len, bool direction)
{
    if (gSSHLogger.GetLogLvl() < SSHLogLevel::Debug3) {
        return;
    }

    unsigned int  mod = len % 16;
    unsigned int  lines = len / 16 + (mod > 0 ? 1 : 0);
    unsigned int  buf_size = 80 * lines + 80;
    if (m_debugsize < buf_size) {
        if (m_debug) {
            delete[] m_debug;
        }
        m_debug = new unsigned char[buf_size];
        m_debugsize = buf_size;
    }
    unsigned char* p = m_debug;

    int written = 0;
    if (direction) {
        written = snprintf((char*)p, buf_size, "Incoming raw packet, length: %lu\n", len);
    } else {
        written = snprintf((char*)p, buf_size, "Outcoming raw packet, length: %lu\n", len);
    }
    p += written; buf_size -= written;
    for (unsigned int i = 0; i < lines; i++) {
        snprintf((char*)p, buf_size, "0x%.4x  ", i * 16);
        p += 8; buf_size -= 8;
        for (unsigned int  j = 0; j < 16; j++) {
            if (j > 0 && (j % 8) == 0) {
                snprintf((char*)p++, buf_size--, " ");
            }
            unsigned int  index = i * 16 + j;
            if (index >= len) {
                snprintf((char*)p, buf_size, "   ");
            } else {
                snprintf((char*)p, buf_size, "%.2x ", data[index]);
            }
            p += 3; buf_size -= 3;
        }
        snprintf((char*)p++, buf_size--, " ");
        for (unsigned int  j = 0; j < 16; j++) {
            unsigned int  index = i * 16 + j;
            if (index >= len) {
                break;
            }
            if (j > 0 && (j % 8) == 0) {
                snprintf((char*)p++, buf_size--, " ");
            }
            snprintf((char*)p++, buf_size--, "%c", isprint(data[index]) != 0 ? data[index] : '.');
        }
        snprintf((char*)p, buf_size, "\n");
        p += 1; buf_size -= 1;
    }
    *p = 0;
    LOGDBG3("%s", m_debug);
}

int TCPClientBoomerang::Read()
{
    int total_read = 0;
    int read = 0;
    do {
        if (total_read == (int)m_size) {
            Realloc();
        }
        read = recv(m_sock, (char*)(m_data + total_read), m_size - total_read, 0);
        int err = GET_LAST_ERROR;
        if (read == SOCKET_ERROR &&
#if defined(_WINDOWS_)
            err != WSAEWOULDBLOCK)
#elif __linux__
            err != EWOULDBLOCK)
#endif
        {
            LOGERR("TCP: Recv error: %u", err);
            total_read = -1;
            break;
        } else if (read == 0) {
            LOGINF("TCP: Conenction has been closed");
            // total_read = -1;
            OnClose();
            Close();
            break;
        } else if (read > 0) {
            total_read += read;
        }
    } while (read > 0 && total_read < MAX_TCP_PACKET_SIZE);

    return total_read;
}

int TCPClientBoomerang::SetAsyncMode()
{
    m_thr = std::thread(ThreadWrapper, this);
    return 1;
}
