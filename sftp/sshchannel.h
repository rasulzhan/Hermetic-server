#ifndef __SSH_CHANNEL_H__
#define __SSH_CHANNEL_H__

#include <stdint.h>
#include <mutex>
#include <condition_variable>
#include "sshpacket.h"

class SSHTransport;

class SSHChannel
{
    friend class SSHTransport;
public:
    SSHChannel(uint32_t id, SSHTransport* trnsp);
    virtual ~SSHChannel();

    uint32_t RemoteID();
    uint32_t ID();

    bool Opened();

    int Exec(const char* command);

    int RequestPseudoTerminal(const char* terminal);
    int OpenShell();
    int SendData(const char* data);

protected:
    virtual int OpenChannel(const char* type);
    virtual int CloseChannel();

    virtual int OnRequest(const SSHPacket& packet);
    virtual int OnOpenConfirm(const SSHPacket& packet);
    virtual int OnOpenFailure(const SSHPacket& packet);
    virtual int OnWindowAdjust(const SSHPacket& packet);
    virtual int OnData(const SSHPacket& packet);
    virtual int OnExtData(const SSHPacket& packet);
    virtual int OnEOF(const SSHPacket& packet);
    virtual int OnClose(const SSHPacket& packet);
    virtual int OnSuccess(const SSHPacket& packet);
    virtual int OnFailure(const SSHPacket& packet);

protected:
    int Send(SSHPacket& packet);
    int ProcessPacket(const SSHPacket& packet);

    int ProcessOpenConfirm(const SSHPacket& packet);
    int ProcessOpenFailure(const SSHPacket& packet);
    int ProcessRequest(const SSHPacket& packet);

    int ChannelEOF();
    int WindowAdjust();

    int WaitForResponse();
    void SignalEvent();

protected:
    uint32_t        m_id;
    uint32_t        m_remote_id;
    SSHTransport*   m_ssh_trnsp;
    uint32_t        m_remote_wnd_size;
    uint32_t        m_remote_packet_size;
    uint32_t        m_local_wnd_size;
    std::mutex      m_lock;
    std::condition_variable  m_cbevent;
    bool            m_signal;
    int             m_rc;
};

#endif // __SSH_CHANNEL_H__
