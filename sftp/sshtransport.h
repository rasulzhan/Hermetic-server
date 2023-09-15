#pragma once

#include "tcpclient_bom.h"
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include "sshchannel.h"
#include "sshpacket.h"
#include "sshlog.h"

enum SSH_STAGE {
    EXCH_VERSION,
    EXCH_KEYS,
    AUTH,
    AUTH_METHODS,
    DATA
};

enum SSH_AUTH_METHOD {
    AUTH_NONE   = 0,
    AUTH_PBKEY  = 1,
    AUTH_PWD    = 2
};

#define SSH_CLIENT_BANNER           "SSH-2.0-Client release 1.0"
#define SSH_CLIENT_BANNER_CLRF      SSH_CLIENT_BANNER "\r\n"
#define SSH_USERAUTH_NM             "ssh-userauth"
#define SSH_USERAUTH_NM_LEN         12
#define SSH_CONNECTION_NM           "ssh-connection"
#define SSH_CONNECTION_NM_LEN       14

struct EndpointData
{
    EndpointData();
    ~EndpointData();

    unsigned char*  kexinit;
    uint32_t        kexinit_len;
    unsigned char*  banner;
    uint32_t        banner_len;
    unsigned char*  pbkey;
    uint32_t        pbkey_len;
    unsigned char*  prvkey;
    uint32_t        prvkey_len;
    unsigned char*  mackey;
    uint32_t        mackey_len;
    EVP_CIPHER_CTX* crypt;
    HMAC_CTX*       mac;
    uint32_t        seqno;
    unsigned char   blocksize;
};

class SSHTransport : public TCPClientBoomerang
{
    friend class SSHChannel;
    friend bool IsChannelValid(SSHTransport*, SSHChannel*);

public:
    SSHTransport();
    virtual ~SSHTransport();

    int Open(const char* addr, unsigned short port = 22);
    void Shutdown();

    SSHChannel* OpenChannel(const char* type);
    int CloseChannel(SSHChannel* channel);

    void SetUsername(const char* data);

    bool IsPublicKeyAuthAvailable();
    bool IsPasswordAuthAvailable();

    int AuthByPublicKey(const char* pubkey, const char* privkey, const char* passphrase);
    int AuthByPassword(const char* data);

    void InitLog(const char *path, SSHLogLevel lvl);

protected:
    virtual void OnConnect() override;
    virtual void OnRead(const unsigned char* data, size_t len) override;
    virtual void OnClose() override;

    int Auth();
    int KeyExchangeInit();
    int KeyExchangeInitReply(const SSHPacket& packet);
    int KeyExchangeProcess();
    int KeyExchangeProcessReply(/*const*/ SSHPacket& packet);
    int NewKeys();
    int ServiceRequest(const char* request);
    int AuthMethods();
    int ProcessDisconnect(const SSHPacket& packet);
    int ProcessIgnoreMessage(const SSHPacket& packet);
    int ProcessDebugMessage(const SSHPacket& packet);
    int ProcessUnimplementedMessage(const SSHPacket& packet);
    int ProcessAuthMethods(const SSHPacket& packet);
    int ProcessGlobalRequest(const SSHPacket& packet);
    int ProcessBanner(const SSHPacket& packet);
    int ProcessPublicKeySign(const SSHPacket& packet);
    int Disconnect(uint32_t reason, const char* description = NULL);

    int VerifySignature(const unsigned char* shared_key, unsigned int shared_key_len,
        const unsigned char* hostkey, unsigned int hostkey_len,
        const unsigned char* sign, unsigned int sign_len,
        unsigned char* out_hash, unsigned int& out_hash_len);

    int Send(SSHPacket& packet);

    void Close(int reason);

    SSHChannel* AllocChannel(const char* type);
    void FreeChannel(SSHChannel* channel);
    int ForwardToChannel(const SSHPacket& packet);

    uint32_t ExtractPacketSize(SSHPacket& packet);
    int DecryptPacket(SSHPacket& packet);

private:
    SSH_STAGE       m_state;

    EndpointData    m_local;
    EndpointData    m_remote;

    unsigned char*  m_session;
    uint32_t        m_session_len;

    SSHChannel**    m_channels;
    uint32_t        m_channels_count;
    uint32_t        m_next_channel_seqno;

    int             m_rc;

    unsigned char*  m_username;
    uint32_t        m_username_len;

    SSHPacket*      m_composite;
    SSH_AUTH_METHOD m_auth_methods;

    char*           m_passphrase;
    char*           m_privkey;
    char*           m_pubkey;
};

bool IsChannelValid(SSHTransport *transport, SSHChannel *channel);
