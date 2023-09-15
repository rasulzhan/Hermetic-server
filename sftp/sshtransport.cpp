#include "sshtransport.h"
#include <openssl/sha.h>
#include <thread>
#include <chrono>
#include "sshconst.h"
#include "sshutils.h"
#include "sshchannel.h"
#include "sshsftp.h"

#ifdef __linux__
#include <sys/ioctl.h>
#include <errno.h>
#endif

#define CHECK_RETURN(x) if( (x) <= 0) { return -1; }
#define CHECK_EXIT(x) if(x != 1) { goto exit; }
#define CHECK_NULL_EXIT(x) if(!x) { goto exit; }

// Currently MAC based on sha256
#define MAC_HASH_LENGTH SHA256_DIGEST_LENGTH

EndpointData::EndpointData()
    : kexinit(nullptr)
    , kexinit_len(0)
    , banner(nullptr)
    , banner_len(0)
    , pbkey(nullptr)
    , pbkey_len(0)
    , prvkey(nullptr)
    , prvkey_len(0)
    , mackey(nullptr)
    , mackey_len(0)
    , crypt(nullptr)
    , mac(nullptr)
    , seqno(0)
    , blocksize(16)
{
}

EndpointData::~EndpointData()
{
    if (kexinit) {
        explicit_zero(&kexinit, kexinit_len);
    }
    if (banner) {
        explicit_zero(&banner, banner_len);
    }
    if (pbkey) {
        explicit_zero(&pbkey, pbkey_len);
    }
    if (prvkey) {
        explicit_zero(&prvkey, prvkey_len);
    }
    if (mackey) {
        explicit_zero(&mackey, mackey_len);
    }
    if (crypt) {
        EVP_CIPHER_CTX_free(crypt);
    }
    if (mac) {
        HMAC_CTX_free(mac);
    }
}

SSHTransport::SSHTransport()
    : m_state(EXCH_VERSION)
    , m_session(NULL)
    , m_session_len(0)
    , m_channels(NULL)
    , m_channels_count(0)
    , m_next_channel_seqno(0)
    , m_rc(0)
    , m_username(NULL)
    , m_username_len(0)
    , m_composite(NULL)
    , m_auth_methods(AUTH_NONE)
    , m_passphrase(NULL)
    , m_privkey(NULL)
    , m_pubkey(NULL)
{
    //gLogger.Create("ssh", LogLevel::Debug1);
}

SSHTransport::~SSHTransport()
{
    if (m_session) {
        explicit_zero(&m_session, m_session_len);
    }
    for (size_t i = 0; i < m_channels_count; i++) {
        if (m_channels[i] != NULL) {
            delete m_channels[i];
            m_channels[i] = NULL;
        }
    }
    if (m_username) {
        delete[] m_username;
        m_username = nullptr;
    }
    if (m_composite) {
        delete m_composite;
        m_composite = nullptr;
    }
    if (m_passphrase) {
        explicit_zero(&m_passphrase, strlen(m_passphrase));
    }
    if (m_privkey) {
        explicit_zero(&m_privkey, strlen(m_privkey));
    }
    if (m_pubkey) {
        explicit_zero(&m_pubkey, strlen(m_pubkey));
    }
}

void SSHTransport::SetUsername(const char* data)
{
    if (m_username) {
        delete[] m_username;
    }
    size_t len = strlen(data);
    m_username = new unsigned char[len * 4];
    m_username_len = unicode_to_utf8((unsigned char*)data, len, m_username);
}

int SSHTransport::Open(const char* addr, unsigned short port /*= 22*/)
{
    m_rc = 0;
    m_state = EXCH_VERSION;

    TCPClientBoomerang::Close();
    if (!TCPClientBoomerang::Open(addr, port)) {
        return -1;
    }

#ifdef __linux__
    int mode = 1;
    if (ioctl(m_sock, FIONBIO, &mode) == -1) {
        LOGERR("Could not set the socket to non-block mode: %u", errno);
        return -1;
    }
#else
    u_long mode = 1;
    if (ioctlsocket(m_sock, FIONBIO, &mode) == SOCKET_ERROR) {
        LOGERR("Could not set the socket to non-block mode: %u", WSAGetLastError());
        return -1;
    }
#endif

    while (m_state != AUTH && m_rc == 0) {
        int read = Read();
        if (read == -1) {
            return -1;
        } else if (read == 0) {
            // we have to wait a bit till data is coming
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }
        OnRead(m_data, read);
    }
/*
    if (m_rc == 0) {
        return SetAsyncMode();
    }
*/
    return m_state == AUTH ? 1 : -1;
}

void SSHTransport::Shutdown()
{
    Disconnect(SSH_DISCONNECT_BY_APPLICATION, "Bay,bay");
    TCPClientBoomerang::Close();
}

void SSHTransport::Close(int reason)
{
    m_rc = reason;
    TCPClientBoomerang::Close();
}

void SSHTransport::OnConnect()
{
    // SSH version 2
    TCPClientBoomerang::Send((const unsigned char*)SSH_CLIENT_BANNER_CLRF, sizeof(SSH_CLIENT_BANNER_CLRF) - 1);
}

void SSHTransport::OnRead(const unsigned char* data, size_t len)
{
    size_t readed = 0;
    while (readed < len) {
        if (m_state == EXCH_VERSION) {
            for (size_t i = 0; i < len; i++) {
                readed++;
                if (data[i] == '\n' && i > 0 && data[i - 1] == '\r') {
                    m_remote.banner_len = i - 1;
                    m_remote.banner = new unsigned char[m_remote.banner_len];
                    memcpy(m_remote.banner, data, m_remote.banner_len);
                    break;
                }
            }
            if (m_remote.banner && memcmp(m_remote.banner, "SSH-2.", 6) == 0) {
                KeyExchangeInit();
                m_state = EXCH_KEYS;
            } else {
                Disconnect(SSH_DISCONNECT_PROTOCOL_VERSION_NOT_SUPPORTED, "Supported SSH-2.X");
                Close(1);
            }
        } else {
            SSHPacket packet(data + readed, len - readed);

            bool composite_process = false;
            if (m_composite) {
                LOGDBG2("Concatenating splitted packet: " PRIsize_t "/" PRIsize_t ". Incoming data length: " PRIsize_t,
                        m_composite->TotalLength(), m_composite->Size(), packet.Size());
                uint32_t copied = m_composite->Copy(packet.Data(), packet.Size());
                readed += copied;
                if (!m_composite->EoF()) {
                    if (readed < len) {
                        LOGERR("Data leak, incoming size: %u, processed size: " PRIsize_t, len, readed);
                    }
                    break;
                }
                m_composite->Swap(packet);
                delete m_composite;
                m_composite = NULL;
                composite_process = true;
            } else {
                uint32_t require_length = ExtractPacketSize(packet);
                if (require_length < 4 || require_length > MAX_SSH_PACKET_LEN) {
                    LOGERR("Extracting packet length error: %u", require_length);
                    break;
                }
                uint32_t current_length = packet.Size();
                if (require_length > current_length) {
                    LOGDBG1("Splitted packet detected %u/%u", current_length, require_length);
                    m_composite = new SSHPacket(require_length);
                    m_composite->Copy(packet.Data(), packet.Size());
                    break;
                }
            }

            if (m_state > EXCH_KEYS) {
                if (DecryptPacket(packet) != 1) {
                    // TODO Decrypt error
                    readed = len;
                    break;
                }
                packet.SetTotalLength(packet.Length() + 4 + MAC_HASH_LENGTH);
            } else {
                packet.SetTotalLength(packet.Length() + 4);
            }
            packet.SetPayloadLength();
            m_remote.seqno++;

            if (!composite_process) {
                readed += packet.TotalLength();
            }

            debug(packet.Payload(), packet.PayloadLength(), true);
            switch (packet.MessageType()) {
            case SSH_MSG_DISCONNECT:
                ProcessDisconnect(packet);
                Close(0);
                break;
            case SSH_MSG_IGNORE:
                ProcessIgnoreMessage(packet);
                continue;
            case SSH_MSG_UNIMPLEMENTED:
                ProcessUnimplementedMessage(packet);
                continue;
            case SSH_MSG_DEBUG:
                ProcessDebugMessage(packet);
                continue;
            }

            switch (m_state) {
            case EXCH_KEYS:
            {
                switch (packet.MessageType()) {
                case SSH_MSG_KEXINIT:
                    if (KeyExchangeInitReply(packet) == 1) {
                        KeyExchangeProcess();
                    } else {
                        Disconnect(SSH_DISCONNECT_KEY_EXCHANGE_FAILED);
                        Close(2);
                    }
                    break;
                case SSH_MSG_KEXDH_REPLY:
                    if (KeyExchangeProcessReply(packet) == 1) {
                        NewKeys();
                    } else {
                        Disconnect(SSH_DISCONNECT_KEY_EXCHANGE_FAILED);
                        Close(3);
                    }
                    break;
                case SSH_MSG_NEWKEYS:
                    m_state = AUTH_METHODS;
                    ServiceRequest(SSH_USERAUTH_NM);
                    break;
                default:
                    break;
                }
                //readed += packet.Length() + 4;
            }
            break;
            case AUTH_METHODS:
            {
                switch (packet.MessageType()) {
                case SSH_MSG_SERVICE_ACCEPT:
                    AuthMethods();
                    break;
                case SSH_MSG_USERAUTH_FAILURE:
                    ProcessAuthMethods(packet);
                    m_state = AUTH;
                    break;
                case SSH_MSG_USERAUTH_BANNER:
                    ProcessBanner(packet);
                    break;
                default:
                    break;
                }
                //readed += packet.TotalLength();
            }
            break;
            case AUTH:
            {
                switch (packet.MessageType()) {
                case SSH_MSG_USERAUTH_FAILURE:
                    LOGINF("Authentication failed");
                    Close(5);
                    break;
                case SSH_MSG_USERAUTH_SUCCESS:
                    LOGINF("Authentication successful");
                    m_state = DATA;
                    break;
                case SSH_MSG_USERAUTH_BANNER:
                    ProcessBanner(packet);
                    break;
                case SSH_MSG_USERAUTH_PK_OK:
                    if (ProcessPublicKeySign(packet) != 1) {
                        Disconnect(SSH_DISCONNECT_BY_APPLICATION);
                        Close(4);
                    }
                    break;
                default:
                    LOGERR("Unknown packet type: %u", (int)packet.MessageType());
                    break;
                }
                //readed += packet.TotalLength();
            }
            break;
            case DATA:
            {
                unsigned char packet_type = packet.MessageType();
                switch (packet_type) {
                case SSH_MSG_GLOBAL_REQUEST:
                    ProcessGlobalRequest(packet);
                    break;
                case SSH_MSG_REQUEST_SUCCESS:
                    LOGINF("SSH_MSG_REQUEST_SUCCESS");
                    break;
                case SSH_MSG_REQUEST_FAILURE:
                    LOGINF("SSH_MSG_REQUEST_FAILURE");
                    break;
                default:
                    if (packet_type >= SSH_MSG_CHANNEL_OPEN && packet_type <= SSH_MSG_CHANNEL_FAILURE) {
                        ForwardToChannel(packet);
                    } else {
                        LOGERR("Unknown packet type: %u", (int)packet_type);
                    }
                    break;
                }
                //readed += packet.TotalLength();
                break;
            }
            default:
                // skip
                LOGERR("Unknown ssh state: %u", (int)m_state);
                readed = len;
                break;
            }
            //m_remote.seqno++;
        }
    }
}

void SSHTransport::OnClose()
{
}

int SSHTransport::Send(SSHPacket& packet)
{
    int rc = -1;
    unsigned char mod = packet.TotalLength() % m_local.blocksize;
    unsigned char padding = mod == 0 ? m_local.blocksize : m_local.blocksize - mod;
    if (padding < 4) {
        padding += m_local.blocksize;
    }
    if (packet.TotalLength() + padding < 16) {
        padding += 16 - (unsigned char)packet.TotalLength() - padding;
    }
    packet.SetPadding(padding);
    packet.SetLength();

    if (m_state > EXCH_KEYS) {
        debug(packet.Data(), packet.TotalLength(), false);

        uint32_t seqno = ntonu32(m_local.seqno);
        unsigned char packet_mac[MAC_HASH_LENGTH] = { 0 };

        // Calculate MAC, whole unencrypted packet (include length and paddings)
        CHECK_EXIT(HMAC_CTX_reset(m_local.mac));
        CHECK_EXIT(HMAC_Init_ex(m_local.mac, m_local.mackey, m_local.mackey_len, EVP_sha256(), NULL));
        CHECK_EXIT(HMAC_Update(m_local.mac, (unsigned char*)&seqno, 4));
        CHECK_EXIT(HMAC_Update(m_local.mac, packet.Data(), packet.TotalLength()));
        CHECK_EXIT(HMAC_Final(m_local.mac, packet_mac, NULL));

        unsigned char block[EVP_MAX_BLOCK_LENGTH];
        unsigned char *p = (unsigned char*)packet.Data();

        // Encrypt whole packet (include length and paddings), without MAC
        for (size_t i = 0; i < packet.TotalLength(); i += m_local.blocksize) {
            rc = EVP_Cipher(m_local.crypt, block, p + i, m_local.blocksize);
            if (rc != 1 && rc != m_local.blocksize) {
                LOGERR("Failed on encrypting");
                return -1;
            }
            memcpy(p + i, block, m_local.blocksize);
        }
        // Add MAC to packet
        packet.SetMAC(packet_mac, sizeof(packet_mac));
    }

    TCPClientBoomerang::Send(packet.Data(), packet.TotalLength());
    m_local.seqno++;
    rc = 1;
exit:
    return rc;
}

int SSHTransport::KeyExchangeInit()
{
    SSHPacket packet;
    packet.Write((char)SSH_MSG_KEXINIT);

    // write a cookie
    for (int i = 0; i < 16; i++) {
        packet.Write((char)(rand() % 255));
    }

    // Key exchange algorithms
    // "curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group14-sha256,diffie-hellman-group14-sha1";
    packet.WriteBuf("curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521");

    // Server host key algorithms
    packet.WriteBuf("ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,ssh-ed25519");

    // Encryption algorithms
    // "aes256-ctr,aes256-cbc,rijndael-cbc@lysator.liu.se,aes192-ctr,aes192-cbc,aes128-ctr,aes128-cbc,chacha20-poly1305@openssh.com,blowfish-ctr,blowfish-cbc,3des-ctr,3des-cbc,arcfour256,arcfour128";
    packet.WriteBuf("aes128-ctr,aes192-ctr,aes256-ctr");
    packet.WriteBuf("aes128-ctr,aes192-ctr,aes256-ctr");

    // MAC algorithms
    // "hmac-sha2-256,hmac-sha1,hmac-sha1-96,hmac-md5,hmac-sha2-256-etm@openssh.com,hmac-sha1-etm@openssh.com,hmac-sha1-96-etm@openssh.com,hmac-md5-etm@openssh.com";
    packet.WriteBuf("hmac-sha2-256");
    packet.WriteBuf("hmac-sha2-256");

    // Compression
    packet.WriteBuf("none");
    packet.WriteBuf("none");

    // Languages
    packet.WriteBuf("");
    packet.WriteBuf("");

    packet.Write((char)0);      // first_kex_packet_follows
    packet.Write((uint32_t)0);  // Reserved

    m_local.kexinit_len = packet.TotalLength() - 5; // without packet length and padding length
    m_local.kexinit = new unsigned char[m_local.kexinit_len];
    memcpy(m_local.kexinit, packet.Payload(), m_local.kexinit_len);

    Send(packet);

    return 1;
}

int SSHTransport::KeyExchangeInitReply(const SSHPacket& packet)
{
    const unsigned char *data = NULL;
    uint32_t len = 0;

    m_remote.kexinit_len = packet.PayloadLength();
    m_remote.kexinit = new unsigned char[m_remote.kexinit_len];
    memcpy(m_remote.kexinit, packet.Payload(), m_remote.kexinit_len);

    unsigned char cookie[16];
    packet.ReadBuf(cookie, 16);

    // KEX algorithms
    if (packet.ReadString(&data, len)) {
        LOGDBG1("KEX algorithms: %.*s", len, data);
    }
    // server host key algorithms
    if (packet.ReadString(&data, len)) {
        LOGDBG1("Host keys algorithms: %.*s", len, data);
    }
    // encryption algorithms client to server
    if (packet.ReadString(&data, len)) {
        LOGDBG1("Encryption algorithms client to server: %.*s", len, data);
    }
    // encryption algorithms server to client
    if (packet.ReadString(&data, len)) {
        LOGDBG1("Encryption algorithms server to client: %.*s", len, data);
    }
    // mac algorithms client to server
    if (packet.ReadString(&data, len)) {
        LOGDBG1("MAC algorithms client to server: %.*s", len, data);
    }
    // mac algorithms server to client
    if (packet.ReadString(&data, len)) {
        LOGDBG1("MAC algorithms server to client: %.*s", len, data);
    }
    // compression algorithms client to server
    if (packet.ReadString(&data, len)) {
        LOGDBG1("Comression algorithms server to client: %.*s", len, data);
    }
    // compression algorithms server to client
    if (packet.ReadString(&data, len)) {
        LOGDBG1("Comression algorithms client to server: %.*s", len, data);
    }
    // languages client to server
    if (packet.ReadString(&data, len)) {
        LOGDBG1("Language client to server: %.*s", len, data);
    }
    // languages server to client
    if (packet.ReadString(&data, len)) {
        LOGDBG1("Language server to client: %.*s", len, data);
    }
    // first kex packet follows
    char first_follows;
    packet.Read(first_follows);
    LOGDBG1("First KEX packet follows: %u", len);

    return 1;
}

int SSHTransport::KeyExchangeProcess()
{
    EVP_PKEY *key = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    SSHPacket packet;
    size_t len;
    int rc = -1;

    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
    if (pctx == NULL) {
        goto exit;
    }
    if (EVP_PKEY_keygen_init(pctx) != 1 || EVP_PKEY_keygen(pctx, &key) != 1) {
        goto exit;
    }
    m_local.prvkey_len = 32;
    m_local.prvkey = new unsigned char[m_local.prvkey_len];
    len = 32;
    if (EVP_PKEY_get_raw_private_key(key, m_local.prvkey, &len) != 1) {
        goto exit;
    }
    m_local.pbkey_len = 32;
    m_local.pbkey = new unsigned char[m_local.pbkey_len];
    len = 32;
    if (EVP_PKEY_get_raw_public_key(key, m_local.pbkey, &len) != 1) {
        goto exit;
    }

    packet.Write((char)SSH_MSG_KEXDH_INIT);
    packet.WriteBuf(m_local.pbkey, m_local.pbkey_len);
    Send(packet);

    rc = 1;
exit:
    if (key) {
        EVP_PKEY_free(key);
    }
    if (pctx) {
        EVP_PKEY_CTX_free(pctx);
    }
    return rc;
}

#define CALC_KEY(X, R) \
    EVP_MD_CTX_reset(ctx); \
    EVP_DigestInit(ctx, EVP_sha256()); \
    tmp_len = ntonu32(shared_key_len); \
    EVP_DigestUpdate(ctx, &tmp_len, 4); \
    EVP_DigestUpdate(ctx, shared_key, shared_key_len); \
    EVP_DigestUpdate(ctx, m, SHA256_DIGEST_LENGTH); \
    EVP_DigestUpdate(ctx, X, 1); \
    EVP_DigestUpdate(ctx, m_session, SHA256_DIGEST_LENGTH); \
    EVP_DigestFinal(ctx, R, NULL);

int SSHTransport::KeyExchangeProcessReply(SSHPacket& packet)
{
    int rc = -1;
    EVP_MD_CTX* ctx = NULL;
    BIGNUM* k_bn = NULL;
    unsigned char* shared_key = NULL;
    const unsigned char *hostkey = NULL, *sign = NULL;
    uint32_t tmp_len = 0, m_len = 0, shared_key_len = 0, hostkey_len = 0, sign_len = 0;
    unsigned char m[32] = { 0 }, local_iv[32] = { 0 }, local_key[32] = { 0 },
        remote_iv[32] = { 0 }, remote_key[32] = { 0 };

    packet.ReadString(&hostkey, hostkey_len);

    packet.Read(m_remote.pbkey_len);
    m_remote.pbkey = new unsigned char[m_remote.pbkey_len];
    packet.ReadBuf(m_remote.pbkey, m_remote.pbkey_len);

    packet.ReadString(&sign, sign_len);

    k_bn = BN_new();
    if (curve25519_gen_k(m_local.prvkey, m_remote.pbkey, k_bn) != 1) {
        goto exit;
    }

    shared_key_len = BN_num_bytes(k_bn) + 1;
    if (BN_num_bits(k_bn) % 8) {
        /* don't need leading 00 */
        shared_key_len--;
    }
    shared_key = new unsigned char[shared_key_len];

    if (BN_num_bits(k_bn) % 8) {
        BN_bn2bin(k_bn, shared_key);
    } else {
        shared_key[0] = 0;
        BN_bn2bin(k_bn, shared_key + 1);
    }

    if (VerifySignature(shared_key, shared_key_len, hostkey, hostkey_len, sign, sign_len, m, m_len) != 1) {
        goto exit;
    }

    // set a session if haven't set yet
    if (m_session_len == 0) {
        m_session_len = m_len;
        m_session = new unsigned char[m_session_len];
        memcpy(m_session, m, m_session_len);
    }

    m_local.mackey_len = 32;
    m_local.mackey = new unsigned char[m_local.mackey_len];
    m_remote.mackey_len = 32;
    m_remote.mackey = new unsigned char[m_remote.mackey_len];

    ctx = EVP_MD_CTX_new();
    CALC_KEY("A", local_iv);
    CALC_KEY("B", remote_iv);
    CALC_KEY("C", local_key);
    CALC_KEY("D", remote_key);
    CALC_KEY("E", m_local.mackey);
    CALC_KEY("F", m_remote.mackey);

    m_local.crypt = EVP_CIPHER_CTX_new();
    rc = EVP_CipherInit(m_local.crypt, EVP_aes_128_ctr(), local_key, local_iv, 1);
    m_local.blocksize = 16; // aes_128_ctr

    m_remote.crypt = EVP_CIPHER_CTX_new();
    rc = EVP_CipherInit(m_remote.crypt, EVP_aes_128_ctr(), remote_key, remote_iv, 0);
    m_remote.blocksize = 16; // aes_128_ctr

    m_local.mac = HMAC_CTX_new();
    m_remote.mac = HMAC_CTX_new();

    rc = 1;

exit:
    if (ctx) {
        EVP_MD_CTX_free(ctx);
    }
    if (k_bn) {
        BN_free(k_bn);
    }
    if (shared_key) {
        explicit_zero(&shared_key, shared_key_len);
    }
    if (m_local.pbkey) {
        explicit_zero(&m_local.pbkey, m_local.pbkey_len);
        m_local.pbkey_len = 0;
    }
    if (m_local.prvkey) {
        explicit_zero(&m_local.prvkey, m_local.prvkey_len);
        m_local.prvkey_len = 0;
    }
    if (m_remote.pbkey) {
        explicit_zero(&m_remote.pbkey, m_remote.pbkey_len);
        m_remote.pbkey_len = 0;
    }

    memset(local_iv,   0, sizeof(local_iv));
    memset(remote_iv,  0, sizeof(remote_iv));
    memset(local_key,  0, sizeof(local_key));
    memset(remote_key, 0, sizeof(remote_key));

    return rc;
}

int SSHTransport::VerifySignature(
    const unsigned char* shared_key, unsigned int shared_key_len,
    const unsigned char* hostkey, unsigned int hostkey_len,
    const unsigned char* sign, unsigned int sign_len,
    unsigned char* out_hash, unsigned int& out_hash_len)
{
    int rc = -1;
    uint32_t tmp_len = 0;
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        goto exit;
    }
    CHECK_EXIT(EVP_DigestInit_ex(ctx, EVP_sha256(), NULL));

    tmp_len = ntonu32(strlen(SSH_CLIENT_BANNER));
    CHECK_EXIT(EVP_DigestUpdate(ctx, &tmp_len, 4));
    CHECK_EXIT(EVP_DigestUpdate(ctx, SSH_CLIENT_BANNER, strlen(SSH_CLIENT_BANNER)));

    tmp_len = ntonu32(m_remote.banner_len);
    CHECK_EXIT(EVP_DigestUpdate(ctx, &tmp_len, 4));
    CHECK_EXIT(EVP_DigestUpdate(ctx, m_remote.banner, m_remote.banner_len));

    tmp_len = ntonu32(m_local.kexinit_len);
    CHECK_EXIT(EVP_DigestUpdate(ctx, &tmp_len, 4));
    CHECK_EXIT(EVP_DigestUpdate(ctx, m_local.kexinit, m_local.kexinit_len));

    tmp_len = ntonu32(m_remote.kexinit_len);
    CHECK_EXIT(EVP_DigestUpdate(ctx, &tmp_len, 4));
    CHECK_EXIT(EVP_DigestUpdate(ctx, m_remote.kexinit, m_remote.kexinit_len));

    tmp_len = ntonu32(hostkey_len);
    CHECK_EXIT(EVP_DigestUpdate(ctx, &tmp_len, 4));
    CHECK_EXIT(EVP_DigestUpdate(ctx, hostkey, hostkey_len));

    tmp_len = ntonu32(m_local.pbkey_len);
    CHECK_EXIT(EVP_DigestUpdate(ctx, &tmp_len, 4));
    CHECK_EXIT(EVP_DigestUpdate(ctx, m_local.pbkey, m_local.pbkey_len));

    tmp_len = ntonu32(m_remote.pbkey_len);
    CHECK_EXIT(EVP_DigestUpdate(ctx, &tmp_len, 4));
    CHECK_EXIT(EVP_DigestUpdate(ctx, m_remote.pbkey, m_remote.pbkey_len));

    tmp_len = ntonu32(shared_key_len);
    CHECK_EXIT(EVP_DigestUpdate(ctx, &tmp_len, 4));
    CHECK_EXIT(EVP_DigestUpdate(ctx, shared_key, shared_key_len));
    CHECK_EXIT(EVP_DigestFinal_ex(ctx, out_hash, &out_hash_len));

    CHECK_EXIT(nistp_sign_verify(hostkey, hostkey_len, sign, sign_len, out_hash, out_hash_len));

    rc = 1;
exit:
    if (ctx) {
        EVP_MD_CTX_free(ctx);
    }
    return rc;
}

int SSHTransport::NewKeys()
{
    SSHPacket packet;
    packet.Write((char)SSH_MSG_NEWKEYS);
    return Send(packet);
}

int SSHTransport::ServiceRequest(const char* request)
{
    SSHPacket packet;
    packet.Write((char)SSH_MSG_SERVICE_REQUEST);
    packet.WriteBuf(request);
    return Send(packet);
}

int SSHTransport::DecryptPacket(SSHPacket& packet)
{
    unsigned char block[EVP_MAX_BLOCK_LENGTH] = { 0 };
    int rc = 0;

    size_t packet_len = packet.Length() + 4; // 4 bytes packet length itself

    // Decrypt whole packet, start from second block - first one we've already decrypted

    unsigned char *p = (unsigned char *)packet.Data();
    for (size_t i = m_remote.blocksize; i < packet_len; i += m_remote.blocksize) {
        rc = EVP_Cipher(m_remote.crypt, block, p + i, m_remote.blocksize);
        if (rc != 1 && rc != m_remote.blocksize) {
            LOGERR("Failed on decrypting");
            rc = -1;
            break;
        }
        memcpy(p + i, block, m_remote.blocksize);
    }

    // Verify MAC of packet
    unsigned char hash[HMAC_MAX_MD_CBLOCK] = { 0 };
    uint32_t seqno = ntonu32(m_remote.seqno);
    uint32_t hash_len = 0;

    CHECK_RETURN(HMAC_Init_ex(m_remote.mac, m_remote.mackey, m_remote.mackey_len, EVP_sha256(), NULL));
    CHECK_RETURN(HMAC_Update(m_remote.mac, (unsigned char*)&seqno, 4));
    CHECK_RETURN(HMAC_Update(m_remote.mac, p, packet_len));
    CHECK_RETURN(HMAC_Final(m_remote.mac, hash, &hash_len));
    if (hash_len != MAC_HASH_LENGTH) {
        LOGERR("MAC hash has unexpected size: %u", hash_len);
        return -1;
    }

    if (memcmp(p + packet_len, hash, MAC_HASH_LENGTH) == 0) {
        //packet.SetTotalLength(packet_len + MAC_HASH_LENGTH);
        return 1;
    }

    LOGERR("Could not verify packet's MAC");
    return -1;
}

uint32_t SSHTransport::ExtractPacketSize(SSHPacket& packet)
{
    uint32_t len = 0;
    if (m_state > EXCH_KEYS) { // Encrypted packet
        unsigned char block[EVP_MAX_BLOCK_LENGTH] = { 0 };
        // Decrypt packet length
        int rc = EVP_Cipher(m_remote.crypt, block, packet.Data(), m_remote.blocksize);
        if (rc != 1 && rc != m_remote.blocksize) {
            return -1;
        }
        memcpy((unsigned char*)packet.Data(), block, m_remote.blocksize);
        len += MAC_HASH_LENGTH; // MAC size
    }
    len += packet.Length() + 4; // 4 bytes packet length itself
    return len;
}

int SSHTransport::ProcessDisconnect(const SSHPacket& packet)
{
    const unsigned char *msg, *lng;
    uint32_t msg_len, lang_len, reason_code;
    packet.Read(reason_code);
    packet.ReadString(&msg, msg_len);
    packet.ReadString(&lng, lang_len);

    LOGINF("Disconnect message: %u", reason_code);
    if (msg) {
        LOGINF("%.*s", msg_len, msg);
    }

    return 1;
}

int SSHTransport::ProcessIgnoreMessage(const SSHPacket& packet)
{
    const unsigned char *data = NULL;
    uint32_t datalen = 0;
    packet.ReadString(&data, datalen);
    LOGINF("Ignore message recieved. len: %u", datalen);

    return 1;
}

int SSHTransport::ProcessUnimplementedMessage(const SSHPacket& packet)
{
    uint32_t seqno = 0;
    packet.Read(seqno);
    LOGINF("Unimplemented message recieved for seqno: %u", seqno);

    return 1;
}

int SSHTransport::AuthMethods()
{
    SSHPacket packet;

    packet.Write((char)SSH_MSG_USERAUTH_REQUEST);
    packet.WriteBuf(m_username, m_username_len);
    packet.WriteBuf(SSH_CONNECTION_NM);
    packet.WriteBuf("none");

    Send(packet);
    return 1;
}

int SSHTransport::ProcessAuthMethods(const SSHPacket& packet)
{
    uint32_t len;
    packet.Read(len);
    char *str = new char[len + 1];
    packet.ReadBuf((unsigned char*)str, len);
    str[len] = 0;

    m_auth_methods = AUTH_NONE;
    if (strstr(str, "publickey") != NULL) {
        m_auth_methods = (SSH_AUTH_METHOD)(m_auth_methods | AUTH_PBKEY);
    }
    if (strstr(str, "password") != NULL) {
        m_auth_methods = (SSH_AUTH_METHOD)(m_auth_methods | AUTH_PWD);
    }
    delete[] str;
    str = nullptr;

    return m_auth_methods;
}

int SSHTransport::ProcessGlobalRequest(const SSHPacket& packet)
{
    uint32_t len = 0;
    unsigned char want_reply = 0;
    const unsigned char* req_name = NULL;
    packet.ReadString(&req_name, len);
    packet.Read(want_reply);

    LOGINF("Recieved a global request: name: %.*s, reply: %u", len, req_name, (int)want_reply);

    if (want_reply != 0) {
        // client should reply
        // SSH_MSG_REQUEST_SUCCESS or SSH_MSG_REQUEST_FAILURE
    }

    return 1;
}

int SSHTransport::ProcessBanner(const SSHPacket& packet)
{
    uint32_t len;
    const unsigned char *msg_utf8 = NULL;
    if (packet.ReadString(&msg_utf8, len)) {
        LOGINF("Banner:\n%.*s", len, msg_utf8);
    }
    return 1;
}

SSHChannel* SSHTransport::OpenChannel(const char* type)
{
    SSHChannel* channel = AllocChannel(type);
    if (channel) {
        channel->OpenChannel(type);
        if (channel->WaitForResponse() != 1) {
            return NULL;
        }
    }
    return channel;
}

int SSHTransport::CloseChannel(SSHChannel* channel)
{
    if (channel) {
        if (channel->Opened()) {
            channel->CloseChannel();
        }
        FreeChannel(channel);
    }
    return 1;
}

int SSHTransport::Disconnect(uint32_t reason, const char* description)
{
    SSHPacket packet;

    if (description == NULL) {
        description = "";
    }

    packet.Write((char)SSH_MSG_DISCONNECT);
    packet.Write(reason);
    packet.WriteBuf(description);
    packet.WriteBuf(""); // lang

    Send(packet);

    return 1;
}

SSHChannel* SSHTransport::AllocChannel(const char* type)
{
    SSHChannel* res = NULL;
    if (strcmp(type, "sftp") == 0) {
        res = new SSHSFTP(m_next_channel_seqno++, this);
    } else {
        res = new SSHChannel(m_next_channel_seqno++, this);
    }
    if (m_channels) {
        for (size_t i = 0; i < m_channels_count; i++) {
            if (m_channels[i] == NULL) {
                m_channels[i] = res;
                return res;
            }
        }
    }
    size_t new_count = m_channels_count == 0 ? 2 : m_channels_count * 2;
    SSHChannel** tmp = new SSHChannel*[new_count];
    memset(tmp, 0, sizeof(SSHChannel*) * new_count);
    if (m_channels) {
        memcpy(tmp, m_channels, m_channels_count);
        delete[] m_channels;
        m_channels = nullptr;
    }
    m_channels = tmp;
    m_channels[m_channels_count] = res;
    m_channels_count = new_count;

    return res;
}

void SSHTransport::FreeChannel(SSHChannel* channel)
{
    for (size_t i = 0; i < m_channels_count; i++) {
        if (m_channels[i] == channel) {
            delete m_channels[i];
            m_channels[i] = NULL;
            break;
        }
    }
}

int SSHTransport::ForwardToChannel(const SSHPacket& packet)
{
    // TODO add std::mutex
    uint32_t channel_id = 0;
    packet.Read(channel_id);

    if (m_channels) {
        for (size_t i = 0; i < m_channels_count; i++) {
            if (m_channels[i] != NULL && m_channels[i]->ID() == channel_id) {
                m_channels[i]->ProcessPacket(packet);
                return 1;
            }
        }
    }
    LOGINF("Received unknown channel ID: %u", channel_id);

    return -1;
}

bool SSHTransport::IsPublicKeyAuthAvailable()
{
    return m_auth_methods & AUTH_PBKEY;

}
bool SSHTransport::IsPasswordAuthAvailable()
{
    return m_auth_methods & AUTH_PWD;
}

int SSHTransport::Auth()
{
    while (m_state != DATA && m_rc == 0) {
        int read = TCPClientBoomerang::Read();
        if (read == -1) {
            return -1;
        } else if (read == 0) {
            // we have to wait a bit till data is coming
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }
        OnRead(m_data, read);
    }
    if (m_rc == 0) {
        return TCPClientBoomerang::SetAsyncMode();
    }
    return -1;
}

int SSHTransport::AuthByPublicKey(const char* pubkey, const char* privkey, const char* passphrase)
{
    if (!(m_auth_methods & AUTH_PBKEY) || pubkey == NULL || privkey == NULL) {
        return -1;
    }

    if (!passphrase) {
        passphrase = "";
    }

    size_t pubkey_len = 0;
    unsigned char *pubkey_data = NULL;
    if (read_publickey(pubkey, &pubkey_data, pubkey_len) != 1) {
        return -1;
    }
    // TODO
    // generate pub key from private key if does not provided

    uint32_t algo_name_len = ntonu32(pubkey_data);
    unsigned char *algo_name = pubkey_data + 4;

    SSHPacket packet;
    packet.Write((char)SSH_MSG_USERAUTH_REQUEST);
    packet.WriteBuf(m_username, m_username_len);
    packet.WriteBuf(SSH_CONNECTION_NM);
    packet.WriteBuf("publickey");
    packet.Write((char)0);
    packet.WriteBuf(algo_name, algo_name_len);
    packet.WriteBuf(pubkey_data, pubkey_len);

    Send(packet);

    if (pubkey_data) {
        explicit_zero(&pubkey_data, pubkey_len);
    }
    if (m_privkey) {
        explicit_zero(&m_privkey, strlen(m_privkey));
    }
    if (m_pubkey) {
        explicit_zero(&m_pubkey, strlen(m_pubkey));
    }
    if (m_passphrase) {
        explicit_zero(&m_passphrase, strlen(m_passphrase));
    }

    uint32_t len = strlen(privkey);
    m_privkey = new char[len + 1];
    memcpy(m_privkey, privkey, len);
    m_privkey[len] = 0;

    len = strlen(pubkey);
    m_pubkey = new char[len + 1];
    memcpy(m_pubkey, pubkey, len);
    m_pubkey[len] = 0;

    len = strlen(passphrase);
    if (len) {
        m_passphrase = new char[len + 1];
        memcpy(m_passphrase, passphrase, len);
        m_passphrase[len] = 0;
    }

    return Auth();
}

int SSHTransport::AuthByPassword(const char* password)
{
    if (!(m_auth_methods & AUTH_PWD)) {
        return -1;
    }

    size_t len = strlen(password);
    unsigned char* pwd_utf8 = new unsigned char[len * 4];
    size_t pwd_len = unicode_to_utf8((unsigned char*)password, len, pwd_utf8);

    SSHPacket packet;
    packet.Write((char)SSH_MSG_USERAUTH_REQUEST);
    packet.WriteBuf(m_username, m_username_len);
    packet.WriteBuf(SSH_CONNECTION_NM);
    packet.WriteBuf("password");
    packet.Write((char)0);
    packet.WriteBuf(pwd_utf8, pwd_len);

    Send(packet);

    if (pwd_utf8) {
        explicit_zero(&pwd_utf8, pwd_len);
    }

    return Auth();
}

int SSHTransport::ProcessPublicKeySign(const SSHPacket& packet)
{
    int rc = -1;
    uint32_t algo_name_len, method_name_len;
    const unsigned char *algo_name = NULL;
    unsigned char *sign = NULL, *pubkey_data = NULL, *sign_data = NULL, *method_name, *p = NULL;
    size_t sign_len = 0, pubkey_len = 0, sign_data_len = 0;
    SSHPacket pktout;

    packet.ReadString(&algo_name, algo_name_len);

    if (strncmp((char*)algo_name, "ssh-rsa", 7) != 0) {
        LOGERR("Unsupported algorithm: %s. Currently only ssh-rsa is supported.", algo_name);
        goto exit;
    }

    if (read_publickey(m_pubkey, &pubkey_data, pubkey_len) != 1) {
        return -1;
    }

    method_name_len = ntonu32(pubkey_data);
    method_name = pubkey_data + 4;

    pktout.Write((char)SSH_MSG_USERAUTH_REQUEST);
    pktout.WriteBuf(m_username, m_username_len);
    pktout.WriteBuf(SSH_CONNECTION_NM);
    pktout.WriteBuf("publickey");
    pktout.Write((char)1);
    pktout.WriteBuf(method_name, method_name_len);
    pktout.WriteBuf(pubkey_data, pubkey_len);

    sign_data_len = 4 + m_session_len + pktout.PayloadLength();
    sign_data = p = new unsigned char[sign_data_len];
    htonu32(p, m_session_len);
    p += 4;
    memcpy(p, m_session, m_session_len);
    p += m_session_len;
    memcpy(p, pktout.Payload(), pktout.PayloadLength());

    if (sign_rsa_privatekey(m_privkey, m_passphrase, sign_data, sign_data_len, &sign, sign_len) != 1) {
        LOGERR("Could not sign private key: %s", m_privkey);
        goto exit;
    }

    pktout.Write(4 + method_name_len + 4 + sign_len);
    pktout.WriteBuf(method_name, method_name_len);
    pktout.WriteBuf(sign, sign_len);
    Send(pktout);

    rc = 1;
exit:
    if (m_privkey) {
        explicit_zero(&m_privkey, strlen(m_privkey));
    }
    if (m_passphrase) {
        explicit_zero(&m_passphrase, strlen(m_passphrase));
    }
    if (pubkey_data) {
        explicit_zero(&pubkey_data, pubkey_len);
    }
    if (sign_data) {
        explicit_zero(&sign_data, sign_data_len);
    }
    if (sign) {
        explicit_zero(&sign, sign_len);
    }
    return rc;
}

int SSHTransport::ProcessDebugMessage(const SSHPacket& packet)
{
    char always_display;
    const unsigned char *msg, *lng;
    uint32_t msg_len, lang_len;

    packet.Read(always_display);
    packet.ReadString(&msg, msg_len);
    packet.ReadString(&lng, lang_len);

    if (msg) {
        LOGINF("Debug message: %.*s", msg_len, msg);
    }

    return 1;
}

void SSHTransport::InitLog(const char *path, SSHLogLevel lvl)
{
    gSSHLogger.Create(path, lvl);
}

bool IsChannelValid(SSHTransport *transport, SSHChannel *channel)
{
    if (transport == NULL || channel == NULL) {
        return false;
    }
    for (size_t i = 0; i < transport->m_channels_count; i++) {
        if (transport->m_channels[i] == channel) {
            return true;
        }
    }
    return false;
}
