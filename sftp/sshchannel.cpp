#include "sshchannel.h"
#include "sshtransport.h"
#include "sshconst.h"
#include "sshlog.h"

SSHChannel::SSHChannel(uint32_t id, SSHTransport* ssh_trnsp)
    : m_id(id)
    , m_remote_id(-1)
    , m_ssh_trnsp(ssh_trnsp)
    , m_remote_wnd_size(0)
    , m_remote_packet_size(0)
    , m_local_wnd_size(102400)
    , m_signal(false)
    , m_rc(0)
{
}

SSHChannel::~SSHChannel()
{
    m_ssh_trnsp = NULL;
}

uint32_t SSHChannel::RemoteID()
{
    return m_remote_id;
}

uint32_t SSHChannel::ID()
{
    return m_id;
}

bool SSHChannel::Opened()
{
    return m_remote_id != (size_t)(-1);
}

int SSHChannel::Send(SSHPacket& packet)
{
    m_rc = -1;
    m_ssh_trnsp->Send(packet);
    return 1;
}

int SSHChannel::ProcessPacket(const SSHPacket& packet)
{
    m_local_wnd_size -= packet.PayloadLength();
    if (m_local_wnd_size < 32768) {
        WindowAdjust();
    }

    switch (packet.MessageType()) {
    case SSH_MSG_CHANNEL_REQUEST:
        ProcessRequest(packet);
        OnRequest(packet);
        break;
    case SSH_MSG_CHANNEL_OPEN_CONFIRMATION:
        ProcessOpenConfirm(packet);
        OnOpenConfirm(packet);
        break;
    case SSH_MSG_CHANNEL_OPEN_FAILURE:
        ProcessOpenFailure(packet);
        OnOpenFailure(packet);
        break;
    case SSH_MSG_CHANNEL_WINDOW_ADJUST:
        OnWindowAdjust(packet);
        break;
    case SSH_MSG_CHANNEL_DATA:
        LOGINF("Channel[%d] Incoming data", m_id);
        OnData(packet);
        break;
    case SSH_MSG_CHANNEL_EXTENDED_DATA:
        OnExtData(packet);
        break;
    case SSH_MSG_CHANNEL_EOF:
        LOGINF("Channel[%d] End of file", m_id);
        OnEOF(packet);
        break;
    case SSH_MSG_CHANNEL_CLOSE:
        LOGERR("Channel[%d] Close", m_id);
        m_remote_id = -1;
        OnClose(packet);
        break;
    case SSH_MSG_CHANNEL_SUCCESS:
        LOGINF("Channel[%d] Success", m_id);
        OnSuccess(packet);
        break;
    case SSH_MSG_CHANNEL_FAILURE:
        LOGERR("Channel[%d] Failure", m_id);
        OnFailure(packet);
        break;
    default:
        LOGERR("Channel[%d] Unknown packet type: %d", m_id, (int)packet.MessageType());
        return -1;
        break;
    }
    return 1;
}

int SSHChannel::OpenChannel(const char* type)
{
    SSHPacket packet;

    packet.Write((char)SSH_MSG_CHANNEL_OPEN);
    packet.WriteBuf(type);
    packet.Write(m_id);
    packet.Write(m_local_wnd_size);
    packet.Write((uint32_t)MAX_SSH_PACKET_LEN);

    Send(packet);

    return 1;
}

int SSHChannel::CloseChannel()
{
    SSHPacket packet;

    packet.Write((char)SSH_MSG_CHANNEL_CLOSE);
    packet.Write(m_remote_id);

    Send(packet);

    m_remote_id = -1;

    return 1;
}

int SSHChannel::ChannelEOF()
{
    SSHPacket packet;

    packet.Write((char)SSH_MSG_CHANNEL_EOF);
    packet.Write(m_remote_id);

    Send(packet);

    return 1;
}

int SSHChannel::WindowAdjust()
{
    SSHPacket packet;

    m_local_wnd_size += 1024000;
    packet.Write((char)SSH_MSG_CHANNEL_WINDOW_ADJUST);
    packet.Write(m_remote_id);
    packet.Write(m_local_wnd_size);

    LOGINF("Channel[%d] Local window adjust: %u", m_id, m_local_wnd_size);

    Send(packet);

    return 1;
}


int SSHChannel::ProcessOpenConfirm(const SSHPacket& packet)
{
    packet.Read(m_remote_id);
    packet.Read(m_remote_wnd_size);
    packet.Read(m_remote_packet_size);

    LOGINF("Channel[%d] Opened: id: %u/%u, wnd size: %u, packet size: %u",
        m_id, m_id, m_remote_id, m_remote_wnd_size, m_remote_packet_size);

    m_rc = 1;
    return 1;
}

int SSHChannel::ProcessOpenFailure(const SSHPacket& packet)
{
    uint32_t rc = 0, rc_len = 0;
    const unsigned char *rc_descr = NULL;
    packet.Read(rc);
    LOGERR("Open channel failure: rc: %u", rc);
    if (packet.ReadString(&rc_descr, rc_len) && rc_descr) {
        LOGERR("Open channel failure message: %.*s", rc_len, rc_descr);
    }

    m_rc = -1;
    return 1;
}

int SSHChannel::ProcessRequest(const SSHPacket& packet)
{
    uint32_t len = 0;
    unsigned char want_reply = 0;
    const unsigned char* req_type = NULL;
    packet.ReadString(&req_type, len);
    packet.Read(want_reply);

    LOGINF("Channel[%d] Recieved a request: type: %.*s, reply: %u", m_id, len, req_type, (int)want_reply);

    if (want_reply != 0) {
        // client should reply
        // SSH_MSG_CHANNEL_SUCCESS or SSH_MSG_CHANNEL_FAILURE
    }

    return 1;
}

int SSHChannel::OnRequest(const SSHPacket& packet)
{
    return 1;
}
int SSHChannel::OnOpenConfirm(const SSHPacket& packet)
{
    m_rc = 1;
    SignalEvent();
    return 1;
}
int SSHChannel::OnOpenFailure(const SSHPacket& packet)
{
    m_rc = -1;
    SignalEvent();
    return 1;
}
int SSHChannel::OnWindowAdjust(const SSHPacket& packet)
{
    uint32_t bytes_to_add;
    packet.Read(bytes_to_add);
    m_remote_wnd_size += bytes_to_add;
    LOGINF("Channel[%d] Remote window adjust: %u", m_id, m_remote_wnd_size);
    return 1;
}
int SSHChannel::OnData(const SSHPacket& packet)
{
    uint32_t len = 0;
    const unsigned char *data = NULL;
    if (packet.ReadString(&data, len)) {
        LOGINF("Channel[%d] Incoming data length:%u", m_id, len);
        LOGDBG2("Channel[%d] Data: %.*s", m_id, len, data);
    }
    SignalEvent();
    return 1;
}
int SSHChannel::OnExtData(const SSHPacket& packet)
{
    m_rc = -1;
    const unsigned char* message = NULL;
    uint32_t data_type_code, str_len;
    
    packet.Read(data_type_code);
    packet.ReadString(&message, str_len);

    LOGINF("Channel[%d] Ext Data, type code: %u, message: %.*s", m_id, data_type_code, str_len, message);

    return 1;
}
int SSHChannel::OnEOF(const SSHPacket& packet)
{
    SignalEvent();
    return 1;
}
int SSHChannel::OnClose(const SSHPacket& packet)
{
    SignalEvent();
    return 1;
}
int SSHChannel::OnSuccess(const SSHPacket& packet)
{
    m_rc = 1;
    SignalEvent();
    return 1;
}
int SSHChannel::OnFailure(const SSHPacket& packet)
{
    m_rc = -1;
    SignalEvent();
    return 1;
}

int SSHChannel::WaitForResponse()
{
    std::unique_lock<std::mutex> lock(m_lock);
    m_signal = false;
    while (!m_signal) {
        if (m_cbevent.wait_for(lock, std::chrono::seconds(10)) == std::cv_status::timeout) {
            LOGERR("Channel[%d] Response timeout", m_id);
            return SSH_CHANNEL_ERROR_TIMEOUT;
        }
    }
    return m_rc;
}

void SSHChannel::SignalEvent()
{
    std::unique_lock<std::mutex> lock(m_lock);
    m_signal = true;
    m_cbevent.notify_one();
}

int SSHChannel::Exec(const char* command)
{
    m_rc = -1;
    SSHPacket packet;

    packet.Write((char)SSH_MSG_CHANNEL_REQUEST);
    packet.Write(m_remote_id);
    packet.WriteBuf("exec");
    packet.Write((char)1);
    packet.WriteBuf(command);

    Send(packet);

    WaitForResponse();

    return 1;
}

int SSHChannel::RequestPseudoTerminal(const char* terminal)
{
    m_rc = -1;
    SSHPacket packet;

    packet.Write((char)SSH_MSG_CHANNEL_REQUEST);
    packet.Write(m_remote_id);
    packet.WriteBuf("pty-req");
    packet.Write((char)1);
    packet.WriteBuf(terminal);
    packet.Write((uint32_t)120);    // terminal width, characters
    packet.Write((uint32_t)50);     // terminal height, rows
    packet.Write((uint32_t)0);      // terminal width, pixels
    packet.Write((uint32_t)0);      // terminal height, pixels
    packet.WriteBuf("");            // encoded terminal modes

    Send(packet);

    return WaitForResponse();
}

int SSHChannel::OpenShell()
{
    m_rc = -1;
    SSHPacket packet;

    packet.Write((char)SSH_MSG_CHANNEL_REQUEST);
    packet.Write(m_remote_id);
    packet.WriteBuf("shell");
    packet.Write((char)1);

    Send(packet);

    return WaitForResponse();
}

int SSHChannel::SendData(const char* data)
{
    m_rc = -1;
    SSHPacket packet;

    packet.Write((char)SSH_MSG_CHANNEL_DATA);
    packet.Write(m_remote_id);
    packet.WriteBuf(data);

    Send(packet);

    return WaitForResponse();
}
