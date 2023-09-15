#include "sshsftp.h"
#include <cstdio>
#include <cstring>
#include "sshconst.h"
#include "sshlog.h"

SSHSFTP::SSHSFTP(uint32_t id, SSHTransport *owner)
    : SSHChannel(id, owner)
    , m_state(SFTP_NONE)
    , m_reqid(0)
    , m_handles(NULL)
    , m_handles_count(0)
    , m_composite(NULL)
    , m_data(NULL)
{
}

SSHSFTP::~SSHSFTP()
{
    FreeHandles();
    if (m_composite) {
        delete m_composite;
        m_composite = nullptr;
    }
}

int SSHSFTP::Send(FXPacket& packet)
{
    packet.SetLength();

    SSHPacket out;
    out.Write((char)SSH_MSG_CHANNEL_DATA);
    out.Write(m_remote_id);
    out.WriteBuf(packet.Data(), packet.TotalLength());

    return SSHChannel::Send(out);
}

int SSHSFTP::OpenChannel(const char* type)
{
    return SSHChannel::OpenChannel("session");
}

int SSHSFTP::OnOpenConfirm(const SSHPacket& packet)
{
    SSHPacket out;

    out.Write((char)SSH_MSG_CHANNEL_REQUEST);
    out.Write(m_remote_id);
    out.WriteBuf("subsystem");
    out.Write((char)1);  // want to get an answer
    out.WriteBuf("sftp");

    SSHChannel::Send(out);

    m_state = SFTP_OPEN;

    return 1;
}

int SSHSFTP::OnSuccess(const SSHPacket& packet)
{
    if (m_state == SFTP_OPEN) {
        FXPacket out;
        out.Write((char)SSH_FXP_INIT);
        out.Write((uint32_t)3);     // Version 3
    
        Send(out);
        m_state = SFTP_INIT;
    }
    return 1;
}

int SSHSFTP::OnFailure(const SSHPacket& packet)
{
    if (m_state == SFTP_OPEN) {
        m_rc = -1;
        SignalEvent();
    }
    return 1;
}

int SSHSFTP::OnData(const SSHPacket& packet)
{
    uint32_t channel_pck_len, fx_pck_len;

    packet.Read(channel_pck_len);
    if (m_composite) {
        LOGDBG2("SFTP[%u] Concatenating splitted packet " PRIsize_t "/" PRIsize_t ". Incoming packet length: %u", m_id, m_composite->TotalLength(), m_composite->Size(), channel_pck_len);
        m_composite->Copy(packet.RPos(), channel_pck_len);
    } else {
        packet.Read(fx_pck_len);
        if (channel_pck_len - 4 != fx_pck_len) {
            LOGDBG1("SFTP[%u] Splitted packet detected. Packet length: %u, FX packet length: %u", m_id, channel_pck_len, fx_pck_len);
            m_composite = new FXPacket(fx_pck_len + 4);
            m_composite->Copy(packet.RPos() - 4, channel_pck_len);
        }
    }

    if (m_composite) {
        if (m_composite->EoF()) {
            ProcessData(*m_composite);
            delete m_composite;
            m_composite = NULL;
        } else {     
            // waiting for the next part
            return 1;
        }
    } else {
        const FXPacket fxpacket(packet);
        ProcessData(fxpacket);
    }

    SignalEvent();

    return 1;
}

SSH_FILE_HANDLE* SSHSFTP::OpenFile(const char* file, uint32_t access)
{
    SSH_FILE_HANDLE* result = NULL;
    FXPacket packet;

    LOGINF("SFTP[%d] Open file: %s (access: %u)", m_id, file, access);

    packet.Write((char)SSH_FXP_OPEN);
    packet.Write(m_reqid++);

    size_t len = strlen(file) * 4;
    unsigned char* file_utf8 = new unsigned char[len];
    len = unicode_to_utf8((unsigned char*)file, strlen(file), file_utf8);
    packet.WriteBuf(file_utf8, len);
    delete[] file_utf8;
    file_utf8 = nullptr;

    packet.Write(access);   // access
    packet.Write((uint32_t)SSH_FILEXFER_ATTR_PERMISSIONS); // flags
    packet.Write((uint32_t)(S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)); // attr

    Send(packet);
    if (WaitForResponse() == SSH_FX_OK) {
        result = (SSH_FILE_HANDLE*)m_data;
    }

    return result;
}

SSH_FILE_HANDLE* SSHSFTP::OpenDir(const char* path)
{
    SSH_FILE_HANDLE* result = NULL;
    FXPacket packet;

    LOGINF("SFTP[%d] Open folder: %s", m_id, path);

    packet.Write((char)SSH_FXP_OPENDIR);
    packet.Write(m_reqid++);

    size_t len = strlen(path) * 4;
    unsigned char* path_utf8 = new unsigned char[len];
    len = unicode_to_utf8((unsigned char*)path, strlen(path), path_utf8);
    packet.WriteBuf(path_utf8, len);
    delete[] path_utf8;
    path_utf8 = nullptr;

    Send(packet);
    if (WaitForResponse() == SSH_FX_OK) {
        result = (SSH_FILE_HANDLE*)m_data;
    }

    return result;
}

int SSHSFTP::ReadDir(SSH_FILE_HANDLE* handle, unsigned char **data, uint32_t data_size)
{
    if (!handle) {
        return -1;
    }

    LOGINF("SFTP[%d] Read folder, handle: %p", m_id, (void*)handle);

    int result = -1;
    m_buf.len = 0;
    m_buf.size = data_size;
    m_buf.data = *data;
    FXPacket packet;

    packet.Write((char)SSH_FXP_READDIR);
    packet.Write(m_reqid++);
    packet.WriteBuf(handle->handle, handle->handle_len);

    Send(packet);
    result = WaitForResponse();
    if (result == SSH_FX_OK) {
        result = m_buf.len;
    } else if (result == SSH_FX_EOF) {
        result = 0;
    }
    return result;
}

int SSHSFTP::GetFileAttrs(SSH_FILE_HANDLE* handle)
{
    if (!handle) {
        return -1;
    }
    int result = -1;
    FXPacket packet;

    packet.Write((char)SSH_FXP_FSTAT);
    packet.Write(m_reqid++);
    packet.WriteBuf(handle->handle, handle->handle_len);

    packet.Write((uint32_t)(SSH_FILEXFER_ATTR_SIZE | SSH_FILEXFER_ATTR_ALLOCATION_SIZE | SSH_FILEXFER_ATTR_PERMISSIONS));

    m_data = handle;

    Send(packet);
    if (WaitForResponse() == SSH_FX_OK) {
        result = 1;
    }

    return result;
}

int SSHSFTP::Write(SSH_FILE_HANDLE* handle, uint64_t offset, unsigned char* data, uint32_t data_size)
{
    if (!handle) {
        return -1;
    }

    LOGINF("SFTP[%d] Write, handle: %p, size: %u, offset: %llu", m_id, (void*)handle, data_size, offset);

    int result = -1;
    FXPacket packet;

    packet.Write((char)SSH_FXP_WRITE);
    packet.Write(m_reqid++);
    packet.WriteBuf(handle->handle, handle->handle_len);
    packet.Write(offset);
    packet.WriteBuf(data, data_size);

    Send(packet);
    result = WaitForResponse();
    if (result == SSH_FX_OK) {
        result = 1;
    }
    return result;
}

int SSHSFTP::Read(SSH_FILE_HANDLE* handle, uint64_t offset, unsigned char **data, uint32_t data_size)
{
    if (!handle) {
        return -1;
    }

    LOGINF("SFTP[%d] Read, handle: %p, offset: %llu", m_id, (void*)handle, offset);

    int result = -1;
    m_buf.len = 0;
    m_buf.size = data_size;
    m_buf.data = *data;
    FXPacket packet;

    packet.Write((char)SSH_FXP_READ);
    packet.Write(m_reqid++);
    packet.WriteBuf(handle->handle, handle->handle_len);
    packet.Write(offset);
    packet.Write(data_size);

    Send(packet);
    result = WaitForResponse();
    if (result == SSH_FX_OK) {
        result = m_buf.len;
    } else if (result == SSH_FX_EOF) {
        result = 0;
    }
    return result;
}

int SSHSFTP::CloseHandle(SSH_FILE_HANDLE* handle)
{
    if (!handle) {
        return 1;
    }

    LOGINF("SFTP[%d] Close handle: %p", m_id, (void*)handle);

    int result = -1;
    FXPacket packet;

    packet.Write((char)SSH_FXP_CLOSE);
    packet.Write(m_reqid++);
    packet.WriteBuf(handle->handle, handle->handle_len);

    Send(packet);
    FreeHandle(handle);

    result = WaitForResponse();
    if (result == SSH_FX_OK) {
        result = 1;
    }
    return result;
}

SSH_FILE_HANDLE* SSHSFTP::AllocHandle()
{
    std::lock_guard<std::mutex> lock(m_handles_lock);
    SSH_FILE_HANDLE* res = NULL;
    if (m_handles) {
        for (size_t i = 0; i < m_handles_count; i++) {
            if (m_handles[i] == NULL) {
                res = new SSH_FILE_HANDLE;
                m_handles[i] = res;
                break;
            }
        }
    }
    if (res == NULL) {
        size_t new_count = m_handles_count == 0 ? 32 : m_handles_count * 2;
        SSH_FILE_HANDLE** tmp = new SSH_FILE_HANDLE*[new_count];
        memset(tmp, 0, sizeof(SSH_FILE_HANDLE*) * new_count);
        if (m_handles) {
            memcpy(tmp, m_handles, m_handles_count);
            delete[] m_handles;
        }
        res = new SSH_FILE_HANDLE;
        m_handles = tmp;
        m_handles[m_handles_count] = res;
        m_handles_count = new_count;
    }
    return res;
}

void SSHSFTP::FreeHandle(SSH_FILE_HANDLE* handle)
{
    std::lock_guard<std::mutex> lock(m_handles_lock);
    for (size_t i = 0; i < m_handles_count; i++) {
        if (m_handles[i] == handle) {
            delete m_handles[i];
            m_handles[i] = NULL;
            break;
        }
    }
}

void SSHSFTP::FreeHandles()
{
    std::lock_guard<std::mutex> lock(m_handles_lock);
    for (size_t i = 0; i < m_handles_count; i++) {
        if (m_handles[i] != NULL) {
            delete m_handles[i];
            m_handles[i] = NULL;
        }
    }
    if (m_handles) {
        delete[] m_handles;
        m_handles = nullptr;
    }
    m_handles_count = 0;
}

int SSHSFTP::ProcessData(const FXPacket& packet)
{
    uint32_t fx_pck_len;
    packet.Read(fx_pck_len);

    char type;
    packet.Read(type);

    switch (m_state) {
    case SFTP_INIT:
    {
        if (type == SSH_FXP_VERSION) {
            uint32_t sftp_version, len, ext_name_len, ext_val_len;

            packet.Read(sftp_version);
            LOGINF("SFTP[%d] Version %u", m_id, sftp_version);
            
            // read extensions
            const unsigned char *ext_name = NULL, *ext_val = NULL;
            len = sizeof(type) + sizeof(sftp_version);                 
            while (fx_pck_len > len) {
                packet.Read(ext_name_len);
                packet.ReadString(&ext_name, ext_name_len);
                packet.Read(ext_val_len);
                packet.ReadString(&ext_val, ext_val_len);
                if (ext_name && ext_val) {
                    LOGINF("SFTP[%d] Extension: %.*s = %.*s", m_id, ext_name_len, ext_name, ext_val_len, ext_val);
                }
                len += 4 + ext_name_len + 4 + ext_val_len;
            }
            m_state = SFTP_PROCESS;
            m_rc = 1;
        } else {
            LOGERR("SFTP[%d] Unexpected FX packet type %u", m_id, (int)type);
            m_rc = -1;
        }
    }
    break;
    case SFTP_PROCESS:
    {
        uint32_t req_id;
        packet.Read(req_id);

        if (req_id != m_reqid - 1) {
            LOGERR("SFTP[%d] Unexpected request ID: %u. Expected %u", m_id, req_id, m_reqid - 1);
            break;
        }

        switch (type) {
        case SSH_FXP_HANDLE:
        {
            SSH_FILE_HANDLE* handle = AllocHandle();
            packet.Read(handle->handle_len);
            packet.ReadBuf(handle->handle, handle->handle_len);

            LOGINF("SFTP[%d] New handle: %p, length %u", m_id, (void*)handle, handle->handle_len);

            m_data = handle;
            m_rc = SSH_FX_OK;
        }
        break;
        case SSH_FXP_STATUS:
        {
            uint32_t status_code, msg_len;

            packet.Read(status_code);
            const unsigned char *msg = NULL;
            packet.ReadString(&msg, msg_len);

            LOGINF("SFTP[%d] Status: %u, '%.*s'", m_id, status_code, msg_len, msg);

            m_rc = status_code;
        }
        break;
        case SSH_FXP_ATTRS:
        {
            SSH_FILE_HANDLE* handle = (SSH_FILE_HANDLE*)m_data;
            uint32_t mask;
            packet.Read(mask);
            if (mask & SSH_FILEXFER_ATTR_SIZE) {
                packet.Read(handle->size);
            }
            if (mask & 0x02 /*ALLOCATION_SIZE*/) {
                packet.Read(handle->allocation_size);
            }
            if (mask & SSH_FILEXFER_ATTR_PERMISSIONS) {
                uint32_t size;
                packet.Read(size);
            }

            LOGINF("SFTP[%d] Attributes, handle: %p", m_id, (void*)handle);

            m_rc = SSH_FX_OK;
        }
        break;
        case SSH_FXP_NAME:
        {
            const unsigned char *path = NULL, *data = NULL;
            uint32_t count, len, attr_mask, value32;
            uint64_t value64;

            LOGINF("SFTP[%d] Terminal", m_id);

            m_buf.len = 0;

            packet.Read(count);
            for (uint32_t i = 0; i < count; i++) {
                packet.ReadString(&path, len);
                /*
                if (m_buf.data && m_buf.size - m_buf.len > (int32_t)(len + 1)) {
                    memcpy((void*)(m_buf.data + m_buf.len), (void*)path, len);
                    m_buf.data[m_buf.len + len] = 0;
                }
                m_buf.len += len + 1;
                */

                packet.ReadString(&data, len);                
                if (data) {
                    LOGDBG1("SFTP[%d] %.*s", m_id, len, data);
                    if (m_buf.data && m_buf.size - m_buf.len > (int32_t)(len + 1)) {
                        memcpy((void*)(m_buf.data + m_buf.len), (void*)data, len);
                    }
                }
                m_buf.data[m_buf.len + len] = ',';
                m_buf.len += len + 1;
                //
                packet.Read(attr_mask);
                if (attr_mask & SSH_FILEXFER_ATTR_SIZE) {
                    packet.Read(value64);
                }
                if (attr_mask & 0x02 /*ALLOCATION_SIZE*/) {
                    packet.Read(value64);
                }
                if (attr_mask & SSH_FILEXFER_ATTR_PERMISSIONS) {
                    packet.Read(value32);
                }
                if (attr_mask & SSH_FILEXFER_ATTR_ACCESSTIME) {
                    packet.Read(value64);
                }
                if (attr_mask & SSH_FILEXFER_ATTR_CREATETIME) {
                    packet.Read(value64);
                }
                if (attr_mask & SSH_FILEXFER_ATTR_MODIFYTIME) {
                    packet.Read(value64);
                }
            }
            m_buf.data[m_buf.len] = 0;
            if (!packet.EoF()) {
                char endlist = 0;
                packet.Read(endlist);
            }

            m_rc = SSH_FX_OK;
        }
        break;
        case SSH_FXP_DATA:
        {
            uint32_t len;
            //unsigned char eof = 0;
            packet.Read(len);
            m_buf.len = len > m_buf.size ? m_buf.size : len;
            packet.ReadBuf(m_buf.data, m_buf.len);
            //if (!packet.EoF()) {
            //    packet.Read(eof);
            //}

            LOGINF("SFTP[%d] Read data, size: %u", m_id, len);

            m_rc = SSH_FX_OK;
            break;
        }
        default:
            LOGERR("SFTP[%d] Unknown FX packet type %u", m_id, (int)type);
            break;
        }
    }
    break;
    default:
        break;
    }

    return 1;
}

bool IsSFTPHandleValid(SSHSFTP *sftp, SSH_FILE_HANDLE *handle)
{
    if (sftp == NULL || handle == NULL) {
        return false;
    }
    std::lock_guard<std::mutex> lock(sftp->m_handles_lock);
    for (size_t i = 0; i < sftp->m_handles_count; i++) {
        if (sftp->m_handles[i] == handle) {
            return true;
        }
    }
    return false;
}
