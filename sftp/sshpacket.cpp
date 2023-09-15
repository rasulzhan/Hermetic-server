#include "sshpacket.h"
#include <string.h>
#include <cstdlib>
#include <algorithm>
#include "sshconst.h"

DataStream::DataStream(): m_buf(nullptr), m_wpos(0), m_rpos(0), m_size(0), m_ref(false)
{
}

DataStream::~DataStream()
{
    if (!m_ref && m_buf) {
        delete[] m_buf;
        m_buf == nullptr;
    }
}

void DataStream::Realloc(size_t new_size/*=1024*/)
{
    new_size += m_size;
    unsigned char* tmp = new unsigned char[new_size];
    memset(tmp, 0, new_size);
    if (m_buf != nullptr) {
        memcpy(tmp, m_buf, m_size);
        delete[] m_buf;
    }
    m_buf = tmp;
    m_size = new_size;
}

void DataStream::WriteBuf(const char* value)
{
    WriteBuf((unsigned char*)value, strlen(value));
}

void DataStream::WriteBuf(const unsigned char* value, uint32_t len)
{
    while (m_wpos + sizeof(len) + len > m_size) {
        Realloc();
    }
    uint32_t data_len = ntonu32(len);
    memcpy(m_buf + m_wpos, &data_len, sizeof(data_len));
    m_wpos += sizeof(data_len);

    if (len > 0) {
        memcpy(m_buf + m_wpos, value, len);
        m_wpos += len;
    }
}

const unsigned char* DataStream::Data() const
{
    return m_buf;
}
const unsigned char* DataStream::RPos() const
{
    return m_buf + m_rpos;
}
const unsigned char* DataStream::WPos() const
{
    return m_buf + m_wpos;
}

size_t DataStream::TotalLength() const
{
    return m_buf == nullptr ? 0 : m_wpos;
}

size_t DataStream::Size() const
{
    return m_size;
}

uint32_t DataStream::Copy(const unsigned char* data, uint32_t len)
{
    uint32_t written = std::min(m_size - m_wpos, (size_t)len);
    memcpy(m_buf + m_wpos, data, written);
    m_wpos += written;
    return written;
}

bool DataStream::EoF() const
{
    return m_size == m_wpos;
}

void DataStream::Swap(DataStream& stream)
{
    unsigned char*  tmp_buf  = m_buf;
    size_t          tmp_wpos = m_wpos;
    size_t          tmp_rpos = m_rpos;
    size_t          tmp_size = m_size;
    bool            tmp_ref  = m_ref;

    m_buf  = stream.m_buf;
    m_wpos = stream.m_wpos;
    m_rpos = stream.m_rpos;
    m_size = stream.m_size;
    m_ref  = stream.m_ref;

    stream.m_buf  = tmp_buf;
    stream.m_wpos = tmp_wpos;
    stream.m_rpos = tmp_rpos;
    stream.m_size = tmp_size;
    stream.m_ref  = tmp_ref;
}

///////////////
// SSHPacket //
///////////////
SSHPacket::SSHPacket()
{
    m_rpos = PAYLOAD_OFFEST + 1;
    m_wpos = PAYLOAD_OFFEST;
}

SSHPacket::SSHPacket(size_t len)
{
    m_payload_size = 0;
    m_size = len;
    m_rpos = PAYLOAD_OFFEST + 1;
    m_wpos = 0;
    m_buf = new unsigned char[m_size];
    m_ref = false;
}

SSHPacket::SSHPacket(const unsigned char* buf, size_t len)
{
    m_payload_size = 0;
    m_size = len;
    m_rpos = PAYLOAD_OFFEST + 1;
    m_wpos = len;
    m_buf = (unsigned char*)buf;
    m_ref = true;
    //m_buf = new unsigned char[m_size];
    //memcpy(m_buf, buf, m_size);
}

const unsigned char* SSHPacket::ReadBuf(unsigned char* value, uint32_t len) const
{
    if (m_rpos >= m_payload_size + PAYLOAD_OFFEST) {
        return 0;
    }
    if (m_rpos + len > m_payload_size + PAYLOAD_OFFEST) {
        len = m_payload_size + PAYLOAD_OFFEST - m_rpos;
    }
    memcpy(value, m_buf + m_rpos, len);
    m_rpos += len;
    return value;
}

const unsigned char* SSHPacket::ReadString(const unsigned char **value, uint32_t& len) const
{
    len = 0;
    if (value == NULL || m_rpos + sizeof(uint32_t) > m_payload_size + PAYLOAD_OFFEST) {
        return NULL;
    }
    *value = NULL;
    len = ntonu32(m_buf + m_rpos);
    m_rpos += 4;
    if (len == 0 || m_rpos + len > m_payload_size + PAYLOAD_OFFEST) {
        return NULL;
    }
    *value = m_buf + m_rpos;
    m_rpos += len;
    return *value;
}

const unsigned char* SSHPacket::Payload() const
{
    return m_buf == nullptr ? nullptr : m_buf + PAYLOAD_OFFEST;
}

size_t SSHPacket::PayloadLength() const
{
    if (m_payload_size == 0) {
        if (m_wpos > PAYLOAD_OFFEST) {
            return m_wpos - PAYLOAD_OFFEST;
        }
    }
    return m_payload_size;
}

bool SSHPacket::PayloadEOF() const
{
    return m_rpos >= PAYLOAD_OFFEST + m_payload_size;
}

void SSHPacket::SetPayloadLength()
{
    m_payload_size = Length() - 1 - m_buf[4];
}

void SSHPacket::SetTotalLength(size_t value)
{
    if (value <= m_size) {
        m_wpos = value;
    }
}

void SSHPacket::SetPadding(unsigned char value)
{
    if (!m_buf || m_wpos + value > m_size) {
        Realloc();
    }
    *(m_buf + 4) = value;

    for (int j = 0; j < value; j++) {
        *(m_buf + m_wpos++) = rand() % 255 + 1;
    }
}

void SSHPacket::SetLength()
{
    if (!m_buf) {
        Realloc();
    }
    uint32_t len = ntonu32(m_wpos - sizeof(uint32_t));
    memcpy(m_buf, &len, sizeof(len));
}

size_t SSHPacket::Length() const
{
    if (m_size > MSG_ID_OFFEST) {
        return ntonu32(m_buf);
    }
    return 0;
}

void SSHPacket::SetMAC(const unsigned char* mac, uint32_t len)
{
    while (m_wpos + len > m_size) {
        Realloc();
    }
    memcpy(m_buf + m_wpos, mac, len);
    m_wpos += len;
}

unsigned char SSHPacket::MessageType() const
{
    return m_size > MSG_ID_OFFEST ? m_buf[MSG_ID_OFFEST] : SSH_MSG_INVALID_VALUE;
}


//////////////
// FXPacket //
//////////////

FXPacket::FXPacket()
{
    m_wpos = 4;
}

FXPacket::FXPacket(uint32_t len)
{
    m_buf = new unsigned char[len];
    memset(m_buf, 0, len);
    m_rpos = 0;
    m_wpos = 0;
    m_size = len;
    m_ref = false;
}

FXPacket::FXPacket(const SSHPacket& packet)
{
    m_buf = (unsigned char*)packet.Payload() + 9;
    m_rpos = 0;
    m_wpos = packet.PayloadLength() - 9;
    m_size = m_wpos;
    m_ref = true;
}

void FXPacket::SetLength()
{
    if (!m_buf) {
        Realloc();
    }
    uint32_t len = ntonu32(m_wpos - sizeof(uint32_t));
    memcpy(m_buf, &len, sizeof(len));
}

uint32_t FXPacket::RequestID() const
{
    if (m_size > MSG_ID_OFFEST) {
        return ntonu32(m_buf + 5);
    }
    return 0;
}

uint32_t FXPacket::Length() const
{
    if (m_size > MSG_ID_OFFEST) {
        return ntonu32(m_buf);
    }
    return 0;
}

int FXPacket::ReadBuf(unsigned char* value, uint32_t len) const
{
    if (m_rpos >= m_wpos) {
        return 0;
    }
    if (m_rpos + len > m_wpos) {
        len = m_wpos - m_rpos;
    }
    memcpy(value, m_buf + m_rpos, len);
    m_rpos += len;
    return len;
}

const unsigned char* FXPacket::ReadString(const unsigned char **value, uint32_t& len) const
{
    if (value == NULL || m_rpos + sizeof(uint32_t) >= m_wpos) {
        return NULL;
    }
    *value = NULL;
    len = ntonu32(m_buf + m_rpos);
    m_rpos += 4;
    if (len == 0 || m_rpos + len >= m_wpos) {
        return NULL;
    }
    *value = m_buf + m_rpos;
    m_rpos += len;
    return *value;
}