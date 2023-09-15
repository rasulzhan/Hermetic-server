#ifndef __SSH_PACKET_H__
#define __SSH_PACKET_H__

#include <cstring>
#include "utils.h"

#define PAYLOAD_OFFEST 5
#define MSG_ID_OFFEST 5

class DataStream
{
public:
    DataStream();
    virtual ~DataStream();

    template<typename T>
    void Write(T value)
    {
        while (m_wpos + sizeof(value) > m_size) {
            Realloc();
        }
        if (sizeof(value) > 4) {
            value = ntonu64(value);
        } else if (sizeof(value) > 2) {
            value = ntonu32(value);
        }
        memcpy(m_buf + m_wpos, &value, sizeof(value));
        m_wpos += sizeof(value);
    }

    void WriteBuf(const char* value);
    void WriteBuf(const unsigned char* value, uint32_t len);

    const unsigned char* RPos() const;
    const unsigned char* WPos() const;
    const unsigned char* Data() const;

    size_t TotalLength() const;
    size_t Size() const;

    uint32_t Copy(const unsigned char* data, uint32_t len);
    
    bool EoF() const;

    void Swap(DataStream& stream);

protected:
    void Realloc(size_t new_size = 1024);

protected   :
    unsigned char* m_buf;
    size_t m_wpos;
    mutable size_t m_rpos;
    size_t m_size;
    bool m_ref;
};

class SSHPacket: public DataStream
{
public:
    SSHPacket();
    SSHPacket(size_t len);
    SSHPacket(const unsigned char* buf, size_t len);

    template<typename T>
    int Read(T& value) const
    {
        if (m_rpos >= m_payload_size + PAYLOAD_OFFEST) {
            return 0;
        }
        memcpy(&value, m_buf + m_rpos, sizeof(value));
        if (sizeof(value) > 4) {
            value = ntonu64(value);
        } else if (sizeof(value) > 2) {
            value = ntonu32(value);
        }
        m_rpos += sizeof(value);
        return sizeof(value);
    }

    const unsigned char* ReadBuf(unsigned char *value, uint32_t len) const;
    const unsigned char* ReadString(const unsigned char **value, uint32_t& len) const;

    void SetPadding(unsigned char value);
    void SetLength();
    size_t Length() const;
    void SetMAC(const unsigned char* mac, uint32_t len);

    const unsigned char* Payload() const;
    size_t PayloadLength() const;
    bool PayloadEOF() const;
    void SetPayloadLength();
    void SetTotalLength(size_t value);
    unsigned char MessageType() const;

protected:
    size_t m_payload_size;
};


class FXPacket: public DataStream
{
public:
    FXPacket();
    FXPacket(uint32_t len);
    FXPacket(const SSHPacket& packet);

    uint32_t Length() const;
    void SetLength();

    uint32_t RequestID() const;

    template<typename T>
    int Read(T& value) const
    {
        if (m_rpos >= m_wpos) {
            return 0;
        }
        memcpy(&value, m_buf + m_rpos, sizeof(value));
        if (sizeof(value) > 4) {
            value = ntonu64(value);
        } else if (sizeof(value) > 2) {
            value = ntonu32(value);
        }
        m_rpos += sizeof(value);
        return sizeof(value);
    }

    int ReadBuf(unsigned char* value, uint32_t len) const;
    const unsigned char* ReadString(const unsigned char **value, uint32_t& len) const;
};

#endif // __SSH_PACKET_H__