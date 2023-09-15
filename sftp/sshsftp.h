#ifndef __SSH_SFTP_H__
#define __SSH_SFTP_H__

#include "sshchannel.h"
#include <mutex>
#include <condition_variable>

// SSH_FXP_OPEN or SSH_FXP_OPENDIR
struct SSH_FILE_HANDLE  // TODO: hide structure
{
    SSH_FILE_HANDLE() : handle_len(0), size(0), allocation_size(0) {}
    uint32_t        handle_len;
    unsigned char   handle[256];    // max handle length
    uint64_t        size;
    uint64_t        allocation_size;
};

class SSHSFTP: public SSHChannel
{
    friend bool IsSFTPHandleValid(SSHSFTP*, SSH_FILE_HANDLE*);

    struct SSH_BUF
    {
        SSH_BUF() : data(NULL), size(0), len(0) {}
        unsigned char *data;
        int32_t size;
        int32_t len;
    };

    enum SFTPState
    {
        SFTP_NONE,
        SFTP_OPEN,
        SFTP_INIT,
        SFTP_PROCESS
    };

public:
    SSHSFTP(uint32_t id, SSHTransport *owner);
    virtual ~SSHSFTP();

    SSH_FILE_HANDLE* OpenFile(const char *file, uint32_t access);

    SSH_FILE_HANDLE* OpenDir(const char *file);
    int ReadDir(SSH_FILE_HANDLE *handle, unsigned char **data, uint32_t data_size);

    int GetFileAttrs(SSH_FILE_HANDLE *file);
    int Write(SSH_FILE_HANDLE *handle, uint64_t offset, unsigned char *data, uint32_t data_size);
    int Read(SSH_FILE_HANDLE *handle, uint64_t offset, unsigned char **data, uint32_t data_size);
    int CloseHandle(SSH_FILE_HANDLE *handle);

protected:
    virtual int OpenChannel(const char *type) override;

    virtual int OnOpenConfirm(const SSHPacket& packet) override;
    virtual int OnSuccess(const SSHPacket& packet) override;
    virtual int OnFailure(const SSHPacket& packet) override;
    virtual int OnData(const SSHPacket& packet) override;

    int Send(FXPacket& packet);

    SSH_FILE_HANDLE* AllocHandle();
    void FreeHandle(SSH_FILE_HANDLE* handle);
    void FreeHandles();

private:
    int ProcessData(const FXPacket& packet);

private:
    SFTPState           m_state;
    uint32_t            m_reqid;
    SSH_FILE_HANDLE**   m_handles;
    size_t              m_handles_count;
    std::mutex          m_handles_lock;
    FXPacket*           m_composite;    // packet in case if we get splitted packets
    void*               m_data;
    SSH_BUF             m_buf;
};

bool IsSFTPHandleValid(SSHSFTP *sftp, SSH_FILE_HANDLE *handle);

#endif // __SSH_SFTP_H__
