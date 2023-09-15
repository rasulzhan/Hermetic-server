#include "sshtools.h"
#include "sshtransport.h"
#include "sshchannel.h"
#include "sshsftp.h"
#include "sshconst.h"

#include <unistd.h>
#include <cstdarg>

#if defined(_WIN32)
#else
#include <fstream>
#include <iostream>
#include <string>
#include <cerrno>
#include <clocale>

#endif

#ifndef errno_t
#define errno_t FILE*
#endif

#ifndef fopen_s
#define fopen_s(fp, fmt, mode)          *(fp)=fopen( (fmt), (mode))
#endif

namespace sshtools {

#define BUFFER_SIZE     16384

#define PROGRESS(x) if (progress) { progress(x); }
#define MESSAGE(format, ...) if (message)\
    {\
        snprintf(msg, sizeof(msg), format, ##__VA_ARGS__);\
        message(msg);\
    }

long long GetFileSize(const char *file)
{
#if defined(_WIN32)
    long long result = -1L;
    HANDLE hFile = CreateFile(file, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if(hFile == INVALID_HANDLE_VALUE) {
        return -1;
    }
    LARGE_INTEGER fsize_li;
    if (!GetFileSizeEx(hFile, &fsize_li)) {
        goto exit;
    }
    result = fsize_li.QuadPart;
exit:

    CloseHandle(hFile);
    return result;
#else
// #error GetFileSize is unimplemented
    long long result = -1L;
    std::ifstream hFile(file, std::ios::binary);
    const auto begin = hFile.tellg();
    hFile.seekg(0, std::ios::end);
    const auto end = hFile.tellg();
    result = end-begin;
    return result;
#endif
}

int UploadFile(SSHTransport *ssh, const char *src, const char *dest, std::function<void(int)> progress, std::function<void(const char*)> message)
{
    int rc = -1;
    char msg[512];

    if (!ssh) {
        MESSAGE("SSH is not initialized");
        return -1;
    }

    FILE *fsrc = nullptr;
    SSHSFTP *sftp = nullptr;
    SSH_FILE_HANDLE *fdest = nullptr;
    size_t onepercent = 0, progressval = 0;
    uint64_t offset = 0;
    long long srcsize = 0;
    const int attempts = 3;
    int attempt = 0;
    int restart = 0;
    std::unique_ptr<unsigned char[]> buf(new unsigned char[BUFFER_SIZE]);
    uint32_t access = SSH_FXF_CREATE | SSH_FXF_WRITE | SSH_FXF_TRUNC;

    errno_t err = fopen_s(&fsrc, src, "rb");
    if (fsrc == nullptr || err != 0) {
        MESSAGE("Could not open local file: %s. Error: %d", src, err);
        return -1;
    }

    MESSAGE("Local file is opened: %s", src);

    srcsize = GetFileSize(src);
    if (srcsize == -1L) {
        MESSAGE("Could not determine local file size: %s", src);
        return -1;
    }

    MESSAGE("Local file size: %lld bytes", srcsize);

restart:
    attempt = 0;
    if (sftp) {
        if (fdest) {
            sftp->CloseHandle(fdest);
            fdest = nullptr;
        }
        ssh->CloseChannel(sftp);
        sftp = nullptr;
    }

    sftp = (SSHSFTP*)ssh->OpenChannel("sftp");
    if (!sftp) {
        MESSAGE("Failed on open SFTP channel");
        goto cleanup;
    }

    MESSAGE("SFTP channel is opened");

    fdest = sftp->OpenFile(dest, access);
    if (!fdest) {
        MESSAGE("Could not create remote file: %s", dest);
        goto cleanup;
    }

    MESSAGE("Remote file is opened: %s", dest);

    onepercent = srcsize / 100;

    MESSAGE("Uploading file...");

    PROGRESS(progressval);

    while (offset < (uint64_t)srcsize) {
        int read = fread(buf.get(), sizeof(char), BUFFER_SIZE, fsrc);
        if (read == 0) {
            MESSAGE("Failed to read local file: %d", ferror(fsrc));
            break;
        }

        if (read != BUFFER_SIZE) {
            if (!feof(fsrc)) {
                MESSAGE("Failed to read local file: %d", ferror(fsrc));
                break;
            }
        }
attempt:
        int rc = sftp->Write(fdest, offset, buf.get(), read);
        if (rc == -1) {
            MESSAGE("Failed to write remote file");
            break;
        } else if (rc == SSH_CHANNEL_ERROR_TIMEOUT) {
            if (attempt++ < attempts) {
                MESSAGE("Write remote file timeout. Attempt %d/%d", attempt, attempts);
                goto attempt;
            }
            if (restart++ < 3) {
                MESSAGE("Restarting sftp channel...");
                access = SSH_FXF_CREATE | SSH_FXF_WRITE;
                if (fseek(fsrc, -read, SEEK_CUR) != 0) {
                    MESSAGE("Failed to move the position of local file backward. Error %d", ferror(fsrc));
                    break;
                }
                goto restart;
            }
            MESSAGE("Write remote file timeout");
            break;
        }
        attempt = 0;
        restart = 0;
        offset += read;

        if (offset / onepercent > progressval) {
            progressval = offset / onepercent;
            PROGRESS(progressval);
        }

    }

    MESSAGE("Upload completed. Read %llu/%lld bytes", offset, srcsize);

    if (offset == (uint64_t)srcsize) {
        rc = 1;
        PROGRESS(100);
    }

cleanup:
    if (fsrc) {
        fclose(fsrc);
    }
    if (fdest) {
        sftp->CloseHandle(fdest);
    }
    if (sftp) {
        ssh->CloseChannel(sftp);
    }
    return rc;
}

int DownlodFile(SSHTransport *ssh, const char *src, const char *dest, std::function<void(int)> progress, std::function<void(const char*)> message)
{
    char msg[512];
    int rc = -1;
    if (!ssh) {
        MESSAGE("SSH is not initialized");
        return -1;
    }

    FILE *fdest = nullptr;
    SSHSFTP *sftp = nullptr;
    SSH_FILE_HANDLE *fsrc = nullptr;
    size_t onepercent = 0, progressval = 0;
    uint64_t offset = 0, srcsize = 0;
    const int attempts = 3;
    int attempt = 0;
    int restart = 0;
    std::unique_ptr<unsigned char[]> buf(new unsigned char[BUFFER_SIZE]);
    unsigned char *p = buf.get();

    errno_t err = fopen_s(&fdest, dest, "wb");
    if (fdest == nullptr || err != 0) {
        MESSAGE("Could not create local file: %s. Error: %d", dest, err);
        goto cleanup;
    }

    MESSAGE("Local file is created: %s", dest);

restart:
    attempt = 0;

    if (sftp) {
        if (fsrc) {
            sftp->CloseHandle(fsrc);
            fsrc = nullptr;
        }
        ssh->CloseChannel(sftp);
        sftp = nullptr;
    }

    sftp = (SSHSFTP*)ssh->OpenChannel("sftp");
    if (!sftp) {
        MESSAGE("Failed on open SFTP channel");
        goto cleanup;
    }

    MESSAGE("SFTP channel is opened");

    fsrc = sftp->OpenFile(src, SSH_FXF_READ);
    if (!fsrc) {
        MESSAGE("Could not open remote file: %s", src);
        goto cleanup;
    }

    MESSAGE("Remote file is opened: %s", src);

    if (sftp->GetFileAttrs(fsrc) != 1 || fsrc->size == 0) {
        MESSAGE("Could not get file size");
        goto cleanup;
    }

    srcsize = fsrc->size;
    MESSAGE("Remote file size: %llu bytes", srcsize);

    onepercent = srcsize / 100;

    MESSAGE("Downloading file...");

    PROGRESS(progressval);

    while (true) {
attempt:
        int read = sftp->Read(fsrc, offset, &p, BUFFER_SIZE);
        if (read == SSH_CHANNEL_ERROR_TIMEOUT) {
            if (attempt++ < attempts) {
                MESSAGE("Read remote file timeout. Attempt %d/%d", attempt, attempts);
                goto attempt;
            }
            if (restart++ < 3) {
                MESSAGE("Restarting sftp channel...");
                goto restart;
            }
            MESSAGE("Read remote file timeout");
            break;
        } else if (read == 0) {
            // End of file
            break;
        } else if (read < 0) {
            MESSAGE("Failed to read remote file");
        }

        attempt = 0;
        restart = 0;

        if (fwrite(buf.get(), sizeof(char), read, fdest) != (size_t)read) {
            MESSAGE("Failed to write local file. Error: %d",  ferror(fdest));
            goto cleanup;
        }
        offset += read;

        fflush(fdest);

        if (offset / onepercent > progressval) {
            progressval = offset / onepercent;
            PROGRESS(progressval);
        }

    }

    MESSAGE("Download completed. Read %llu/%llu bytes", offset, srcsize);

    if (offset == srcsize) {
        rc = 1;
        PROGRESS(100);
    }

cleanup:
    if (fdest) {
        fflush(fdest);
        fclose(fdest);
    }
    if (fsrc) {
        sftp->CloseHandle(fsrc);
    }
    if (sftp) {
        ssh->CloseChannel(sftp);
    }
    return rc;
}

}
