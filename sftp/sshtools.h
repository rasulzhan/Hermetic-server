#ifndef SSHTOOLS_H
#define SSHTOOLS_H

#include <functional>

class SSHTransport;

namespace sshtools {

int UploadFile(SSHTransport *ssh,
               const char *src,
               const char *dst,
               std::function<void(int)> progress = nullptr,
               std::function<void(const char*)> message = nullptr);

int DownlodFile(SSHTransport *ssh,
                const char *src,
                const char *dst,
                std::function<void(int)> progress  = nullptr,
                std::function<void(const char*)> message = nullptr);

}

#endif // SSHTOOLS_H
