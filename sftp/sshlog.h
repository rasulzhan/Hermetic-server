#ifndef __SSH_LOG_H__
#define __SSH_LOG_H__

#define sshlog(format, ...) \
    printf(format, ##__VA_ARGS__);

#include <iostream>
#include <mutex>

#define LOGERR(fmt, ...) if (gSSHLogger.GetLogLvl() >= SSHLogLevel::Error)   { gSSHLogger.Write(SSHLogLevel::Error, fmt, ##__VA_ARGS__); }
#define LOGWRN(fmt, ...) if (gSSHLogger.GetLogLvl() >= SSHLogLevel::Warning) { gSSHLogger.Write(SSHLogLevel::Warning, fmt, ##__VA_ARGS__); }
#define LOGINF(fmt, ...) if (gSSHLogger.GetLogLvl() >= SSHLogLevel::Info)    { gSSHLogger.Write(SSHLogLevel::Info, fmt, ##__VA_ARGS__); }
#define LOGDBG1(fmt, ...) if (gSSHLogger.GetLogLvl() >= SSHLogLevel::Debug1)  { gSSHLogger.Write(SSHLogLevel::Debug1, fmt, ##__VA_ARGS__); }
#define LOGDBG2(fmt, ...) if (gSSHLogger.GetLogLvl() >= SSHLogLevel::Debug2)  { gSSHLogger.Write(SSHLogLevel::Debug2, fmt, ##__VA_ARGS__); }
#define LOGDBG3(fmt, ...) if (gSSHLogger.GetLogLvl() >= SSHLogLevel::Debug3)  { gSSHLogger.Write(SSHLogLevel::Debug3, fmt, ##__VA_ARGS__); }

enum class SSHLogLevel
{
    Error,
    Warning,
    Info,
    Debug1,
    Debug2,
    Debug3,
    Max
};

class SSHLogger
{
public:
    SSHLogger();
    ~SSHLogger();

    void Create(const char *path, SSHLogLevel lvl);
    void Write(SSHLogLevel lvl, const char *format, ...);

    SSHLogLevel GetLogLvl();

private:
    FILE        *m_file;
    std::string m_path;
    SSHLogLevel m_lvl;
    std::mutex  m_lock;
};

extern SSHLogger gSSHLogger;

#endif // __SSH_LOG_H__
