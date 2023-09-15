#include "sshlog.h"
#include <chrono>
#include <mutex>

#if defined(_WIN32)
#include <Windows.h>
#include <winsock.h>
#define getpid      GetCurrentProcessId
#define gettid      GetCurrentThreadId
#endif

#include <unistd.h>
#include <cstdarg>
#include <stdlib.h>
#include <stdio.h>
#ifndef errno_t
#include <stdint.h>
#define errno_t int
#endif

SSHLogger gSSHLogger;

namespace ch = std::chrono;
typedef ch::duration<int, std::ratio_multiply<ch::hours::period, std::ratio<24> >::type> days;

namespace {
const char *log_lvl_nm = "EWIDDD";
}

SSHLogger::SSHLogger()
    : m_file(stdout)
    , m_lvl(SSHLogLevel::Error)
{
}

SSHLogger::~SSHLogger()
{
    if (m_file && m_file != stdout) {
        fclose(m_file);
    }
}

void SSHLogger::Create(const char *path, SSHLogLevel lvl)
{
    std::lock_guard<std::mutex> lock(m_lock);
    char host[64];
    if (gethostname(host, sizeof(host)) != 0) {
        snprintf(host, sizeof(host), "localhost");
    }

    char fname[256];
    int written = snprintf(fname, sizeof(fname), "%s/%s-ssh-%lu.log", path, host, getpid());

    if (m_file && m_file != stdout) {
        fclose(m_file);
    }

    if (written < 0) {
        m_file = stdout;
    } else {
        fname[written] = 0;
        m_file = fopen(fname, "w+");
        if (m_file == nullptr) {
            m_file = stdout;
        }
    }

    m_lvl = lvl;
}

void SSHLogger::Write(SSHLogLevel lvl, const char *format, ...)
{
    std::lock_guard<std::mutex> lock(m_lock);
    auto a = std::chrono::system_clock::now();
    auto tp = a.time_since_epoch();
    days d = ch::duration_cast<days>(tp);
    tp -= d;
    ch::hours h = ch::duration_cast<ch::hours>(tp);
    tp -= h;
    ch::minutes m = ch::duration_cast<ch::minutes>(tp);
    tp -= m;
    ch::seconds s = ch::duration_cast<ch::seconds>(tp);
    tp -= s;
    ch::milliseconds ms = ch::duration_cast<ch::milliseconds>(tp);

    char fmt[512];
    snprintf(fmt, sizeof(fmt), "%02d:%02d:%02d:%03d [%c] %x %s\n",
             (int)h.count(), (int)m.count(), (int)s.count(), (int)ms.count(), log_lvl_nm[(int)lvl], gettid(), format);

    va_list args;
    va_start(args, format);

    vfprintf(m_file, fmt, args);
    fflush(m_file);

    va_end(args);
}

SSHLogLevel SSHLogger::GetLogLvl()
{
    return m_lvl;
}
