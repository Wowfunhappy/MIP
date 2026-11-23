/* Mavericks port: os_log is 10.12+. Substitute only uses it for LOG(). */
#ifndef MIP_COMPAT_OS_LOG_H
#define MIP_COMPAT_OS_LOG_H
#include <syslog.h>
#define OS_LOG_DEFAULT 0
#define os_log(log, fmt, ...) syslog(LOG_NOTICE, fmt, ##__VA_ARGS__)
#endif
