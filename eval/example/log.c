#include <syslog.h>
#include "svc.h"

void log_request(const char *host)
{
    syslog(LOG_INFO, "report for %s", host);
}
