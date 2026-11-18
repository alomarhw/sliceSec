#include <stdlib.h>
#include <string.h>
#include "svc.h"

/* Serve one client: read a host name and report on it. */
void serve(int sock)
{
    char *host = malloc(128);
    if (read_request(sock, host, 128) != 0) {
        free(host);
        return;
    }
    host[strcspn(host, "\r\n")] = '\0';
    run_report(sock, host);
    free(host);
    log_request(host);
}
