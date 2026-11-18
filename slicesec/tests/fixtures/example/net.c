#include <string.h>
#include <sys/socket.h>
#include "svc.h"

/* Read one request line from the client into req. */
int read_request(int sock, char *req, size_t n)
{
    ssize_t got = recv(sock, req, n - 1, 0);
    if (got <= 0)
        return -1;
    req[got] = '\0';
    return 0;
}
