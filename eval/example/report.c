#include <stdio.h>
#include <string.h>
#include "svc.h"

/* Build the shell command that pings the requested host. */
void build_command(char *cmd, size_t n, const char *host)
{
    snprintf(cmd, n, "ping -c 1 %s", host);
}

/* Run the command and send its output back. */
int run_report(int sock, const char *host)
{
    char cmd[256];
    char line[512];
    build_command(cmd, sizeof cmd, host);
    FILE *out = popen(cmd, "r");
    if (out == NULL)
        return -1;
    while (fgets(line, sizeof line, out) != NULL)
        send(sock, line, strlen(line), 0);
    return pclose(out);
}
