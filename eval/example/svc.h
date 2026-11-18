#include <stddef.h>
int read_request(int sock, char *req, size_t n);
int run_report(int sock, const char *host);
void build_command(char *cmd, size_t n, const char *host);
void log_request(const char *host);
