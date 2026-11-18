#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static void run(const char *cmd) {
    char line[128];
    strcpy(line, cmd);
    system(line);
}
int main(void) {
    char buf[64];
    char *p = malloc(64);
    fgets(buf, sizeof buf, stdin);
    int n = atoi(buf);
    char *q = p;
    run(buf);
    free(p);
    printf("%s %d\n", q, n);
    return 0;
}
