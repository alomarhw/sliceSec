#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Vulnerability 1: buffer overflow via gets() */
void process_input() {
    char buf[64];
    char output[64];
    gets(buf);
    strcpy(output, buf);
    printf("%s\n", output);
}

/* Vulnerability 2: use-after-free */
void free_and_use() {
    char *data = malloc(64);
    gets(data);
    free(data);
    printf("%s\n", data);
}

/* Vulnerability 3: race condition - write without lock */
void add_to_list(void *entry, void *list) {
    char *name = malloc(32);
    gets(name);
    list_add_tail(entry, list);
}

int main() {
    process_input();
    free_and_use();
    return 0;
}
