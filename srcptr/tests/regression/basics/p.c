#include <stdlib.h>
struct S { char *buf; int n; };
void sink(char *c) { system(c); }
void set(char **out, char *v) { *out = v; }
int main(void) {
    char a[16];
    char *p = a;
    char *q;
    q = p;
    char *r;
    set(&r, q);
    char **pp = &p;
    struct S s;
    s.buf = q;
    void (*fp)(char *) = sink;
    fp(r);
    char *m = malloc(8);
    char *n = m;
    free(m);
    return n[0];
}
