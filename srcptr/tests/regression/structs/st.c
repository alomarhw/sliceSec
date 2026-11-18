struct S { char *buf; };
void g(struct S *ps, char *v) { ps->buf = v; }
char *h(struct S *ps) { return ps->buf; }
int main(void) {
    char x[4];
    struct S s;
    g(&s, x);
    char *y = h(&s);
    char *z = s.buf;
    struct S *t = &s;
    char *w = t->buf;
    return 0;
}
