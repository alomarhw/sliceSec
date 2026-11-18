void f(int *a) { *a = 1; }
int main(void) {
    int x, y;
    int *p = &x;
    int *q = p;
    int *r;
    r = &y;
    r = q;
    int **pp = &q;
    f(p);
    return *r;
}
