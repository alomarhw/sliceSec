struct S { int m(int a); };
int h1(int a){ return a; }
int h2(int *p){ return *p; }
int u_method(){ S s; int x = 1; int r = s.m(x); return r; }
int u_ptr(){ int x = 1; int r = h2(&x); return r; }
int u_exprarg(){ int x = 1; int r = h1(x + 1); return r; }
int u_two(){ int x = 1; int y = 2; h1(x); h1(y); return 0; }
int u_retptr(){ int x = 1; return h2(&x); }
int u_switch(){ int x = 1; switch (h1(x)) { case 1: return 1; } return 0; }
int u_dowhile(){ int x = 1; do { x = 0; } while (h1(x)); return 0; }
int u_forinc(){ int x = 1; int i; for (i = 0; i < 3; i = h1(x)) { } return i; }
