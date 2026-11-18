int f1(int a){ return a; }
int f2(int a, int b){ return a + b; }
int t_decl(){ int x = 1; int r = f1(x); return r; }
int t_expr(){ int x = 1; f1(x); return 0; }
int t_assign(){ int x = 1; int r; r = f1(x); return r; }
int t_return(){ int x = 1; return f1(x); }
int t_return2(){ int x = 1; int y = 2; return f2(x, y); }
int t_if(){ int x = 1; if (f1(x)) { return 1; } return 0; }
int t_while(){ int x = 1; while (f1(x)) { x = 0; } return 0; }
int t_nested(){ int x = 1; int y = 2; int r = f2(f1(x), y); return r; }
int t_retnested(){ int x = 1; int y = 2; return f2(y, f1(x)); }
int t_retexpr(){ int x = 1; return f1(x) + 1; }
int t_ifexpr(){ int x = 1; if (f1(x) > 0) { return 1; } return 0; }
int t_for(){ int x = 3; int i; for (i = 0; i < f1(x); i++) { } return i; }
int t_declnested2(){ int x = 1; int y = 2; int r = f2(y, f1(x)); return r; }
int t_deep(){ int x = 1; int y = 2; int z = 3; int r = f2(f2(y, f1(x)), z); return r; }
int t_after(){ int x = 1; int y = 2; int z = 3; int r = f2(f1(x), f2(y, z)); return r; }
