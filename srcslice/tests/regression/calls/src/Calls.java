class Calls {
  int g1(int a){ return a; }
  int j_decl(){ int x = 1; int r = g1(x); return r; }
  int j_return(){ int x = 1; return g1(x); }
  int j_if(){ int x = 1; if (g1(x) > 0) { return 1; } return 0; }
}
