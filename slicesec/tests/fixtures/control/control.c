void f(int x, int y){
  int a = 0, b = 0;
  if (x > 0) {
    a = 1;
  } else if (y) {
    b = 2;
  } else b = 3;
  while (y < 9) y++;
  for (int i = 0; i < x; i++) a += i;
  switch (x) { case 1: b = 4; break; default: b = 5; }
  if (!y) return;
  a = 7;
  do { a--; } while (a > b);
}
