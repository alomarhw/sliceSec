#include <string>
#include <cstdlib>
#include <iostream>
char gbuf[32];
class Shell { public:
  void exec(const std::string &c) { std::system(c.c_str()); }
};
int main() {
  std::string s;
  std::cin >> s;
  Shell sh;
  sh.exec(s);
  char *e = getenv("HOME");
  char *f = e;
  system(f);
  return 0;
}
