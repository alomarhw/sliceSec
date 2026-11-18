struct A { int dev; int ws; };
int g(int a, int b, int c);
int m3(struct A s){ int ws = 0; g(s.ws, 0, 0); return ws; }
int m4(struct A s){ int a = 1; memset(&s, 0, sizeof(s)); g(a, sizeof(s), a); return 0; }
int m5(struct A *p){ int k = 1; g(p->dev, k, 0); return 0; }
int m6(struct A *p){ int k = 1; g(0,
		h(k) |
		h(p->dev), 0); return 0; }
int m7(struct A *p){ int ws = 1; g(p->ws, ws, 0); return 0; }
