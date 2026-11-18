int G1 = 0;
int G2 = 0;
int proto(int q, int w);
int likely(int c);
int sink(int v);
int callee(int p, int k)
{
	int r;
	int pdep = p + 1;
	int kdep = k + 1;
	r = sink(pdep);
	if (likely(r == 0)) {
		return kdep;
	}
	return pdep;
}
int caller_a(int a)
{
	int b = 2;
	return callee(a, b);
}
int caller_b(int a)
{
	int b = 2;
	int out = callee(b, a);
	return out;
}
