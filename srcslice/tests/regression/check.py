"""Check srcSlice output against expectations: function<TAB>var<TAB>kind<TAB>values(;-separated)
kinds: cf = exact cfuncs set, dv = dvars must include, nodv = dvars must not include,
       def = def lines must include, use = use lines must include, absent = profile must not exist."""
import re, subprocess, sys
binary, archive, oracle = sys.argv[1:4]
prof = {}
for line in subprocess.run([binary, archive], capture_output=True, text=True).stdout.splitlines():
    m = re.match(r'(.*?),([^,]*),([^,]*),def\{(.*?)\},use\{(.*?)\},dvars\{(.*?)\},pointers\{(.*?)\},cfuncs\{(.*)\}$', line)
    if m:
        sp = lambda s: set(filter(None, s.split(',')))
        prof[(m[2], m[3])] = dict(defs=sp(m[4]), use=sp(m[5]), dv=sp(m[6]), cf=set(re.findall(r'[^,{}]+\{\d+\}', m[8])))
ok = n = 0
for row in open(oracle):
    if not row.strip() or row.startswith('#'): continue
    fn, v, kind, *vals = row.rstrip('\n').split('\t'); want = set(filter(None, (vals[0] if vals else '').split(';')))
    p = prof.get((fn, v)); n += 1
    if kind == 'absent': good = p is None
    elif p is None: good = False
    elif kind == 'cf': good = p['cf'] == want
    elif kind == 'dv': good = want <= p['dv']
    elif kind == 'nodv': good = not (want & p['dv'])
    elif kind == 'def': good = want <= p['defs']
    elif kind == 'use': good = want <= p['use']
    ok += good
    if not good: print('FAIL', fn, v, kind, sorted(want), '| got', p and {k: sorted(x) for k, x in p.items()})
print(f'{ok}/{n} checks pass')
