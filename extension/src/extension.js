// VS Code front end for slicesec: srcSlice forward slices, taint paths and vulnerability findings.
// The analysis runs in a Python process (python -m slicesec.server) spoken to over stdin/stdout, one JSON-RPC
// message per line. Paths in requests and results are relative to the workspace folder.
'use strict';
const vscode = require('vscode');
const cp = require('child_process');
const path = require('path');
const fs = require('fs');
const readline = require('readline');

const LANGS = ['c', 'cpp', 'python'];
let server = null, out = null, diags = null, deco = null, tree = null, status = null;
let findings = [];

// ---- server ---------------------------------------------------------------------------------------------
class Server {
  constructor(root) {
    this.root = root; this.next = 1; this.pending = new Map(); this.proc = null;
  }
  start() {
    const cfg = vscode.workspace.getConfiguration('slicesec');
    const py = cfg.get('pythonPath') || 'python3';
    const env = Object.assign({}, process.env);
    const bundled = path.join(__dirname, '..', 'backend');           // packaged copy of the slicesec package
    const backend = cfg.get('backendPath') || (fs.existsSync(bundled) ? bundled : '');
    if (backend) env.PYTHONPATH = backend + (env.PYTHONPATH ? path.delimiter + env.PYTHONPATH : '');
    this.proc = cp.spawn(py, ['-m', 'slicesec.server'], { env, cwd: this.root });
    readline.createInterface({ input: this.proc.stdout }).on('line', l => this.onLine(l));
    this.proc.stderr.on('data', d => out.append(d.toString()));
    this.proc.on('exit', code => {
      out.appendLine(`server exited (${code})`);
      for (const [, p] of this.pending) p.reject(new Error('analysis server stopped'));
      this.pending.clear(); this.proc = null;
    });
    this.proc.on('error', e => out.appendLine(`cannot start ${py}: ${e.message}`));
  }
  onLine(line) {
    let msg; try { msg = JSON.parse(line); } catch { return; }
    const p = this.pending.get(msg.id); if (!p) return;
    this.pending.delete(msg.id);
    msg.error ? p.reject(new Error(msg.error.message)) : p.resolve(msg.result);
  }
  call(method, params = {}) {
    if (!this.proc) this.start();
    const id = this.next++;
    return new Promise((resolve, reject) => {
      this.pending.set(id, { resolve, reject });
      this.proc.stdin.write(JSON.stringify({ jsonrpc: '2.0', id, method, params }) + '\n');
    });
  }
  stop() {
    if (!this.proc) return;
    try { this.proc.stdin.write(JSON.stringify({ jsonrpc: '2.0', id: 0, method: 'shutdown' }) + '\n'); } catch { }
    const p = this.proc; setTimeout(() => p && p.kill(), 1000); this.proc = null;
  }
}

function rootOf(uri) {
  const ws = uri && vscode.workspace.getWorkspaceFolder(uri);
  return ws ? ws.uri.fsPath : (uri ? path.dirname(uri.fsPath) : undefined);
}

async function ensureServer(uri) {
  const root = rootOf(uri);
  if (!root) throw new Error('open a C, C++ or Python file first');
  if (server && server.root === root) return server;
  if (server) server.stop();
  server = new Server(root);
  const t = Date.now();
  const info = await server.call('initialize', { root, maxHops: vscode.workspace.getConfiguration('slicesec').get('maxHops') });
  out.appendLine(`initialized ${root}: ${info.files} files, ${info.profiles} slice profiles, ${info.findings} findings, ` +
    `${info.seconds} s analysis, ${Date.now() - t} ms round trip; ${JSON.stringify(info.versions)}`);
  if (info.skipped.length) out.appendLine(`srcML could not convert: ${info.skipped.join(', ')}`);
  return server;
}

// ---- helpers --------------------------------------------------------------------------------------------
const rel = (doc) => path.relative(server.root, doc.uri.fsPath).split(path.sep).join('/');
const uriOf = (file) => vscode.Uri.file(path.join(server.root, file));
const lineRange = (n) => new vscode.Range(n - 1, 0, n - 1, Number.MAX_SAFE_INTEGER);

function wordAtCursor() {
  const ed = vscode.window.activeTextEditor;
  if (!ed) return null;
  const r = ed.document.getWordRangeAtPosition(ed.selection.active, /[A-Za-z_][A-Za-z0-9_]*/);
  return r ? { ed, var: ed.document.getText(r), line: ed.selection.active.line + 1 } : null;
}

// ---- findings -> Problems panel -------------------------------------------------------------------------
async function analyzeWorkspace(uri) {
  const s = await ensureServer(uri);
  const t = Date.now();
  const res = await s.call('analyze');
  findings = res.findings;
  const byFile = new Map();
  const sev = { error: vscode.DiagnosticSeverity.Error, warning: vscode.DiagnosticSeverity.Warning };
  for (const f of findings) {
    const d = new vscode.Diagnostic(lineRange(f.line), `${f.message}`, sev[f.severity] ?? vscode.DiagnosticSeverity.Warning);
    d.source = 'sliceSec';
    d.code = { value: `${f.cwe} ${f.rule}`, target: vscode.Uri.parse(`https://cwe.mitre.org/data/definitions/${f.cwe.split('-')[1]}.html`) };
    d.relatedInformation = f.path.map((st, i) => new vscode.DiagnosticRelatedInformation(
      new vscode.Location(uriOf(st.file), lineRange(st.line)), `${i + 1}. ${st.var}: ${st.how}`));
    if (!byFile.has(f.file)) byFile.set(f.file, []);
    byFile.get(f.file).push(d);
  }
  diags.clear();
  for (const [file, ds] of byFile) diags.set(uriOf(file), ds);
  status.text = `$(shield) sliceSec: ${findings.length} finding${findings.length === 1 ? '' : 's'}`;
  out.appendLine(`analyze: ${findings.length} findings, ${res.seconds} s analysis, ${Date.now() - t} ms round trip`);
}

// ---- decorations and the results tree -------------------------------------------------------------------
function makeDecorations() {
  return {
    slice: vscode.window.createTextEditorDecorationType({
      backgroundColor: new vscode.ThemeColor('slicesec.sliceBackground'), isWholeLine: true,
      overviewRulerColor: new vscode.ThemeColor('slicesec.sliceBackground'), overviewRulerLane: vscode.OverviewRulerLane.Left }),
    criterion: vscode.window.createTextEditorDecorationType({
      backgroundColor: new vscode.ThemeColor('slicesec.criterionBackground'), isWholeLine: true, fontWeight: 'bold' }),
    taint: vscode.window.createTextEditorDecorationType({
      backgroundColor: new vscode.ThemeColor('slicesec.taintBackground'), isWholeLine: true,
      overviewRulerColor: new vscode.ThemeColor('slicesec.taintBackground'), overviewRulerLane: vscode.OverviewRulerLane.Right }),
  };
}

let shown = { slice: new Map(), criterion: new Map(), taint: new Map() };   // file -> decoration options

function paint() {
  for (const ed of vscode.window.visibleTextEditors) {
    if (!server || !ed.document.uri.fsPath.startsWith(server.root)) continue;
    const f = rel(ed.document);
    for (const k of Object.keys(shown)) ed.setDecorations(deco[k], shown[k].get(f) || []);
  }
}

function clearHighlights() {
  shown = { slice: new Map(), criterion: new Map(), taint: new Map() };
  paint(); tree.set('', []);
}

class ResultsTree {
  constructor() { this.title = ''; this.items = []; this.emitter = new vscode.EventEmitter(); this.onDidChangeTreeData = this.emitter.event; }
  set(title, items) { this.title = title; this.items = items; this.emitter.fire(); }
  getTreeItem(x) { return x; }
  getChildren(x) { return x ? x.children || [] : this.items; }
}

function leaf(label, file, line, description) {
  const it = new vscode.TreeItem(label, vscode.TreeItemCollapsibleState.None);
  it.description = description;
  it.command = { command: 'vscode.open', title: 'open', arguments: [uriOf(file), { selection: lineRange(line) }] };
  return it;
}

// ---- commands -------------------------------------------------------------------------------------------
async function sliceVariable() {
  const w = wordAtCursor(); if (!w) return;
  const s = await ensureServer(w.ed.document.uri);
  const r = await s.call('slice', { file: rel(w.ed.document), line: w.line, var: w.var });
  if (!r) { vscode.window.showInformationMessage(`sliceSec: no slice profile for ${w.var} here`); return; }
  shown.slice = new Map(Object.entries(r.lines).map(([f, ls]) => [f, ls.map(lineRange)]));
  shown.criterion = new Map([[rel(w.ed.document), [lineRange(w.line)]]]);
  shown.taint = new Map();
  paint();
  const n = Object.values(r.lines).reduce((a, ls) => a + ls.length, 0);
  const files = Object.entries(r.lines).map(([f, ls]) => {
    const it = new vscode.TreeItem(f, vscode.TreeItemCollapsibleState.Expanded);
    it.description = `${ls.length} lines`;
    it.children = ls.map(l => leaf(`${l}`, f, l, (vscode.workspace.textDocuments.find(d => d.uri.fsPath === uriOf(f).fsPath)?.lineAt(l - 1).text || '').trim()));
    return it;
  });
  const edges = Object.entries(r.controlEdges || {}).flatMap(([f, es]) => es.map(e => ({ f, ...e })));
  const flow = new vscode.TreeItem(`control flow (${edges.length} edges)`, vscode.TreeItemCollapsibleState.Collapsed);
  flow.children = edges.map(e => leaf(`${e.from} → ${e.to}`, e.f, e.from, `${e.kind} · ${e.f} · ${e.function}`));
  const vars = new vscode.TreeItem(`variables (${r.variables.length})`, vscode.TreeItemCollapsibleState.Collapsed);
  vars.children = r.variables.map(v => { const it = new vscode.TreeItem(`${v.var}`); it.description = `${v.function} · ${v.file}`; return it; });
  tree.set(`slice of ${w.var}`, [...files, flow, vars]);
  status.text = `$(list-flat) slice of ${w.var}: ${n} lines, ${r.variables.length} variables`;
}

async function showTaintPath() {
  const w = wordAtCursor(); if (!w) return;
  const s = await ensureServer(w.ed.document.uri);
  const r = await s.call('taint', { file: rel(w.ed.document), line: w.line, var: w.var });
  if (!r) { vscode.window.showInformationMessage(`sliceSec: no slice profile for ${w.var} here`); return; }
  const steps = r.path.length ? r.path : (r.findings[0]?.path || []);
  if (!steps.length) { vscode.window.showInformationMessage(`sliceSec: no untrusted source reaches ${w.var}`); return; }
  shown.taint = new Map(); shown.slice = new Map(); shown.criterion = new Map();
  steps.forEach((st, i) => {
    if (!shown.taint.has(st.file)) shown.taint.set(st.file, []);
    shown.taint.get(st.file).push({ range: lineRange(st.line),
      renderOptions: { after: { contentText: `  ← ${i + 1}. ${st.var}: ${st.how}`, color: new vscode.ThemeColor('editorCodeLens.foreground') } } });
  });
  paint();
  tree.set(`taint path to ${w.var}`, steps.map((st, i) => leaf(`${i + 1}. ${st.var}`, st.file, st.line, `${st.how} · ${st.file}:${st.line}`)));
}

async function hover(doc, pos) {
  if (!server || !doc.uri.fsPath.startsWith(server.root)) return;
  const r0 = doc.getWordRangeAtPosition(pos, /[A-Za-z_][A-Za-z0-9_]*/); if (!r0) return;
  const p = await server.call('profile', { file: rel(doc), line: pos.line + 1, var: doc.getText(r0) }).catch(() => null);
  if (!p) return;
  const md = new vscode.MarkdownString();
  md.appendMarkdown(`**${p.var}** in \`${p.function || '(file)'}\` (srcSlice profile)\n\n`);
  md.appendMarkdown(`def ${p.defs.join(', ') || '–'} · use ${p.uses.join(', ') || '–'}\n\n`);
  if (p.dvars.length) md.appendMarkdown(`flows into ${p.dvars.map(v => `\`${v}\``).join(', ')}\n\n`);
  if (p.aliases.length) md.appendMarkdown(`aliases ${p.aliases.map(v => `\`${v}\``).join(', ')}\n\n`);
  if (p.calls.length) md.appendMarkdown(`passed to ${p.calls.map(c => `\`${c.name}\` (arg ${c.arg})`).join(', ')}\n\n`);
  if (p.pointsTo && p.pointsTo.length) md.appendMarkdown(`points to ${p.pointsTo.map(o => `\`${o}\``).join(', ')} (srcPtr)`);
  return new vscode.Hover(md, r0);
}

// ---- activation -----------------------------------------------------------------------------------------
function activate(context) {
  out = vscode.window.createOutputChannel('slicesec');
  diags = vscode.languages.createDiagnosticCollection('slicesec');
  deco = makeDecorations();
  tree = new ResultsTree();
  status = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 50);
  status.text = '$(shield) sliceSec'; status.command = 'slicesec.analyze'; status.show();
  const guard = (fn) => async (...a) => { try { await fn(...a); } catch (e) { out.appendLine(e.stack || String(e)); vscode.window.showErrorMessage(`sliceSec: ${e.message}`); } };
  const cur = () => vscode.window.activeTextEditor?.document.uri;
  context.subscriptions.push(out, diags, status, ...Object.values(deco),
    vscode.window.registerTreeDataProvider('slicesec.results', tree),
    vscode.commands.registerCommand('slicesec.analyze', guard(() => analyzeWorkspace(cur()))),
    vscode.commands.registerCommand('slicesec.sliceVariable', guard(sliceVariable)),
    vscode.commands.registerCommand('slicesec.showTaintPath', guard(showTaintPath)),
    vscode.commands.registerCommand('slicesec.clearHighlights', clearHighlights),
    vscode.commands.registerCommand('slicesec.restartServer', guard(async () => { if (server) server.stop(); server = null; await analyzeWorkspace(cur()); })),
    vscode.languages.registerHoverProvider(LANGS, { provideHover: hover }),
    vscode.window.onDidChangeVisibleTextEditors(paint),
    vscode.workspace.onDidSaveTextDocument(guard(async (doc) => {
      if (LANGS.includes(doc.languageId) && vscode.workspace.getConfiguration('slicesec').get('analyzeOnSave')) {
        clearHighlights(); await analyzeWorkspace(doc.uri);
      }
    })),
    { dispose: () => server && server.stop() });
  const ed = vscode.window.activeTextEditor;
  if (ed && LANGS.includes(ed.document.languageId) && vscode.workspace.getConfiguration('slicesec').get('analyzeOnSave'))
    guard(() => analyzeWorkspace(ed.document.uri))();
  // read-only view of the state, for the end-to-end test
  return { state: () => ({ findings, root: server && server.root, tree: tree.title, items: tree.items.map(i => i.label),
    shown: Object.fromEntries(Object.entries(shown).map(([k, m]) => [k, Object.fromEntries([...m].map(([f, rs]) => [f, rs.map(r => (r.range || r).start.line + 1)]))])) }) };
}

function deactivate() { if (server) server.stop(); }

module.exports = { activate, deactivate, _internal: { Server } };
