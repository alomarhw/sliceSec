// End-to-end test inside a real VS Code: analyze, slice, taint path, hover. Writes runs/e2e/result.json.
const vscode = require('vscode'); const fs = require('fs'); const path = require('path');
const sleep = ms => new Promise(r => setTimeout(r, ms));
exports.run = async function () {
  const res = { steps: [] }; const log = (k, v) => res.steps.push([k, v]);
  try {
    const ws = vscode.workspace.workspaceFolders[0].uri.fsPath;
    const doc = await vscode.workspace.openTextDocument(path.join(ws, 'flows.c'));
    const ed = await vscode.window.showTextDocument(doc);
    const ext = vscode.extensions.all.find(e => e.packageJSON.name === 'slicesec');
    const api = await ext.activate();
    log('commands', (await vscode.commands.getCommands(true)).filter(c => c.startsWith('slicesec.')));
    let t = Date.now(); await vscode.commands.executeCommand('slicesec.analyze'); log('analyze_ms', Date.now() - t);
    const ds = vscode.languages.getDiagnostics(doc.uri);
    log('diagnostics_flows.c', ds.map(d => [d.range.start.line + 1, d.code.value, d.relatedInformation.length]));
    ed.selection = new vscode.Selection(11, 10, 11, 10);          // line 12: fgets(buf, ...) on "buf"
    t = Date.now(); await vscode.commands.executeCommand('slicesec.sliceVariable'); log('slice_ms', Date.now() - t);
    log('slice_state', api.state().shown, api.state().tree);
    ed.selection = new vscode.Selection(6, 12, 6, 12);            // line 7: system(line) on "line"
    const d2 = await vscode.window.showTextDocument(doc);
    t = Date.now(); await vscode.commands.executeCommand('slicesec.showTaintPath'); log('taint_ms', Date.now() - t);
    log('taint_state', api.state().shown.taint, api.state().items);
    const hov = await vscode.commands.executeCommand('vscode.executeHoverProvider', doc.uri, new vscode.Position(9, 9));
    log('hover', hov.flatMap(h => h.contents.map(c => c.value || String(c))).filter(x => x.includes('srcSlice')));
    await vscode.commands.executeCommand('slicesec.clearHighlights');
    log('cleared', api.state().shown);
  } catch (e) { log('ERROR', e && e.stack); }
  fs.writeFileSync(path.resolve(__dirname, '..', 'result.json'), JSON.stringify(res, null, 1));
};
