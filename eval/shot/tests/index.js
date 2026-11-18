// Fig. 2: sets up the editor state, writes ../ready, and keeps the window open for the screenshot.
const vscode = require('vscode'); const fs = require('fs'); const path = require('path');
const sleep = ms => new Promise(r => setTimeout(r, ms));
exports.run = async function () {
  const here = path.resolve(__dirname, '..');
  try {
    const ws = vscode.workspace.workspaceFolders[0].uri.fsPath;
    const m = await vscode.workspace.openTextDocument(path.join(ws, 'main.c'));
    const r = await vscode.workspace.openTextDocument(path.join(ws, 'report.c'));
    const ext = vscode.extensions.all.find(x => x.packageJSON.name === 'slicesec');
    await ext.activate();
    const em = await vscode.window.showTextDocument(m, vscode.ViewColumn.One);
    await vscode.commands.executeCommand('slicesec.analyze');
    const er = await vscode.window.showTextDocument(r, vscode.ViewColumn.Two);
    const col = r.lineAt(16).text.indexOf('popen(cmd') + 7;      // line 17: popen(cmd, "r") on "cmd"
    er.selection = new vscode.Selection(16, col, 16, col);
    await vscode.commands.executeCommand('slicesec.showTaintPath');
    await vscode.commands.executeCommand('workbench.actions.view.problems');
    await vscode.commands.executeCommand('slicesec.results.focus');
    await vscode.window.showTextDocument(r, vscode.ViewColumn.Two);
    await vscode.commands.executeCommand('workbench.action.closeAuxiliaryBar');
    await vscode.commands.executeCommand('workbench.files.action.collapseExplorerFolders');
    await vscode.commands.executeCommand('workbench.action.focusPanel');
    for (let i = 0; i < 1; i++) await vscode.commands.executeCommand('workbench.action.decreaseViewSize');
    em.revealRange(new vscode.Range(5, 0, 5, 0), vscode.TextEditorRevealType.AtTop);
    er.revealRange(new vscode.Range(4, 0, 4, 0), vscode.TextEditorRevealType.AtTop);
    await vscode.window.showTextDocument(r, vscode.ViewColumn.Two);
    await sleep(3000);
    fs.writeFileSync(path.join(here, 'ready'), 'ok');
    for (let i = 0; i < 60 && !fs.existsSync(path.join(here, 'done')); i++) await sleep(1000);
  } catch (err) { fs.writeFileSync(path.join(here, 'error.txt'), String(err && err.stack)); }
};
