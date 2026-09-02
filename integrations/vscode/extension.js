'use strict';

const vscode = require('vscode');
const { execFile } = require('node:child_process');

function activate(context) {
  const diagnostics = vscode.languages.createDiagnosticCollection('repotruth');
  const status = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 90);
  status.command = 'repotruth.scan';
  status.text = '$(shield) RepoTruth';
  status.tooltip = 'Scan this workspace with RepoTruth';
  status.show();

  const scan = async () => {
    const folder = vscode.workspace.workspaceFolders?.[0];
    if (!folder) return vscode.window.showInformationMessage('RepoTruth: open a folder to scan it.');
    const python = vscode.workspace.getConfiguration('repotruth').get('pythonPath', 'python');
    status.text = '$(sync~spin) RepoTruth scanning';
    execFile(python, ['-m', 'repotruth', folder.uri.fsPath, '--format', 'json', '--fail-on', 'none'],
      { cwd: folder.uri.fsPath, maxBuffer: 16 * 1024 * 1024 }, async (error, stdout, stderr) => {
        diagnostics.clear();
        try {
          if (error && !stdout.trim()) throw new Error(stderr.trim() || error.message);
          const result = JSON.parse(stdout);
          const grouped = new Map();
          for (const finding of result.findings || []) {
            if (!finding.path || finding.path === '.') continue;
            const uri = vscode.Uri.joinPath(folder.uri, ...finding.path.replaceAll('\\', '/').split('/'));
            const line = Math.max(0, Number(finding.line || 1) - 1);
            const severity = finding.severity === 'high' ? vscode.DiagnosticSeverity.Error
              : finding.severity === 'medium' ? vscode.DiagnosticSeverity.Warning
              : vscode.DiagnosticSeverity.Information;
            const diagnostic = new vscode.Diagnostic(new vscode.Range(line, 0, line, 200), `${finding.title}: ${finding.message}`, severity);
            diagnostic.code = finding.rule_id;
            diagnostic.source = 'RepoTruth';
            grouped.set(uri.toString(), { uri, items: [...(grouped.get(uri.toString())?.items || []), diagnostic] });
          }
          for (const { uri, items } of grouped.values()) diagnostics.set(uri, items);
          const benchmark = result.facts?.benchmark;
          status.text = `$(shield) RepoTruth ${result.score}/100`;
          status.tooltip = benchmark ? `Safer than ${benchmark.percentile}% of ${benchmark.ecosystem} calibration projects` : 'Scan complete';
          vscode.window.showInformationMessage(`RepoTruth: ${result.grade} (${result.score}/100), ${result.findings.length} finding(s).`);
        } catch (scanError) {
          status.text = '$(error) RepoTruth unavailable';
          status.tooltip = String(scanError.message || scanError);
          vscode.window.showErrorMessage(`RepoTruth scan failed: ${scanError.message || scanError}`);
        }
      });
  };

  context.subscriptions.push(diagnostics, status, vscode.commands.registerCommand('repotruth.scan', scan));
  if (vscode.workspace.getConfiguration('repotruth').get('scanOnOpen', true)) scan();
}

function deactivate() {}
module.exports = { activate, deactivate };

