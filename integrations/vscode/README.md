# RepoTruth for VS Code

This dependency-free extension runs the locally installed RepoTruth CLI, maps findings to editor diagnostics, and shows the score and peer benchmark in the status bar.

1. Install RepoTruth with `python -m pip install repotruth`.
2. Package this directory with `npx @vscode/vsce package`, then install the resulting VSIX.
3. Run **RepoTruth: Scan Workspace**, or leave `repotruth.scanOnOpen` enabled.

Set `repotruth.pythonPath` when RepoTruth is installed in a virtual environment.

