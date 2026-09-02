# Security policy

RepoTruth analyzes untrusted repositories as data. It never executes commands found in a README, manifest, source file, or generated report. Report values are escaped before HTML output.

The browser interface binds to localhost only, rejects cross-origin scan requests, accepts remote repositories only from public `https://github.com` URLs, and applies download time and repository size limits. Local-folder scanning should not be exposed as a network service.

Please report vulnerabilities privately through GitHub's security advisory feature. Do not include real credentials or private repository contents in a report.
