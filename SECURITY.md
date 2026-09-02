# Security policy

RepoTruth analyzes untrusted repositories as data by default. It never executes README text, source files, or generated reports. Optional runtime verification may execute a narrowly detected test/build command only inside the documented offline Docker sandbox. Report values are escaped before HTML output.

The browser interface binds to localhost only, rejects cross-origin scan requests, accepts remote repositories only from public `https://github.com` URLs, and applies download time and repository size limits. Local-folder scanning should not be exposed as a network service.

Please report vulnerabilities privately through GitHub's security advisory feature. Do not include real credentials or private repository contents in a report.
