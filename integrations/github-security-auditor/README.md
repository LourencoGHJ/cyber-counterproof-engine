# GitHub Security Auditor

A small defensive integration that uses the GitHub REST API to review repository security hygiene.

## Current scope

- Reads repository metadata from the GitHub REST API.
- Checks whether a repository contains a `SECURITY.md` policy.
- Checks the default branch for common security automation workflows (CodeQL, secret scanning, Dependabot, CI and container scanning).
- Produces a JSON report with evidence URLs and explicit `unknown` results where the API cannot establish a fact.

This first version is intentionally read-only. It does not create issues, change settings, modify branches or alter repository contents.

## Requirements

- Python 3.10+
- A GitHub personal access token is optional for public repositories, but recommended for higher API rate limits.
- For private repositories or security-alert endpoints, create a fine-grained token with access only to the repositories you intend to audit and the minimum read permissions required. Never commit tokens.

## Run

From the repository root:

```bash
python integrations/github-security-auditor/audit.py --owner LourencoGHJ --repo cyber-counterproof-engine
```

With a token:

**PowerShell**
```powershell
$env:GITHUB_TOKEN = "github_pat_..."
python integrations/github-security-auditor/audit.py --owner LourencoGHJ --repo cyber-counterproof-engine
```

**Linux/macOS**
```bash
export GITHUB_TOKEN="github_pat_..."
python integrations/github-security-auditor/audit.py --owner LourencoGHJ --repo cyber-counterproof-engine
```

Save a report:

```bash
python integrations/github-security-auditor/audit.py --owner LourencoGHJ --repo cyber-counterproof-engine --output report.json
```

## Interpretation

- `present`: the API returned evidence that the control exists.
- `missing`: the API response confirms that the checked file or workflow is absent.
- `unknown`: the check could not be completed (for example, permission denied, rate limit, or an endpoint unavailable to the current token).

A missing workflow filename is only a heuristic: workflows may use different names or implement equivalent controls differently. This report is not a certification, penetration test, or complete security assessment.

## API use

The tool calls GitHub REST endpoints under `https://api.github.com`, sends the documented API version header, and uses only GET requests. See the [GitHub REST API documentation](https://docs.github.com/en/rest).

## Support

For support, open a GitHub issue in this repository or use the maintainer contact shown on the GitHub profile: https://github.com/LourencoGHJ
