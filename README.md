# Cyber Counterproof Engine (CCE)

[![CI](https://github.com/LourencoGHJ/cyber-counterproof-engine/actions/workflows/ci.yml/badge.svg)](https://github.com/LourencoGHJ/cyber-counterproof-engine/actions/workflows/ci.yml)
[![CodeQL](https://github.com/LourencoGHJ/cyber-counterproof-engine/actions/workflows/codeql.yml/badge.svg)](https://github.com/LourencoGHJ/cyber-counterproof-engine/actions/workflows/codeql.yml)
[![Secret Scanning](https://github.com/LourencoGHJ/cyber-counterproof-engine/actions/workflows/secrets.yml/badge.svg)](https://github.com/LourencoGHJ/cyber-counterproof-engine/actions/workflows/secrets.yml)
[![Container Security](https://github.com/LourencoGHJ/cyber-counterproof-engine/actions/workflows/container-security.yml/badge.svg)](https://github.com/LourencoGHJ/cyber-counterproof-engine/actions/workflows/container-security.yml)

The **Cyber Counterproof Engine (CCE)** is a defensive cybersecurity project built with Python. It analyses declarative firewall policies, identifies risky configurations, compares expected and observed policies, and produces reproducible reports. It is also a practical learning environment for **Security Engineering** and **DevSecOps**.

> CCE is a defensive-audit prototype. Traffic evaluation is a simplified model; it does not replace a real firewall audit and does not automatically change firewall rules.

## Features

- **Policy auditing:** checks defensive requirements and modelled traffic scenarios.
- **Input validation:** validates policy and requirement structures before analysis.
- **Policy drift detection:** compares expected and observed rules by rule identifier.
- **Monitoring:** records periodic checks and drift findings in JSON history.
- **Reproducible evidence:** generates JSON reports and SHA-256 hashes for input files.
- **nftables integration:** validates rules files with `nft --check` and can inspect the active ruleset in read-only mode.
- **Live firewall dashboard:** serves current read-only iptables/ip6tables/nftables analysis over HTTP and pushes updates to browsers with Server-Sent Events; static history reports remain available separately.
- **Packet evaluation:** simulates a packet against a supported iptables filter-chain subset.
- **Rule conflict and chain-flow analysis:** identifies duplicates, potential shadowing, overlaps and structural chain-flow issues.
- **Container packaging:** provides a Docker image that runs the CLI as a non-root user.
- **Cross-platform adapter foundation:** platform detection and firewall adapters for Linux Netfilter and Windows Defender Firewall.
- **GitHub API security auditor:** a separate, read-only integration that checks repository security hygiene and emits JSON evidence. See [integrations/github-security-auditor](integrations/github-security-auditor/README.md).

## Platform support and validation

CCE uses a shared adapter contract and platform detection. Adapter implementation and real-host validation are tracked separately:

| Platform | Firewall integration | Current validation |
|---|---|---|
| Linux | Netfilter and nftables read-only collection | Implemented; real read-only collection executed on Manjaro Linux |
| Windows | Windows Defender Firewall through PowerShell and NetSecurity | Adapter implemented and simulated tests present; real Windows 11 validation remains open ([#20](https://github.com/LourencoGHJ/cyber-counterproof-engine/issues/20)) |

A shared adapter interface does not mean every platform has equivalent feature coverage or operational validation. The Linux adapter is the only adapter in this project state that has been exercised against a real host. Windows support must not be represented as production-validated.

## Security engineering and validation

The repository defines automated checks in GitHub Actions. Workflows run on code changes and, where configured, on a schedule.

| Practice | Tool | Purpose |
|---|---|---|
| CI and tests | GitHub Actions + pytest | Run automated tests and detect regressions |
| Python SAST | Bandit | Find potentially unsafe Python code patterns |
| Additional SAST | CodeQL | Perform static analysis of Python code |
| SCA | pip-audit | Check Python dependencies for known vulnerabilities |
| Secret scanning | Gitleaks | Search for potential secrets in Git history |
| IaC security | Terraform + Checkov | Validate Terraform configuration and selected security controls |
| Container security | Docker + Trivy | Scan OS and library vulnerabilities |
| Dependency management | Dependabot | Propose updates for dependencies and GitHub Actions |

The configured CI checks can act as quality gates. To block merges, enable branch rules and require the relevant status checks in repository settings. See [docs/DEVSECOPS.md](docs/DEVSECOPS.md).

## Local installation

Requirements: Python 3.11 or later.

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev]"
```

On Windows PowerShell, activate with `.venv\\Scripts\\Activate.ps1`.

## GitHub API integration

The [GitHub Security Auditor](integrations/github-security-auditor/README.md) uses the GitHub REST API in read-only mode. It demonstrates a concrete integration with GitHub and checks for a security policy and common security workflow files. It reports inconclusive checks as `unknown`; it does not claim that naming conventions prove a control is effective.

Run it from the repository root:

```bash
python integrations/github-security-auditor/audit.py --owner LourencoGHJ --repo cyber-counterproof-engine --output report.json
```

For token and permission guidance, see its dedicated README. Never commit personal access tokens.

## Responsible use

Use CCE only on systems and repositories you own or are authorized to assess. The GitHub API integration performs GET requests only and does not change repositories, account settings or security controls.
