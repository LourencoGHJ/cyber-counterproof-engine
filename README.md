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
- **nftables integration:** validates rules files with nft --check and can inspect the active ruleset in read-only mode.
- **Local dashboard:** presents an HTML summary of monitoring history.
- **Container packaging:** provides a Docker image that runs the CLI as a non-root user.

## DevSecOps in the development lifecycle

The repository defines automated security checks in GitHub Actions. The workflows run on code changes and, where applicable, on a schedule.

| Practice | Tool | Purpose |
|---|---|---|
| CI and tests | GitHub Actions + pytest | Run automated tests and detect regressions |
| Python SAST | Bandit | Find potentially unsafe Python code patterns |
| Additional SAST | CodeQL | Perform static analysis of Python code |
| SCA | pip-audit | Check Python dependencies for known vulnerabilities |
| Secret scanning | Gitleaks | Search for potential secrets in Git history |
| IaC security | Terraform + Checkov | Validate Terraform configuration and check selected security controls |
| Container security | Docker + Trivy | Build the image and check OS/library vulnerabilities rated HIGH or CRITICAL |
| Dependency management | Dependabot | Propose updates for Python packages, GitHub Actions, and Terraform |

The configured CI checks can act as **quality gates** by failing when a check does not pass. To block merges, enable a branch ruleset for main in GitHub settings and require the relevant status checks. See [docs/DEVSECOPS.md](docs/DEVSECOPS.md) for local commands, control limitations, and recommended setup.

## Local installation

Requirements: Python 3.11 or later. The nft utility is also required for the firewall validation and inspection commands.

    python -m venv .venv
    source .venv/bin/activate
    python -m pip install -e ".[dev]"

On Windows, activate the environment with **.venv\Scripts\Activate.ps1**.

## Usage examples

Audit the example policy:

    cce audit --policy config/policy.json --requirements config/requirements.json --output reports/audit.json

Compare expected and observed policies:

    cce compare-policy --expected config/monitor-expected.json --observed config/monitor-observed.json --output reports/comparison.json

Validate an nftables file without applying rules:

    cce validate-nft --file examples/cce-test.nft --output reports/nft-validation.json

Inspect the active ruleset in read-only mode:

    cce inspect-live --output reports/live-summary.json

Generate a local dashboard from monitoring history:

    cce dashboard --history reports/monitor-history.json --output reports/dashboard.html

## Build and smoke-test the Docker image

Build the image locally and confirm that the CLI starts:

    docker build --pull -t cce:local .
    docker run --rm cce:local --help

The image runs as UID 10001 rather than root. To run an audit, mount input files read-only and provide a writable output directory. Run the container with least privilege and only mount files needed for the task. Image vulnerability scanning runs in the container-security workflow; the workflow does not publish the image to a registry.

The same commands can be run with **python -m cce.cli** after the project is installed in a Python environment.

## Security scope and limitations

- Audit and validation commands do not apply rules to the firewall.
- Live ruleset inspection is read-only.
- Traffic evaluation represents only the simplified model implemented by CCE.
- SHA-256 hashes identify files; they are not digital signatures and do not prove report authenticity.
- The Docker workflow builds and scans a local CI image only; it does not sign or publish releases.
- Trivy fails the image scan for detected HIGH/CRITICAL OS or library vulnerabilities when a fix is available. Scanning does not prove the image is free of vulnerabilities.
- Run infrastructure and network tests only in authorised, isolated environments.

## Career Path & Professional Relevance

CCE provides practical work in defensive security and automated security controls, while distinguishing implemented capabilities from future goals.

### Security Engineer

**Status:** Practical foundation in development for junior roles.

The project provides experience with:

- Defensive security and security-policy validation.
- Linux system administration.
- Firewall configuration analysis with nftables.
- Detection of drift between expected and observed policies.
- Periodic monitoring and evidence recording.
- Automated tests and technical reporting.

This work supports further development toward **Junior Security Engineer** roles and other positions related to systems and infrastructure security.

### DevSecOps Engineer

**Status:** In development, with CI and security-analysis workflows defined in the repository.

The DevSecOps track integrates security into the development lifecycle rather than leaving it until final review. CCE demonstrates this approach through:

- **CI/CD:** GitHub Actions workflows that automatically run tests and checks.
- **SAST:** Python analysis with Bandit and CodeQL.
- **SCA:** Dependency auditing with pip-audit.
- **Secret scanning:** Gitleaks checks for potential secrets in Git history.
- **Infrastructure as Code security:** Terraform validation and Checkov analysis.
- **Container security:** Docker image build, non-root execution, and Trivy vulnerability scanning.
- **Dependency management:** Dependabot update proposals.
- **Quality gates:** checks that return a failure result when configured controls do not pass.

Mandatory branch protection, image signing, and secure container publishing still require additional configuration or development. They are not represented as completed in this phase.

### Development Goals

1. Configure branch protection so relevant checks are required before merging.
2. Review findings and document the handling of false positives from SAST, SCA, secret scanning, and image scanning.
3. Consider image signing and registry publishing if the project is distributed as a container.
4. Expand test coverage, especially for malformed input and failure handling.

CCE is a practical learning project intended to demonstrate **Security Engineering** and **DevSecOps** skills, with explicit documentation of each control's scope and limitations.
