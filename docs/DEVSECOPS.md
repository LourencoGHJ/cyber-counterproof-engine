# DevSecOps in Cyber Counterproof Engine

## Goal

Integrate quality and security checks into the CCE development lifecycle. Automated controls aim to identify issues early, produce repeatable results, and reduce the risk of merging unsafe changes.

## Automated controls

| Control | Workflow/tool | What it checks |
|---|---|---|
| CI and tests | GitHub Actions + pytest | Regressions and behaviour in the engine, CLI, and reports |
| Python SAST | Bandit | Potentially unsafe Python code patterns |
| Additional SAST | CodeQL | Static analysis of Python code |
| SCA | pip-audit | Published vulnerabilities in installed Python dependencies |
| Secret scanning | Gitleaks | Potential secrets across Git history |
| IaC validation | Terraform | Formatting and configuration validity |
| IaC security analysis | Checkov | Security controls for selected Terraform files |
| Dependency updates | Dependabot | Proposed updates for Python packages, Actions, and Terraform |

## Triggers

- CI runs on pushes to main and feat branches, pull requests targeting main, and manual dispatch.
- CodeQL runs on pushes, pull requests, manual dispatch, and a weekly schedule.
- Gitleaks runs on pushes, pull requests, manual dispatch, and a weekly schedule.
- Dependabot checks for updates weekly.

## Run checks locally

From the repository root, create and activate a virtual environment, then install the project and test dependencies:

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev]"
python -m pytest -v
```

Run Bandit:

```bash
python -m pip install bandit
bandit -r src/cce -ll
```

Run pip-audit:

```bash
python -m pip install pip-audit
pip-audit --skip-editable
```

Run Terraform checks from the repository root:

```bash
terraform fmt -check -recursive infra/terraform
terraform -chdir=infra/terraform init -backend=false
terraform -chdir=infra/terraform validate
```

Gitleaks can also be installed and run locally. The GitHub workflow checks the full Git history; a scan of the working directory alone may not cover historical commits.

## Quality gates and branch protection

CI steps return a failed result when a configured check does not pass, making them usable as quality gates. To actually prevent a merge, enable branch protection for main in the GitHub repository settings and require the relevant status checks.

Adding workflows does not enable branch protection automatically. Review the exact check names after the first workflow runs, then select the checks in the branch rules.

## Limitations and maintenance

- A clean scan does not prove that a project has no vulnerabilities; it only means the configured tools did not report issues in the areas they examined.
- CCE traffic evaluation is a simplified model and is not a substitute for controlled integration testing.
- The standalone secure Terraform fixture has a documented inline exception for Checkov control CKV2_AWS_5 because the snippet intentionally does not attach the security group to a workload. Other checks remain enabled. The intentionally insecure fixture is retained for learning and is not included in the quality gate.
- The workflows use major-version references for GitHub Actions. Keep these references current and review Dependabot proposals before merging.
- Never add real credentials to examples. If a valid secret is detected, revoke or rotate it first, then clean the history if required.
- Container-image scanning, publishing container artefacts, and isolated VM integration tests remain possible future phases.
