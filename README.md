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
- **Live firewall dashboard:** serves current read-only iptables/ip6tables/nftables analysis over HTTP and pushes updates to browsers with Server-Sent Events; static history reports remain available separately.
- **Packet evaluation:** simulates a packet against a supported iptables filter-chain subset, including TCP flag masks, and explains the rule-by-rule result.
- **Scenario runner:** checks expected ACCEPT, DROP, REJECT, and INCONCLUSIVE outcomes, including SYN-only matching, from synthetic fixtures.
- **Rule conflict analysis:** detects exact duplicates, redundant rules, proven shadowing, potential verdict overlaps, and TCP rules whose flag conditions can never match.
- **Chain-flow analysis:** maps explicit iptables jump/goto references, structural reachability from base chains, unresolved targets, and potential recursive chain components.
- **Policy-aware consolidated analysis:** optionally compares declared base-chain policies and supported rule selectors with supplied IPv4/IPv6 snapshots, retaining policy evidence hashes.
- **Container packaging:** provides a Docker image that runs the CLI as a non-root user.
- **Cross-platform adapter foundation:** platform detection and firewall adapters for Linux Netfilter and Windows Defender Firewall.

## Platform support and validation

CCE uses a shared adapter contract and platform detection. Adapter implementation and real-host validation are tracked separately:

| Platform | Firewall integration | Current validation |
|---|---|---|
| Linux | Netfilter: `iptables-save`, `ip6tables-save`, and nftables read-only collection | Implemented; real read-only collection executed on Manjaro Linux |
| Windows | Windows Defender Firewall through PowerShell and `NetSecurity` / `ActiveStore` | Adapter implemented and simulated tests present; real Windows 11 validation remains open ([#20](https://github.com/LourencoGHJ/cyber-counterproof-engine/issues/20)) |

A shared adapter interface does not mean every platform has equivalent feature coverage or operational validation. The Linux adapter is the only adapter in this project state that has been exercised against a real host. Windows support must not be represented as production-validated.


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

On Windows PowerShell, activate the environment with **.venv\Scripts\Activate.ps1**. In Windows CMD, use **.venv\Scripts\activate.bat**. After activation, the `cce` command is available. Without activation, invoke **.venv\Scripts\cce.exe** directly (for example, `.venv\Scripts\cce.exe --help`).

## Usage examples

Identify the host and check available CCE capabilities:

    cce doctor
    cce platform-info

Run a one-shot read-only firewall collection on a Linux host:

    cce collect --policy config/policy.json --once --source auto --timeout 10 --sudo-readonly --output reports/collection.json

The `--sudo-readonly` option is for hosts where the fixed firewall-listing commands require elevation. CCE does not run the web service as root and does not apply, remove, or modify rules.

Audit the example policy:

    cce audit --policy config/policy.json --requirements config/requirements.json --output reports/audit.json

Compare expected and observed policies:

    cce compare-policy --expected config/monitor-expected.json --observed config/monitor-observed.json --output reports/comparison.json

Validate an nftables file without applying rules:

    cce validate-nft --file examples/cce-test.nft --output reports/nft-validation.json

Inspect the active ruleset in read-only mode:

    cce inspect-live --output reports/live-summary.json

Generate the local security operations dashboard from monitoring history:

    cce dashboard --history reports/monitor-history.json --output reports/dashboard.html

The dashboard is a simple, responsive HTML report with the latest assessment, counts for PASS/DRIFT/INCONCLUSIVE/ERROR, findings from the latest run, and a searchable, filterable, sortable table of recent executions. Execution details can be expanded, and the report can be printed. It uses only data present in the JSON history, has no external assets, and does not present itself as a live firewall or host-monitoring console.

### Linux live dashboard

On Linux, the live dashboard collects `iptables-save`, `ip6tables-save`, and `nft -j list ruleset` in read-only mode:

    cce serve-dashboard --policy config/policy.json --host 127.0.0.1 --port 8765 --source auto --interval-ms 1000

### Windows 11 live dashboard

On Windows, `--source auto` selects the Windows Defender Firewall adapter and queries the local `ActiveStore` through PowerShell and the `NetSecurity` module. Run the service on the same Windows host whose firewall is being inspected:

    .\.venv\Scripts\python.exe -m cce.cli serve-dashboard --policy config/policy.json --host 127.0.0.1 --port 8765 --source auto --interval-ms 10000 --timeout 60

Open **http://127.0.0.1:8765/** in a browser. The Windows view presents aggregate rule counts (total, enabled, disabled, inbound, outbound, allow and block), profile state and default profile actions. It deliberately does not publish individual rules, application paths, addresses, ports or interface selectors.

The Windows dashboard currently provides a live inventory, not a semantic compliance assessment. Its overall status remains `INCONCLUSIVE` until a Windows policy comparator is implemented. It runs as the current Windows user; access denied or an unavailable `NetSecurity` module is reported without attempting elevation or changing firewall settings.

The live page uses Server-Sent Events (SSE). It sends a new data event when collected evidence or the analysis changes and lightweight heartbeats when the snapshot is unchanged. The interval is a polling target, not a guarantee of end-to-end latency. Windows collection invokes PowerShell and queries associated filters for each rule; start with 5000 ms or more and inspect the measured collection/cycle duration before reducing the interval.

The HTTP service binds to `127.0.0.1` by default. Keep it local during testing. Do not expose the built-in HTTP server directly to the public Internet.

The web service should run as an unprivileged user. If firewall listing requires elevated permissions, configure a narrowly scoped sudoers rule and start CCE with `--sudo-readonly`. This uses non-interactive `sudo -n` only for the fixed listing commands; the web process itself does not run as root. Adapt the binary paths to the host (check them with `command -v iptables-save ip6tables-save nft`) and validate the file with `visudo`:

    sudo visudo -f /etc/sudoers.d/cce-firewall-read
    cce-dashboard ALL=(root) NOPASSWD: /usr/sbin/iptables-save "", /usr/sbin/ip6tables-save "", /usr/sbin/nft -j list ruleset

The empty argument string on the two iptables commands restricts them to no arguments; the nft command is restricted to the exact JSON list-ruleset invocation. Add only the commands actually installed on the host. Then run:

    cce serve-dashboard --policy config/policy.json --host 127.0.0.1 --port 8765 --source auto --interval-ms 1000 --sudo-readonly

If the exact sudoers permission is absent or `sudo` cannot run non-interactively, the collector reports an error and does not prompt for a password.

**Remote access:** keep the service bound to `127.0.0.1` and expose it through a TLS reverse proxy or private VPN where possible. Direct non-loopback binding requires an explicit acknowledgement, a token of at least 32 characters, and a trusted VPN/HTTPS transport. Set the token in the environment; do not pass it as a command-line argument:

    export CCE_DASHBOARD_TOKEN="$(python -c 'import secrets; print(secrets.token_urlsafe(32))')"
    cce serve-dashboard --policy config/policy.json --host 0.0.0.0 --port 8765 --source auto --interval-ms 1000 --allow-remote --trusted-transport --sudo-readonly

Remote access uses HTTP Basic authentication (username `cce`, password from `CCE_DASHBOARD_TOKEN`). The built-in server does not provide TLS; never expose its plain HTTP port directly to the public Internet. Restrict access at the VPN or reverse proxy and keep the token secret.

The static `cce dashboard` command remains intended for an exported historical HTML report; use `cce serve-dashboard` for live collection.

Evaluate a synthetic packet against an offline iptables-save snapshot (read-only):

    cce evaluate-packet --snapshot examples/firewall-test.save --family ipv4 --hook INPUT --packet examples/packets/https-request.json --output reports/evaluation.json

The example snapshot and packet are synthetic. A conclusive `ACCEPT`, `DROP`, or `REJECT` evaluation exits with code 0; an `INCONCLUSIVE` result exits with code 3. Invalid input exits with code 2. Packet IP addresses and values are omitted from the JSON report; input-file SHA-256 hashes are retained as evidence identifiers.

Run the synthetic packet scenarios together:

    cce evaluate-scenarios --manifest examples/firewall-scenarios.json --output reports/scenarios/summary.json

The scenario runner checks five expected outcomes: HTTPS `ACCEPT`, source-restricted SSH `DROP`, Telnet `REJECT`, an unsupported rate-limit rule `INCONCLUSIVE`, and a SYN+ACK packet that must not match a SYN-only rule. The evaluator supports `--tcp-flags mask comp` for the standard SYN, ACK, FIN, RST, URG, and PSH flags, including the `ALL` and `NONE` aliases. It compares only the flags selected by the mask; missing packet-flag metadata produces `INCONCLUSIVE` when those bits are required. The IR schema is now version `1.1`. The scenario runner exits with code 0 when every actual result matches its expected result, code 1 when any scenario differs, and code 2 for invalid inputs. An expected `INCONCLUSIVE` is a successful test of conservative behaviour, not a conclusive packet verdict. The JSON report contains a machine-readable trace and Portuguese explanations for each evaluated rule and final decision.

Analyze a synthetic iptables-save snapshot for duplicate, redundant, shadowed, and potentially overlapping terminal rules:

    cce analyze-rule-conflicts --snapshot examples/firewall-scenarios/conflicting-rules.save --family ipv4 --output reports/conflicts/analysis.json

The analysis compares only fully interpreted terminal rules within the same chain of the `filter` table. It reports full shadowing as proven only when an earlier rule covers every packet that could match a later rule. Opposing verdicts that may match some of the same traffic, without proven full coverage, are reported as potential overlaps. It also detects supported TCP flag conditions that are impossible to satisfy and reports them as unmatchable rules, separately from shadowed rules. Partially interpreted and non-terminal rules are counted but excluded. Exit code 0 means no findings, 1 means findings were detected, and 2 means invalid or malformed input. The report omits raw network/interface selectors and original rule text; it retains the snapshot path and SHA-256 evidence hash.

Analyze structural control flow between iptables filter chains:

    cce analyze-chain-flow --snapshot /path/to/iptables.save --family ipv4 --output reports/chain-flow.json

The chain-flow report preserves explicit jump/goto references in snapshot line order, identifies user chains with no structural path from a base chain, and detects strongly connected components that form potential recursive paths. Reachability is structural: rule selectors are not evaluated, so a reference is not proof that a packet can traverse it. Cycles are reported as potential, not as proven runtime recursion. Unresolved targets remain ambiguous because they may be unsupported extension targets rather than missing chains. Exit code 0 means no findings, 1 means structural findings were reported, 3 means the analysis is partial because the snapshot contains malformed lines, and 2 indicates invalid input.

Run a consolidated offline analysis of one or both firewall families:

    cce analyze-snapshot --ipv4 /path/to/iptables.save --ipv6 /path/to/ip6tables.save --output reports/snapshot-analysis.json

Optionally compare the snapshots with the declarative policy:

    cce analyze-snapshot --policy config/policy.json --ipv4 /path/to/iptables.save --ipv6 /path/to/ip6tables.save --output reports/full-security-audit.json

The consolidated report combines structural inventory, IR interpretation metrics, heuristic SSH/TCP/22 candidates, supported terminal-rule conflict analysis, and a structural chain-flow graph. Either `--ipv4` or `--ipv6` may be omitted, but an omitted family is explicitly reported as not analysed.

When `--policy` is supplied, CCE validates the policy, compares the declared INPUT/OUTPUT/FORWARD base-chain policies for the supplied families, and reuses the supported semantic rule comparison for each supplied snapshot. The report includes policy and snapshot SHA-256 evidence hashes, policy comparison counts, and consolidated policy findings. A conclusive policy mismatch changes the overall status to `DRIFT`; otherwise the overall assessment remains `INCONCLUSIVE`, including when all supported fields match. A match does not prove actual packet reachability or full firewall compliance.

Exit code 1 indicates static rule-conflict findings or conclusive policy drift, 3 indicates that the report was generated without conclusive policy drift but the overall assessment remains inconclusive, and 2 indicates invalid input. Malformed snapshots retain their structural summary; policy comparisons for the affected family become inconclusive instead of claiming that expected rules are missing. The report does not include original rule text or network/port selector values.

## Build and smoke-test the Docker image

Build the image locally and confirm that the CLI starts:

    docker build --pull -t cce:local .
    docker run --rm cce:local --help

The image runs as UID 10001 rather than root. To run an audit, mount input files read-only and provide a writable output directory. Run the container with least privilege and only mount files needed for the task. Image vulnerability scanning runs in the container-security workflow; the workflow does not publish the image to a registry.

Compare declarative policy rules with IPv4/IPv6 iptables-save snapshots:

    cce compare-iptables-save --policy config/policy.json --ipv4 /path/to/iptables.save --ipv6 /path/to/ip6tables.save --output reports/semantic-comparison.json

Rule comparison supports the policy fields `chain`, `action`, `protocol`, `source`, `destination_port`, optional `connection_states`, and exact `input_interface` / `output_interface` names. Connection states use the supported iptables values `INVALID`, `NEW`, `ESTABLISHED`, `RELATED`, `UNTRACKED`, `SNAT` and `DNAT`; `--ctstate` and the legacy `--state` selector are compared as sets. An omitted field does not impose that selector as a policy restriction.

Interface names are compared exactly. A rule constrained to one interface is narrower than a policy that permits any interface; an observed rule without an interface restriction is broader than a policy that requires one; conflicting exact interface names are disjoint. Wildcards (for example `eth+`), negated interface selectors, and malformed or unsupported selectors remain `INCONCLUSIVE`. The schema does not silently reinterpret interface patterns as exact names.

The comparator classifies exact matches, broader/narrower scopes, disjoint scopes, partial overlaps, missing rules and action mismatches. A broader ACCEPT rule or a narrower DROP rule is flagged as a potential exposure; other deviations retain their respective scope/coverage classifications. The `service` field is descriptive and is not translated into firewall semantics.

For supported JUMP/GOTO paths, CCE follows user-chain transfers and RETURN behaviour and intersects the supported selectors along the path. A path is conclusive only where the intersection covers the complete policy scope. It does not yet aggregate multiple partial branches to prove that their union covers one policy rule; those cases remain `INCONCLUSIVE` and are tracked in [#18](https://github.com/LourencoGHJ/cyber-counterproof-engine/issues/18). Negated conditions, partially interpreted rules, unsupported selectors, recursive paths and ambiguous candidates remain conservative.

The comparator is limited to the supported iptables `filter` subset for INPUT/OUTPUT/FORWARD policies. It does not establish kernel-level packet reachability, complete first-match semantics for every construct, NAT or routing behaviour. Native nftables semantic coverage is also limited to base-chain policies and structural inventory; see [#19](https://github.com/LourencoGHJ/cyber-counterproof-engine/issues/19). A rule-level match is not a global compliance verdict.

The same commands can be run with **python -m cce.cli** after the project is installed in a Python environment.

## Current roadmap

The implementation status, evidence, known limitations and prioritised work are maintained in [docs/ROADMAP.md](docs/ROADMAP.md). Exact input/output interface comparison is implemented and integrated ([#17](https://github.com/LourencoGHJ/cyber-counterproof-engine/issues/17), closed). Active work: [#18 partial branch aggregation](https://github.com/LourencoGHJ/cyber-counterproof-engine/issues/18), [#19 native nftables semantics](https://github.com/LourencoGHJ/cyber-counterproof-engine/issues/19), and [#20 real Windows validation](https://github.com/LourencoGHJ/cyber-counterproof-engine/issues/20).

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
