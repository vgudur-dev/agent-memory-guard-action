# 🛡️ Agent Memory Guard Action

[![OWASP](https://img.shields.io/badge/OWASP-Project-blue)](https://owasp.org/www-project-agent-memory-guard/)
[![License](https://img.shields.io/badge/License-Apache%202.0-green)](LICENSE)

A GitHub Action that scans AI agent memory for **poisoning attacks** using [OWASP Agent Memory Guard](https://github.com/OWASP/www-project-agent-memory-guard) — addressing OWASP ASI06: Agent Memory Poisoning.

## Quick Start

```yaml
- name: Scan agent memory for poisoning
  uses: vgudur-dev/agent-memory-guard-action@v1
  with:
    memory-file: './agent_memory/'
    threshold: 'medium'
    fail-on-finding: 'true'
```

## Inputs

| Input | Description | Default |
|-------|-------------|---------|
| `memory-file` | Path to memory file or directory to scan | `''` |
| `threshold` | Risk threshold: `low`, `medium`, `high` | `medium` |
| `output-format` | Output format: `text`, `json`, `sarif` | `text` |
| `fail-on-finding` | Fail the workflow if findings meet threshold | `true` |

## About

Powered by [OWASP Agent Memory Guard](https://github.com/OWASP/www-project-agent-memory-guard) — `pip install agent-memory-guard`

## License

Apache 2.0
