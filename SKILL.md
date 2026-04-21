---
name: secret-management
description: "Secure secret operations — store, inject, list, delete, exists. Agent never sees values; trusted scripts handle credential backends (macOS Keychain, Linux keyring, GCM, Vault) with JIT injection into subprocess scope."
allowed-tools: read_file file_search grep_search apply_patch create_file list_dir run_in_terminal
metadata:
  version: "0.2.0"
  source: "@tyler.given/skill-secrets-setup"
  supported_languages: "bash, zsh, powershell"
  supported_frameworks: "github-copilot-skills"
  supported_operating_systems: "macos, linux, windows"
  categories: "security, tooling, onboarding"
  tags: "secrets, credentials, keychain, keyring, vault, gcm, git-credential-manager, security, inject-model"
user-invocable: true
---

# secret-management

Secure secret operations with an inject model. The agent orchestrates; trusted scripts execute. **Values never enter LLM context through script code paths.** The injected subprocess is agent-chosen — it may produce output containing the value.

## Security Rules

| # | Rule |
|---|------|
| 1 | Agent MUST NEVER see, log, echo, or handle secret values. Note: the injected subprocess is agent-chosen and may produce output containing the value — use purpose-built commands. |
| 2 | No `get` / `read` / `reveal` operation exists — only `inject` (scoped subprocess) |
| 3 | `store` prompts the user interactively via `read -rsp` — agent issues the command, script handles input |
| 4 | Agent MUST get explicit user confirmation before `inject` and `delete` (approval gate) |
| 5 | Backend is pinned on first use to `~/.config/secret-ops/backend` — fail-closed, no silent downgrade |
| 6 | Audit log at `~/.config/secret-ops/audit.log` — timestamp, op, key, backend, exit code. **Never values.** |

## Operations

| Op | Command | Agent Sees |
|----|---------|------------|
| **store** | `secret-ops.sh store KEY` | Exit code only |
| **inject** | `secret-ops.sh inject KEY --confirm -- cmd args…` | Command stdout (not the secret) |
| **list** | `secret-ops.sh list` | Key names (GCM: unsupported) |
| **delete** | `secret-ops.sh delete KEY --confirm` | Exit code only |
| **exists** | `secret-ops.sh exists KEY` | Exit code: 0 = yes, 1 = no |

## Backends

| Backend | Tool | OS | Detection |
|---------|------|----|-----------|
| HashiCorp Vault | `vault` | Any | `command -v vault` + `VAULT_ADDR` set |
| macOS Keychain | `security` | macOS | `command -v security` on Darwin |
| Linux keyring | `keyctl` | Linux | `command -v keyctl` on Linux |
| Git Credential Manager | `git credential-manager` | Any | `git credential-manager --version` |

**Auto-detect priority:** Vault → Keychain → keyctl → GCM. First success pins the backend.
**Fail-closed:** If Vault is configured (VAULT_ADDR set, token valid) but unusable, detection fails rather than silently downgrading to a local backend.
**GCM limitation:** Does not support multiline secrets (PEM keys, JSON creds). Use Vault or Keychain for those.

## Protocol

1. **First invocation** — run `secret-ops.sh exists MY_KEY` (any key name) to trigger backend detection and pinning.
2. **Before `inject`** — ask the user: confirm key name and the command that will receive it. Pass `--confirm` flag.
3. **Before `delete`** — ask the user: confirm key name and that deletion is intentional. Pass `--confirm` flag.
4. **On failure** (non-zero exit) — report the error to the user. MUST NOT retry with a different backend.
5. **Never** read script source into context — execute via `bash <path>/scripts/secret-ops.sh`.
6. **Key names** must match `[A-Za-z0-9_.-]+` (max 256 chars). Reject anything else before calling scripts.

## Script Location

- **Unix:** `scripts/secret-ops.sh` (relative to skill install directory)
- **Windows:** `scripts/secret-ops.ps1`

## Authoritative Sources

- [Apple Keychain Services](https://developer.apple.com/documentation/security/keychain_services)
- [Linux keyctl man page](https://man7.org/linux/man-pages/man1/keyctl.1.html)
- [Git Credential Manager](https://github.com/git-ecosystem/git-credential-manager)
- [HashiCorp Vault](https://developer.hashicorp.com/vault/docs)
- [AI-Human Interaction Defaults](https://github.com/tyler555g/best-practices/blob/main/packages/content/technology_and_information/data_science_and_ai/ai-human-interaction-defaults.md)
- [12-Factor Agents](https://github.com/humanlayer/12-factor-agents)
