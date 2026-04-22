#!/usr/bin/env bash
# secret-ops.sh — secure secret operations (inject model)
# Values never printed to stdout. Agent calls this; never reads source.
set -euo pipefail

CONFIG_DIR="${HOME}/.config/secret-ops"
BACKEND_FILE="${CONFIG_DIR}/backend"
AUDIT_LOG="${CONFIG_DIR}/audit.log"
LOCK_FILE="${CONFIG_DIR}/.backend.lock"
VALID_BACKENDS="vault keychain keyring gcm"
SERVICE_PREFIX="secret-ops:"

mkdir -p "$CONFIG_DIR"
chmod 700 "$CONFIG_DIR"

# ── Key validation ───────────────────────────────────────────────────────────
_validate_key() {
  local key="$1"
  if [[ ! "$key" =~ ^[A-Za-z0-9_.-]+$ ]]; then
    echo "ERROR: Key name must match [A-Za-z0-9_.-]+" >&2
    return 1
  fi
  if [ "${#key}" -gt 256 ]; then
    echo "ERROR: Key name exceeds 256 characters" >&2
    return 1
  fi
}

# ── Audit ────────────────────────────────────────────────────────────────────
_audit() {
  local op="$1" key="${2:-}" rc="${3:-0}"
  local backend
  backend=$(_read_backend 2>/dev/null || echo "none")
  # Sanitize key for log safety (replace control chars)
  local safe_key
  safe_key=$(printf '%s' "$key" | tr -d '\n\r\t')
  printf '%s op=%s key=%s backend=%s rc=%s\n' \
    "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$op" "$safe_key" "$backend" "$rc" \
    >> "$AUDIT_LOG"
}

# ── Backend detection & pinning ──────────────────────────────────────────────
_read_backend() {
  if [ -f "$BACKEND_FILE" ]; then
    local b
    b=$(cat "$BACKEND_FILE")
    # Validate pinned backend is in allowlist
    if echo "$VALID_BACKENDS" | grep -qw "$b"; then
      echo "$b"
      return 0
    fi
    echo "ERROR: Invalid pinned backend '$b' — delete $BACKEND_FILE to re-detect" >&2
    return 1
  fi
  return 1
}

_probe_vault() {
  # Verify vault can write+delete in our namespace (not just that token is valid)
  local probe_key="_probe_${RANDOM}_$$"
  vault kv put "secret/secret-ops/${probe_key}" value=probe_test &>/dev/null 2>&1 || return 1
  vault kv delete "secret/secret-ops/${probe_key}" &>/dev/null 2>&1 || return 1
}

_probe_keyring() {
  # Verify keyctl can store+retrieve in user keyring (not just that binary exists)
  local probe_key="_probe_${RANDOM}_$$" kid
  kid=$(printf 'probe_test' | keyctl padd user "${SERVICE_PREFIX}${probe_key}" @u 2>/dev/null) || return 1
  keyctl unlink "$kid" @u &>/dev/null 2>&1 || return 1
}

_detect_backend() {
  # If VAULT_ADDR is set and vault binary exists, the user intends Vault — fail closed on any issue
  if [ -n "${VAULT_ADDR:-}" ] && command -v vault &>/dev/null; then
    if ! vault token lookup &>/dev/null 2>&1; then
      echo "ERROR: Vault is configured (VAULT_ADDR set) but authentication failed." >&2
      echo "Fix Vault auth, or unset VAULT_ADDR to use a local backend." >&2
      return 1
    fi
    if _probe_vault; then
      echo "vault"
      return 0
    fi
    echo "ERROR: Vault is configured (VAULT_ADDR set, token valid) but probe to secret/secret-ops/ failed." >&2
    echo "Fix Vault permissions, or unset VAULT_ADDR to use a local backend." >&2
    return 1
  fi
  if [ "$(uname -s)" = "Darwin" ] && command -v security &>/dev/null; then
    echo "keychain"
  elif [ "$(uname -s)" = "Linux" ] && command -v keyctl &>/dev/null && _probe_keyring; then
    echo "keyring"
  elif git credential-manager --version &>/dev/null 2>&1; then
    echo "gcm"
  else
    return 1
  fi
}

_ensure_backend() {
  local backend
  if backend=$(_read_backend); then
    echo "$backend"
    return 0
  fi

  # Locked detection + pinning (flock if available, otherwise best-effort)
  if command -v flock &>/dev/null; then
    (
      flock -x 200
      # Re-check after acquiring lock (another process may have pinned)
      if [ -f "$BACKEND_FILE" ]; then
        cat "$BACKEND_FILE"
        return 0
      fi
      backend=$(_detect_backend) || { echo "ERROR: No supported secret backend found" >&2; return 1; }
      printf '%s' "$backend" > "$BACKEND_FILE"
      echo "Backend pinned: $backend" >&2
      echo "$backend"
    ) 200>"$LOCK_FILE"
  else
    # macOS lacks flock — use mkdir-based lock
    local lock_dir="${CONFIG_DIR}/.backend.lockdir"
    local attempts=0
    while ! mkdir "$lock_dir" 2>/dev/null; do
      attempts=$((attempts + 1))
      if [ "$attempts" -gt 20 ]; then
        echo "ERROR: Could not acquire backend lock" >&2
        return 1
      fi
      sleep 0.1
    done
    trap "rmdir '${lock_dir}' 2>/dev/null || true" EXIT
    # Re-check after acquiring lock
    if [ -f "$BACKEND_FILE" ]; then
      cat "$BACKEND_FILE"
      rmdir "$lock_dir" 2>/dev/null || true
      return 0
    fi
    backend=$(_detect_backend) || { rmdir "$lock_dir" 2>/dev/null || true; echo "ERROR: No supported secret backend found" >&2; return 1; }
    printf '%s' "$backend" > "$BACKEND_FILE"
    rmdir "$lock_dir" 2>/dev/null || true
    echo "Backend pinned: $backend" >&2
    echo "$backend"
  fi
}

# ── Backend operations ───────────────────────────────────────────────────────

# -- Store (secrets via stdin, never argv) --
_store_keychain() {
  local key="$1"
  local svc="${SERVICE_PREFIX}${key}"
  if [ "$(uname -s)" = "Darwin" ] && command -v osascript >/dev/null 2>&1; then
    # macOS — GUI dialog; osascript passes value directly to security -w so
    # it never flows through the agent's shell or pseudo-TTY.
    osascript \
      -e "set _p to text returned of (display dialog \"Enter secret for ${key}:\" default answer \"\" with hidden answer buttons {\"Cancel\",\"OK\"} default button \"OK\")" \
      -e "do shell script \"security add-generic-password -a secret-ops -s '${svc}' -U -w \" & quoted form of _p" \
      2>&1 || return 1
  elif [ -t 0 ]; then
    # Non-macOS with real TTY — read interactively then pass as -w arg
    IFS= read -rsp "Enter secret for ${key}: " _sec_val; echo >&2
    security add-generic-password -a "secret-ops" -s "$svc" -U -w "$_sec_val"
    _sec_val=""
  else
    echo "ERROR: No TTY and no GUI available — cannot prompt for secret" >&2
    return 1
  fi
}
_store_keyring() {
  local key="$1" store_rc=0
  IFS= read -rsp "Enter secret for $key: " val; echo
  printf '%s' "$val" | keyctl padd user "${SERVICE_PREFIX}${key}" @u >/dev/null || store_rc=$?
  val=""
  return "$store_rc"
}
_store_gcm() {
  local key="$1" store_rc=0
  IFS= read -rsp "Enter secret for $key: " val; echo
  printf 'protocol=https\nhost=secret-ops.local\npath=%s\nusername=secret-ops\npassword=%s\n\n' "$key" "$val" \
    | git -c credential.helper=manager -c credential.useHttpPath=true credential approve || store_rc=$?
  val=""
  return "$store_rc"
}
_store_vault() {
  local key="$1" store_rc=0
  IFS= read -rsp "Enter secret for $key: " val; echo
  printf '%s' "$val" | vault kv put "secret/secret-ops/$key" value=- >/dev/null || store_rc=$?
  val=""
  return "$store_rc"
}

# -- Exists --
_exists_keychain() { security find-generic-password -a "secret-ops" -s "${SERVICE_PREFIX}$1" &>/dev/null; }
_exists_keyring()  { keyctl search @u user "${SERVICE_PREFIX}$1" &>/dev/null; }
_exists_gcm()      { printf 'protocol=https\nhost=secret-ops.local\npath=%s\nusername=secret-ops\n\n' "$1" | git -c credential.helper=manager -c credential.useHttpPath=true credential fill 2>/dev/null | grep -q "^password="; }
_exists_vault()    { vault kv get -field=value "secret/secret-ops/$1" &>/dev/null; }

# -- Delete --
_delete_keychain() { security delete-generic-password -a "secret-ops" -s "${SERVICE_PREFIX}$1" &>/dev/null; }
_delete_keyring()  { local kid; kid=$(keyctl search @u user "${SERVICE_PREFIX}$1" 2>/dev/null) && keyctl unlink "$kid" @u &>/dev/null; }
_delete_gcm() {
  local key="$1"
  # Retrieve actual credential to reject it properly
  local fill_output
  fill_output=$(printf 'protocol=https\nhost=secret-ops.local\npath=%s\nusername=secret-ops\n\n' "$key" | git -c credential.helper=manager -c credential.useHttpPath=true credential fill 2>/dev/null) || true
  printf '%s\n\n' "$fill_output" | git -c credential.helper=manager -c credential.useHttpPath=true credential reject
}
_delete_vault()    { vault kv delete "secret/secret-ops/$1" &>/dev/null; }

# -- List --
_list_keychain() { security dump-keychain 2>/dev/null | grep '"svce"' | sed 's/.*="//;s/".*//;' | grep "^${SERVICE_PREFIX}" | sed "s/^${SERVICE_PREFIX}//"; }
_list_keyring()  { keyctl show @u 2>/dev/null | awk 'NR>1 {print $NF}' | grep "^${SERVICE_PREFIX}" | sed "s/^${SERVICE_PREFIX}//"; }
_list_gcm()      { echo "(GCM does not support list — use OS credential manager UI)" >&2; return 0; }
_list_vault()    { vault kv list -format=json secret/secret-ops/ 2>/dev/null | python3 -c "import sys,json;[print(k) for k in json.load(sys.stdin)]" 2>/dev/null || vault kv list secret/secret-ops/ 2>/dev/null; }

# -- Inject (retrieve + scoped subprocess — subshell+exec, no argv leak) --
_get_keychain() { security find-generic-password -a "secret-ops" -s "${SERVICE_PREFIX}$1" -w 2>/dev/null; }
_get_keyring()  { local kid; kid=$(keyctl search @u user "${SERVICE_PREFIX}$1" 2>/dev/null) && keyctl pipe "$kid" 2>/dev/null; }
_get_gcm()      { printf 'protocol=https\nhost=secret-ops.local\npath=%s\nusername=secret-ops\n\n' "$1" | git -c credential.helper=manager -c credential.useHttpPath=true credential fill 2>/dev/null | grep "^password=" | cut -d= -f2-; }
_get_vault()    { vault kv get -field=value "secret/secret-ops/$1" 2>/dev/null; }

# ── Dispatch ─────────────────────────────────────────────────────────────────
_dispatch() {
  local op="$1" backend="$2" key="${3:-}"
  local fn="_${op}_${backend}"
  if ! type "$fn" &>/dev/null; then
    echo "ERROR: Operation '$op' not supported on backend '$backend'" >&2
    return 1
  fi
  "$fn" "$key"
}

# ── Main ─────────────────────────────────────────────────────────────────────
main() {
  local op="${1:-help}"
  shift || true

  case "$op" in
    store)
      [ $# -lt 1 ] && { echo "Usage: secret-ops.sh store KEY" >&2; exit 1; }
      local key="$1" backend rc=0
      _validate_key "$key" || exit 1
      backend=$(_ensure_backend) || exit 1
      _dispatch store "$backend" "$key" || rc=$?
      _audit store "$key" "$rc"
      exit "$rc"
      ;;

    inject)
      [ $# -lt 1 ] && { echo "Usage: secret-ops.sh inject KEY [--confirm] -- cmd args…" >&2; exit 1; }
      local key="$1"; shift
      _validate_key "$key" || exit 1

      # Require --confirm flag (approval gate)
      local confirmed=false
      while [ $# -gt 0 ] && [ "$1" != "--" ]; do
        case "$1" in
          --confirm) confirmed=true ;;
          *) echo "ERROR: Unknown flag '$1'" >&2; exit 1 ;;
        esac
        shift
      done
      if [ "$confirmed" != "true" ]; then
        echo "ERROR: inject requires --confirm flag (approval gate)" >&2
        exit 1
      fi
      [ "${1:-}" = "--" ] && shift || { echo "ERROR: Missing '--' separator" >&2; exit 1; }
      [ $# -lt 1 ] && { echo "ERROR: No command specified after '--'" >&2; exit 1; }

      # Inject requires env-var-safe key name (no dots or hyphens)
      if [[ ! "$key" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]]; then
        echo "ERROR: Key '$key' is not a valid environment variable name (use [A-Za-z_][A-Za-z0-9_]*)" >&2
        exit 1
      fi

      local backend rc=0
      backend=$(_ensure_backend) || exit 1
      # Avoid command substitution ($()) which strips ALL trailing newlines
      local val
      IFS= read -r -d '' val < <(_dispatch get "$backend" "$key"; printf '\0') || true
      # Strip single trailing newline added by command stdout (not part of value)
      val="${val%$'\n'}"
      [ -z "$val" ] && { echo "ERROR: Secret '$key' not found" >&2; _audit inject "$key" 1; exit 1; }
      # Inject via subshell+exec: secret is in shell memory only, never in argv
      (export "${key}=${val}"; val=""; exec "$@") && rc=0 || rc=$?
      _audit inject "$key" "$rc"
      exit "$rc"
      ;;

    list)
      local backend rc=0
      backend=$(_ensure_backend) || exit 1
      _dispatch list "$backend" "" || rc=$?
      _audit list "" "$rc"
      exit "$rc"
      ;;

    delete)
      [ $# -lt 1 ] && { echo "Usage: secret-ops.sh delete KEY [--confirm]" >&2; exit 1; }
      local key="$1"; shift
      _validate_key "$key" || exit 1

      # Require --confirm flag (approval gate)
      local confirmed=false
      for arg in "$@"; do
        [ "$arg" = "--confirm" ] && confirmed=true
      done
      if [ "$confirmed" != "true" ]; then
        echo "ERROR: delete requires --confirm flag (approval gate)" >&2
        exit 1
      fi

      local backend rc=0
      backend=$(_ensure_backend) || exit 1
      _dispatch delete "$backend" "$key" || rc=$?
      _audit delete "$key" "$rc"
      exit "$rc"
      ;;

    exists)
      [ $# -lt 1 ] && { echo "Usage: secret-ops.sh exists KEY" >&2; exit 1; }
      local key="$1" backend rc=0
      _validate_key "$key" || exit 1
      backend=$(_ensure_backend) || exit 1
      _dispatch exists "$backend" "$key" || rc=1
      _audit exists "$key" "$rc"
      exit "$rc"
      ;;

    help|--help|-h)
      cat >&2 <<'HELP'
secret-ops.sh — secure secret operations (inject model)

Operations:
  store  KEY                        Store a secret (interactive prompt)
  inject KEY --confirm -- cmd …     Inject secret into subprocess env
  list                              List stored key names
  delete KEY --confirm              Remove a secret
  exists KEY                        Check if a secret exists (exit 0/1)

Backends: vault, keychain, keyring, gcm
Config:   ~/.config/secret-ops/
HELP
      exit 0
      ;;

    *)
      echo "ERROR: Unknown operation '$op'. Run with --help." >&2
      exit 1
      ;;
  esac
}

main "$@"
