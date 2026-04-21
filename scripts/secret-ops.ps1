#Requires -Version 5.1
<#
.SYNOPSIS
  secret-ops.ps1 — secure secret operations (inject model)
  Values never printed to stdout. Agent calls this; never reads source.
#>
[CmdletBinding()]
param(
    [Parameter(Position=0)]
    [ValidateSet('store','inject','list','delete','exists','help')]
    [string]$Operation = 'help',

    [Parameter(Position=1)]
    [string]$Key,

    [Parameter(Position=2, ValueFromRemainingArguments)]
    [string[]]$CommandArgs
)

$ErrorActionPreference = 'Stop'
$ConfigDir = Join-Path $env:USERPROFILE '.config\secret-ops'
$BackendFile = Join-Path $ConfigDir 'backend'
$AuditLog = Join-Path $ConfigDir 'audit.log'
$LockFile = Join-Path $ConfigDir '.backend.lock'
$ValidBackends = @('vault', 'gcm')

if (-not (Test-Path $ConfigDir)) { New-Item -ItemType Directory -Path $ConfigDir -Force | Out-Null }

# ── Key validation ───────────────────────────────────────────────────────────
function Assert-ValidKey {
    param([string]$K)
    if ($K -notmatch '^[A-Za-z0-9_.-]+$') { throw "Key name must match [A-Za-z0-9_.-]+" }
    if ($K.Length -gt 256) { throw "Key name exceeds 256 characters" }
}

# ── Audit ────────────────────────────────────────────────────────────────────
function Write-Audit {
    param([string]$Op, [string]$AuditKey = '', [int]$Rc = 0)
    $backend = if (Test-Path $BackendFile) { Get-Content $BackendFile } else { 'none' }
    $safeKey = $AuditKey -replace '[\r\n\t]', ''
    $ts = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    "$ts op=$Op key=$safeKey backend=$backend rc=$Rc" | Out-File -Append -FilePath $AuditLog -Encoding utf8
}

# ── Backend detection & pinning ──────────────────────────────────────────────
function Get-Backend {
    if (Test-Path $BackendFile) {
        $b = (Get-Content $BackendFile).Trim()
        if ($b -notin $ValidBackends) { throw "Invalid pinned backend '$b' — delete $BackendFile to re-detect" }
        return $b
    }

    # Locked detection + pinning
    $mutex = $null
    $acquired = $false
    try {
        $mutex = [System.Threading.Mutex]::new($false, 'Global\SecretOpsBackendPin')
        $acquired = $mutex.WaitOne(5000)
        if (-not $acquired) { throw 'Could not acquire backend lock (timeout)' }

        # Re-check after lock
        if (Test-Path $BackendFile) { return (Get-Content $BackendFile).Trim() }

        # Detect: Vault → GCM (use $LASTEXITCODE for native commands)
        if ($env:VAULT_ADDR -and (Get-Command vault -ErrorAction SilentlyContinue)) {
            vault token lookup 2>$null | Out-Null
            if ($LASTEXITCODE -eq 0) {
                # Probe: verify we can write+delete in our namespace
                vault kv put 'secret/secret-ops/_probe' value=probe_test 2>$null | Out-Null
                if ($LASTEXITCODE -eq 0) {
                    vault kv delete 'secret/secret-ops/_probe' 2>$null | Out-Null
                    'vault' | Out-File $BackendFile -NoNewline -Encoding utf8; return 'vault'
                }
            }
        }
        if (Get-Command git -ErrorAction SilentlyContinue) {
            git credential-manager --version 2>$null | Out-Null
            if ($LASTEXITCODE -eq 0) { 'gcm' | Out-File $BackendFile -NoNewline -Encoding utf8; return 'gcm' }
        }
        throw 'No supported secret backend found'
    } finally {
        if ($mutex) {
            if ($acquired) { $mutex.ReleaseMutex() }
            $mutex.Dispose()
        }
    }
}

# ── Secure string helpers ────────────────────────────────────────────────────
function ConvertFrom-SecureStringSafe {
    param([System.Security.SecureString]$Secure)
    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Secure)
    try {
        return [Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
    } finally {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
    }
}

# ── Native command exit code helper ──────────────────────────────────────────
function Assert-NativeSuccess {
    param([string]$Context = 'Native command')
    if ($LASTEXITCODE -ne 0) { throw "$Context failed (exit code $LASTEXITCODE)" }
}
$GcmGitArgs = @('-c', 'credential.helper=manager', '-c', 'credential.useHttpPath=true')

function Invoke-GcmStore {
    param([string]$GcmKey)
    $secret = Read-Host "Enter secret for $GcmKey" -AsSecureString
    $plain = ConvertFrom-SecureStringSafe $secret
    try {
        $input = "protocol=https`nhost=secret-ops.local`npath=$GcmKey`nusername=secret-ops`npassword=$plain`n`n"
        $input | git @GcmGitArgs credential approve
        Assert-NativeSuccess 'git credential approve'
    } finally {
        $plain = $null
    }
}

function Invoke-GcmGet {
    param([string]$GcmKey)
    $input = "protocol=https`nhost=secret-ops.local`npath=$GcmKey`nusername=secret-ops`n`n"
    $result = $input | git @GcmGitArgs credential fill 2>$null
    $match = $result | Select-String '^password='
    if ($match) { return ($match -replace '^password=','') }
    throw "Secret '$GcmKey' not found"
}

function Test-GcmExists {
    param([string]$GcmKey)
    try { Invoke-GcmGet $GcmKey | Out-Null; return $true } catch { return $false }
}

function Remove-GcmSecret {
    param([string]$GcmKey)
    $input = "protocol=https`nhost=secret-ops.local`npath=$GcmKey`nusername=secret-ops`n`n"
    try {
        $fill = $input | git @GcmGitArgs credential fill 2>$null
        Assert-NativeSuccess 'git credential fill'
        "$fill`n`n" | git @GcmGitArgs credential reject
        Assert-NativeSuccess 'git credential reject'
    } catch {
        "protocol=https`nhost=secret-ops.local`npath=$GcmKey`nusername=secret-ops`npassword=x`n`n" | git @GcmGitArgs credential reject
        Assert-NativeSuccess 'git credential reject (fallback)'
    }
}

# ── Vault helpers (namespaced under secret/secret-ops/) ──────────────────────
function Invoke-VaultStore {
    param([string]$VaultKey)
    $secret = Read-Host "Enter secret for $VaultKey" -AsSecureString
    $plain = ConvertFrom-SecureStringSafe $secret
    try {
        $plain | vault kv put "secret/secret-ops/$VaultKey" value=- | Out-Null
        Assert-NativeSuccess 'vault kv put'
    } finally {
        $plain = $null
    }
}

function Invoke-VaultGet {
    param([string]$VaultKey)
    $result = vault kv get -field=value "secret/secret-ops/$VaultKey" 2>$null
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrEmpty($result)) {
        throw "Secret '$VaultKey' not found"
    }
    return $result
}

function Test-VaultExists {
    param([string]$VaultKey)
    try { Invoke-VaultGet $VaultKey | Out-Null; return $true } catch { return $false }
}

# ── Main ─────────────────────────────────────────────────────────────────────
try {
    switch ($Operation) {
        'store' {
            if (-not $Key) { throw 'Usage: secret-ops.ps1 store KEY' }
            Assert-ValidKey $Key
            $backend = Get-Backend
            switch ($backend) {
                'gcm'   { Invoke-GcmStore $Key }
                'vault' { Invoke-VaultStore $Key }
                default { throw "Unsupported backend '$backend'" }
            }
            Write-Audit -Op store -AuditKey $Key -Rc 0
        }

        'inject' {
            if (-not $Key) { throw 'Usage: secret-ops.ps1 inject KEY --confirm -- cmd args…' }
            Assert-ValidKey $Key

            # Inject requires env-var-safe key name (no dots or hyphens)
            if ($Key -notmatch '^[A-Za-z_][A-Za-z0-9_]*$') {
                throw "Key '$Key' is not a valid environment variable name (use [A-Za-z_][A-Za-z0-9_]*)"
            }

            # Parse --confirm and -- separator
            $confirmed = $false
            $sepIdx = -1
            for ($i = 0; $i -lt $CommandArgs.Length; $i++) {
                if ($CommandArgs[$i] -eq '--confirm') { $confirmed = $true }
                if ($CommandArgs[$i] -eq '--') { $sepIdx = $i; break }
            }
            if (-not $confirmed) { throw "inject requires --confirm flag (approval gate)" }
            if ($sepIdx -lt 0) { throw "Missing '--' separator" }
            if ($sepIdx -ge $CommandArgs.Length - 1) { throw "No command specified after '--'" }
            $cmd = $CommandArgs[($sepIdx+1)..($CommandArgs.Length-1)]

            $backend = Get-Backend
            $val = switch ($backend) {
                'gcm'   { Invoke-GcmGet $Key }
                'vault' { Invoke-VaultGet $Key }
                default { throw "Unsupported backend '$backend'" }
            }
            # Launch as real child process with scoped env (ProcessStartInfo)
            $procRc = 1
            try {
                $psi = New-Object System.Diagnostics.ProcessStartInfo
                $psi.FileName = $cmd[0]
                if ($cmd.Length -gt 1) {
                    # Proper Windows command-line argument quoting (handles backslash+quote)
                    $quotedArgs = $cmd[1..($cmd.Length-1)] | ForEach-Object {
                        if ($_ -eq '') {
                            '""'
                        } elseif ($_ -match '[\s"]') {
                            # Escape backslash runs preceding quotes or end-of-string, then wrap
                            $escaped = [regex]::Replace($_, '(\\*)"', '$1$1\"')
                            $escaped = [regex]::Replace($escaped, '(\\+)$', '$1$1')
                            "`"$escaped`""
                        } else {
                            $_
                        }
                    }
                    $psi.Arguments = $quotedArgs -join ' '
                }
                $psi.UseShellExecute = $false
                $psi.RedirectStandardOutput = $false
                $psi.RedirectStandardError = $false
                # Copy current env + inject secret
                foreach ($e in [System.Environment]::GetEnvironmentVariables()) {
                    $psi.EnvironmentVariables[$e.Key] = $e.Value
                }
                $psi.EnvironmentVariables[$Key] = $val
                $proc = [System.Diagnostics.Process]::Start($psi)
                $proc.WaitForExit()
                $procRc = $proc.ExitCode
            } finally {
                $val = $null
            }
            Write-Audit -Op inject -AuditKey $Key -Rc $procRc
            exit $procRc
        }

        'list' {
            $backend = Get-Backend
            switch ($backend) {
                'gcm'   { Write-Host '(GCM does not support list — use OS credential manager UI)' }
                'vault' {
                    vault kv list secret/secret-ops/ 2>$null
                    Assert-NativeSuccess 'vault kv list'
                }
                default { throw "Unsupported backend '$backend'" }
            }
            Write-Audit -Op list -Rc 0
        }

        'delete' {
            if (-not $Key) { throw 'Usage: secret-ops.ps1 delete KEY --confirm' }
            Assert-ValidKey $Key

            # Require --confirm flag
            $confirmed = $false
            foreach ($arg in $CommandArgs) {
                if ($arg -eq '--confirm') { $confirmed = $true }
            }
            if (-not $confirmed) { throw "delete requires --confirm flag (approval gate)" }

            $backend = Get-Backend
            switch ($backend) {
                'gcm'   { Remove-GcmSecret $Key }
                'vault' {
                    vault kv delete "secret/secret-ops/$Key" 2>$null | Out-Null
                    Assert-NativeSuccess 'vault kv delete'
                }
                default { throw "Unsupported backend '$backend'" }
            }
            Write-Audit -Op delete -AuditKey $Key -Rc 0
        }

        'exists' {
            if (-not $Key) { throw 'Usage: secret-ops.ps1 exists KEY' }
            Assert-ValidKey $Key
            $backend = Get-Backend
            $found = switch ($backend) {
                'gcm'   { Test-GcmExists $Key }
                'vault' { Test-VaultExists $Key }
                default { throw "Unsupported backend '$backend'" }
            }
            Write-Audit -Op exists -AuditKey $Key -Rc ([int](-not $found))
            if (-not $found) { exit 1 }
        }

        'help' {
            @'
secret-ops.ps1 — secure secret operations (inject model)

Operations:
  store  KEY                        Store a secret (interactive prompt)
  inject KEY --confirm -- cmd …     Inject secret into subprocess env
  list                              List stored key names
  delete KEY --confirm              Remove a secret
  exists KEY                        Check if a secret exists (exit 0/1)

Backends: vault, gcm
Config:   %USERPROFILE%\.config\secret-ops\
'@ | Write-Host
        }
    }
} catch {
    Write-Audit -Op $Operation -AuditKey $Key -Rc 1
    Write-Error $_.Exception.Message
    exit 1
}
