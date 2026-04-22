#Requires -Version 5.1
<#
.SYNOPSIS
  secret-ops.ps1 — secure secret operations (inject model)
  Values never printed to stdout. Agent calls this; never reads source.
#>
[CmdletBinding(DefaultParameterSetName='NoKeyOp')]
param(
    [Parameter(ParameterSetName='KeyOp', Position=0, Mandatory)]
    [Parameter(ParameterSetName='NoKeyOp', Position=0)]
    [ValidateSet('store', 'inject', 'list', 'delete', 'exists', 'help')]
    [string]$Operation = 'help',

    [Parameter(ParameterSetName='KeyOp', Position=1, Mandatory)]
    [string]$Key,

    [Alias('b')]
    [string]$Backend,

    [Parameter(ParameterSetName='KeyOp')]
    [switch]$Confirm,

    [Parameter(ParameterSetName='KeyOp', ValueFromRemainingArguments)]
    [string[]]$RemainingArgs
)

Set-Variable -Name SECRET_STORE -Value 'secret-store' -Option Constant
Set-Variable -Name SECRET_STORE_VAULT -Value 'secret-ops' -Option Constant

$ErrorActionPreference = 'Stop'

$ConfigDir = Join-Path $env:USERPROFILE '.config\secret-ops'
$BackendFile = Join-Path $ConfigDir 'backend'
$AuditLog = Join-Path $ConfigDir 'audit.log'
$LockFile = Join-Path $ConfigDir '.backend.lock'
$ValidBackends = @('vault', $SECRET_STORE, 'gcm')

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
    $backendUsed = if (Test-Path $BackendFile) { Get-Content $BackendFile } else { 'none' }
    $safeKey = $AuditKey -replace '[\r\n\t]', ''
    $ts = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    "$ts op=$Op key=$safeKey backend=$backendUsed rc=$Rc" | Out-File -Append -FilePath $AuditLog -Encoding utf8
}

# ── Backend detection & pinning ──────────────────────────────────────────────
function Get-Backend {
    if ($Backend) {
        if ($Backend -notin $ValidBackends) { throw "Invalid backend '$Backend' specified" }
        return $Backend
    }

    if (Test-Path $BackendFile) {
        $b = (Get-Content $BackendFile).Trim()
        if ($b -notin $ValidBackends) { throw "Invalid pinned backend '$b' - delete $BackendFile to re-detect" }
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

        # Detect: Vault → GCM → SecretStore  (use $LASTEXITCODE for native commands)
        if ($env:VAULT_ADDR -and (Get-Command vault -ErrorAction SilentlyContinue)) {
            # VAULT_ADDR set + vault exists = user intends Vault — fail closed on any issue
            vault token lookup 2>$null | Out-Null
            if ($LASTEXITCODE -ne 0) {
                throw "Vault is configured (VAULT_ADDR set) but authentication failed. Fix Vault auth, or remove `$env:VAULT_ADDR to use a local backend."
            }
            $probeKey = "_probe_$(Get-Random)_$PID"
            vault kv put "secret/secret-ops/$probeKey" value=probe_test 2>$null | Out-Null
            if ($LASTEXITCODE -eq 0) {
                vault kv delete "secret/secret-ops/$probeKey" 2>$null | Out-Null
                if ($LASTEXITCODE -eq 0) {
                    'vault' | Out-File $BackendFile -NoNewline -Encoding utf8; return 'vault'
                }
            }
            throw "Vault is configured (VAULT_ADDR set, token valid) but probe to secret/secret-ops/ failed. Fix Vault permissions, or remove `$env:VAULT_ADDR to use a local backend."
        }
        if (Get-Command git -ErrorAction SilentlyContinue) {
            git credential-manager --version 2>$null | Out-Null
            if ($LASTEXITCODE -eq 0) { 'gcm' | Out-File $BackendFile -NoNewline -Encoding utf8; return 'gcm' }
        }
        if (Get-Module Microsoft.PowerShell.SecretManagement -ListAvailable -ErrorAction SilentlyContinue) {
            if (Get-Module Microsoft.PowerShell.SecretStore -ListAvailable -ErrorAction SilentlyContinue) {
                $SECRET_STORE | Out-File $BackendFile -NoNewline -Encoding utf8; return $SECRET_STORE
            }
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

# ── SecretStore helpers ──────────────────────────────────────────────────────
function Get-SecretOpsVault {
    $v = Get-SecretVault -Name $SECRET_STORE_VAULT -ErrorAction SilentlyContinue
    if (-not $v) {
        Register-SecretVault -Name $SECRET_STORE_VAULT -ModuleName Microsoft.PowerShell.SecretStore -DefaultVault:$false -ErrorAction Stop
        $v = Get-SecretVault -Name $SECRET_STORE_VAULT
    }
    return $v
}

function Invoke-SecretStoreStore {
    param([string]$SecretStoreKey)
    $null = Get-SecretOpsVault
    $secret = Read-Host "Enter secret for $SecretStoreKey" -AsSecureString
    try {
        Set-Secret -Name $SecretStoreKey -SecureStringSecret $secret -Vault $SECRET_STORE_VAULT -ErrorAction Stop
    } finally {
        $secret = $null
    }
}

function Invoke-SecretStoreGet {
    param([string]$SecretStoreKey)
    $null = Get-SecretOpsVault
    $val = Get-Secret -Name $SecretStoreKey -Vault $SECRET_STORE_VAULT -AsPlainText -ErrorAction SilentlyContinue
    if ($null -eq $val) { throw "Secret '$SecretStoreKey' not found" }
    return $val
}

function Test-SecretStoreExists {
    param([string]$SecretStoreKey)
    $null = Get-SecretOpsVault
    return [bool](Get-SecretInfo -Name $SecretStoreKey -Vault $SECRET_STORE_VAULT -ErrorAction SilentlyContinue)
}

function Remove-SecretStoreSecret {
    param([string]$SecretStoreKey)
    $null = Get-SecretOpsVault
    Remove-Secret -Name $SecretStoreKey -Vault $SECRET_STORE_VAULT -ErrorAction Stop
}

# ── GCM helpers ──────────────────────────────────────────────────────────────
$GcmGitArgs = @('-c', 'credential.helper=manager', '-c', 'credential.useHttpPath=true')

function Invoke-GcmStore {
    param([string]$GcmKey)
    $secret = Read-Host "Enter secret for $GcmKey" -AsSecureString
    $plain = ConvertFrom-SecureStringSafe $secret
    try {
        # GCM uses line-based git credential protocol — reject multiline secrets
        if ($plain -match '[\r\n]') {
            throw "GCM backend does not support multiline secrets (use Vault instead)"
        }
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
        # Use Process + StreamWriter to avoid PS pipeline appending trailing newline
        $proc = [System.Diagnostics.Process]::new()
        $proc.StartInfo.FileName = 'vault'
        $proc.StartInfo.Arguments = "kv put `"secret/secret-ops/$VaultKey`" value=-"
        $proc.StartInfo.UseShellExecute = $false
        $proc.StartInfo.RedirectStandardInput = $true
        $proc.StartInfo.RedirectStandardOutput = $true
        $proc.StartInfo.RedirectStandardError = $true
        $proc.Start() | Out-Null
        $proc.StandardInput.Write($plain)
        $proc.StandardInput.Close()
        $proc.WaitForExit()
        if ($proc.ExitCode -ne 0) { throw "vault kv put failed (exit $($proc.ExitCode))" }
    } finally {
        $plain = $null
    }
}

function Invoke-VaultGet {
    param([string]$VaultKey)
    # Use Process+ReadToEnd to preserve multiline values faithfully
    $proc = [System.Diagnostics.Process]::new()
    $proc.StartInfo.FileName = 'vault'
    $proc.StartInfo.Arguments = "kv get -field=value `"secret/secret-ops/$VaultKey`""
    $proc.StartInfo.UseShellExecute = $false
    $proc.StartInfo.RedirectStandardOutput = $true
    $proc.StartInfo.RedirectStandardError = $true
    $proc.Start() | Out-Null
    $result = $proc.StandardOutput.ReadToEnd()
    $proc.WaitForExit()
    if ($proc.ExitCode -ne 0 -or [string]::IsNullOrEmpty($result)) {
        throw "Secret '$VaultKey' not found"
    }
    # Remove single trailing newline added by vault CLI output
    if ($result.EndsWith("`n")) { $result = $result.Substring(0, $result.Length - 1) }
    if ($result.EndsWith("`r")) { $result = $result.Substring(0, $result.Length - 1) }
    return $result
}

function Test-VaultExists {
    param([string]$VaultKey)
    try { Invoke-VaultGet $VaultKey | Out-Null; return $true } catch { return $false }
}

function Main {
    $script:LastExitCode = 0
    try {
        switch ($Operation) {
            'store' {
                Assert-ValidKey $Key
                $backend = Get-Backend
                switch ($backend) {
                    'gcm'         { Invoke-GcmStore $Key }
                    'vault'       { Invoke-VaultStore $Key }
                    $SECRET_STORE { Invoke-SecretStoreStore $Key }
                    default { throw "Unsupported backend '$backend'" }
                }
                Write-Audit -Op store -AuditKey $Key -Rc 0
            }

            'inject' {
                Assert-ValidKey $Key

                # Inject requires env-var-safe key name (no dots or hyphens)
                if ($Key -notmatch '^[A-Za-z_][A-Za-z0-9_]*$') {
                    throw "Key '$Key' is not a valid environment variable name (use [A-Za-z_][A-Za-z0-9_]*)"
                }

                if (-not $Confirm) { throw "inject requires -Confirm flag (approval gate)" }

                # NEW LOGIC: Look for '--', but if it's missing, take everything
                if ($null -eq $RemainingArgs -or $RemainingArgs.Length -eq 0) {
                    throw "No command specified"
                }

                $sepIdx = [Array]::IndexOf($RemainingArgs, '--')

                if ($sepIdx -ge 0) {
                    # If '--' exists, the command starts after it
                    $cmd = $RemainingArgs[($sepIdx+1)..($RemainingArgs.Length-1)]
                } else {
                    # If '--' is missing (consumed by PS), the whole array is the command
                    $cmd = $RemainingArgs
                }

                if ($cmd.Length -eq 0) { throw "No command specified after '--'" }

                $backend = Get-Backend
                $val = switch ($backend) {
                    'gcm'         { Invoke-GcmGet $Key }
                    'vault'       { Invoke-VaultGet $Key }
                    $SECRET_STORE { Invoke-SecretStoreGet $Key }
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
                    foreach ($e in [System.Environment]::GetEnvironmentVariables().GetEnumerator()) {
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
                $script:LastExitCode = $procRc
                if ($procRc -ne 0 -and $MyInvocation.InvocationName -eq '.') { throw "ExitCalledWith_$procRc" }
                return
            }

            'list' {
                $backend = Get-Backend
                switch ($backend) {
                    'gcm'   { Write-Host '(GCM does not support list — use OS credential manager UI)' }
                    'vault' {
                        vault kv list secret/secret-ops/ 2>$null
                        Assert-NativeSuccess 'vault kv list'
                    }
                    $SECRET_STORE {
                        Get-SecretInfo -Vault 'secret-ops' | Select-Object -ExpandProperty Name
                    }
                    default { throw "Unsupported backend '$backend'" }
                }
                Write-Audit -Op list -Rc 0
            }

            'delete' {
                Assert-ValidKey $Key
                if (-not $Confirm) { throw "delete requires -Confirm flag (approval gate)" }

                $backend = Get-Backend
                switch ($backend) {
                    'gcm'         { Remove-GcmSecret $Key }
                    'vault'       {
                        vault kv delete "secret/secret-ops/$Key" 2>$null | Out-Null
                        Assert-NativeSuccess 'vault kv delete'
                    }
                    $SECRET_STORE { Remove-SecretStoreSecret $Key }
                    default { throw "Unsupported backend '$backend'" }
                }
                Write-Audit -Op delete -AuditKey $Key -Rc 0
            }

            'exists' {
                Assert-ValidKey $Key
                $backend = Get-Backend
                $found = switch ($backend) {
                    'gcm'         { Test-GcmExists $Key }
                    'vault'       { Test-VaultExists $Key }
                    $SECRET_STORE { Test-SecretStoreExists $Key }
                    default { throw "Unsupported backend '$backend'" }
                }
                $rc = [int](-not $found)
                Write-Audit -Op exists -AuditKey $Key -Rc $rc
                if (-not $found) { $script:LastExitCode = 1; return }
            }

            'help' {
                @'
secret-ops.ps1 - secure secret operations (inject model)

Usage:
  .\secret-ops.ps1 store KEY [-Backend NAME]
  .\secret-ops.ps1 inject KEY -Confirm [-Backend NAME] -- cmd args...
  .\secret-ops.ps1 list [-Backend NAME]
  .\secret-ops.ps1 delete KEY -Confirm [-Backend NAME]
  .\secret-ops.ps1 exists KEY [-Backend NAME]

Backends: vault, secret-store, gcm
Config:   %USERPROFILE%\.config\secret-ops\
'@ | Write-Output
            }
        }
    } catch {
        Write-Audit -Op $Operation -AuditKey $Key -Rc 1
        Write-Error $_.Exception.Message
        $script:LastExitCode = 1
        return
    }
}

# Only execute Main if script is NOT being dot-sourced
if ($MyInvocation.InvocationName -ne '.') {
    $script:LastExitCode = 0
    Main
    if ($null -ne $script:LastExitCode -and $script:LastExitCode -ne 0) {
        exit $script:LastExitCode
    }
}
