$ScriptFile = Join-Path $PSScriptRoot "secret-ops.ps1"

Describe "Unified secret-ops Tests" {
    BeforeAll {
        $TestRoot = New-Item -ItemType Directory -Path (Join-Path $PSScriptRoot "PesterTestEnv") -Force
        $script:OldUserProfile = $env:USERPROFILE
        $env:USERPROFILE = $TestRoot.FullName
        $ConfigDir = Join-Path $env:USERPROFILE ".config\secret-ops"
        New-Item -ItemType Directory -Path $ConfigDir -Force | Out-Null
        "secret-store" | Out-File (Join-Path $ConfigDir "backend") -NoNewline -Encoding utf8
        
        # Dot-source once to define functions in this scope
        . $ScriptFile
    }

    AfterAll {
        $env:USERPROFILE = $script:OldUserProfile
        if (Test-Path $TestRoot) { Remove-Item $TestRoot -Recurse -Force }
    }

    Context "Operation: exists" {
        It "Returns success when a secret exists" {
            Mock Get-SecretVault { return @{ Name = "secret-ops" } }
            Mock Get-SecretInfo { return @{ Name = "TEST_KEY" } }

            $script:Operation = 'exists'
            $script:Key = 'TEST_KEY'
            Main
            $script:LastExitCode | Should Be 0
        }

        It "Returns exit code 1 when a secret does NOT exist" {
            Mock Get-SecretVault { return @{ Name = "secret-ops" } }
            Mock Get-SecretInfo { return $null }

            $script:Operation = 'exists'
            $script:Key = 'NON_EXISTENT'
            Main
            $script:LastExitCode | Should Be 1
        }
    }

    Context "Operation: store" {
        It "Successfully stores a secret" {
            Mock Read-Host { return (ConvertTo-SecureString "mock-password" -AsPlainText -Force) }
            Mock Get-SecretVault { return @{ Name = "secret-ops" } }
            $script:StoredName = $null
            Mock Set-Secret { 
                param($Name, $SecureStringSecret, $Vault)
                $script:StoredName = $Name
            }

            $script:Operation = 'store'
            $script:Key = 'NEW_SECRET'
            Main
            $script:LastExitCode | Should Be 0
            $script:StoredName | Should Be "NEW_SECRET"
        }
    }

    Context "Operation: list" {
        It "Lists stored secrets" {
            Mock Get-SecretVault { return @{ Name = "secret-ops" } }
            Mock Get-SecretInfo { return @( [PSCustomObject]@{ Name = "KEY1" }, [PSCustomObject]@{ Name = "KEY2" } ) }

            $script:Operation = 'list'
            $result = Main | Out-String
            
            $result | Should Match "KEY1"
            $result | Should Match "KEY2"
            $script:LastExitCode | Should Be 0
        }
    }

    Context "Operation: delete" {
        It "Fails if -Confirm is missing" {
            $script:Operation = 'delete'
            $script:Key = 'KEY_TO_DELETE'
            $script:Confirm = $false
            { Main } | Should Throw "delete requires -Confirm flag (approval gate)"
        }

        It "Successfully deletes a secret with -Confirm" {
            Mock Get-SecretVault { return @{ Name = "secret-ops" } }
            $script:DeletedName = $null
            Mock Remove-Secret {
                param($Name, $Vault)
                $script:DeletedName = $Name
            }

            $script:Operation = 'delete'
            $script:Key = 'KEY_TO_DELETE'
            $script:Confirm = $true
            Main
            $script:LastExitCode | Should Be 0
            $script:DeletedName | Should Be "KEY_TO_DELETE"
        }
    }

    Context "Operation: inject" {
        It "Fails if -Confirm is missing" {
            $script:Operation = 'inject'
            $script:Key = 'MY_SECRET'
            $script:Confirm = $false
            $script:RemainingArgs = @("--", "cmd", "/c", "echo hi")
            { Main } | Should Throw "inject requires -Confirm flag (approval gate)"
        }

        It "Fails if '--' separator is missing" {
            $script:Operation = 'inject'
            $script:Key = 'MY_SECRET'
            $script:Confirm = $true
            $script:RemainingArgs = @("cmd", "/c", "echo hi")
            { Main } | Should Throw "Missing '--' separator before command"
        }

        It "Successfully injects secret into environment" {
            Mock Get-SecretVault { return @{ Name = "secret-ops" } }
            Mock Get-Secret { return "secret-value-123" }
            $tmpFile = [System.IO.Path]::GetTempFileName()

            $script:Operation = 'inject'
            $script:Key = 'MY_SECRET'
            $script:Confirm = $true
            $script:RemainingArgs = @("--", "cmd", "/c", "echo %MY_SECRET% > $tmpFile")
            
            Main

            $fileContent = Get-Content $tmpFile
            ($fileContent -match "secret-value-123") | Should Be $true

            Remove-Item $tmpFile
        }

        It "Propagates exit code from child process" {
            Mock Get-SecretVault { return @{ Name = "secret-ops" } }
            Mock Get-Secret { return "val" }

            $script:Operation = 'inject'
            $script:Key = 'MY_SECRET'
            $script:Confirm = $true
            $script:RemainingArgs = @("--", "cmd", "/c", "exit 42")
            Main
            $script:LastExitCode | Should Be 42
        }
    }

    Context "Operation: help" {
        It "Displays usage message" {
            $script:Operation = 'help'
            $result = Main | Out-String
            $result | Should Match "Usage:"
            $result | Should Match "secret-ops.ps1"
            $script:LastExitCode | Should Be 0
        }
    }
}
