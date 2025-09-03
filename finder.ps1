param(
    [string]$Username = $env:USERNAME,      # Defaults to current user
    [string[]]$Computers = @()              # Optional: list of computers; empty = domain enumeration
)

function ind-LocalAdminAccess {
    param(
        [string]$User,
        [string[]]$TargetComputers
    )

    # Load AD computers if not specified
    if (-not $TargetComputers -or $TargetComputers.Count -eq 0) {
        try {
            $TargetComputers = Get-ADComputer -Filter * | Select-Object -ExpandProperty Name
        } catch {
            Write-Warning "Cannot query AD. Provide a list of computers in -Computers."
            return
        }
    }

    $Accessible = @()

    foreach ($c in $TargetComputers) {
        try {
            $admins = Get-WmiObject -Class Win32_GroupUser -ComputerName $c -ErrorAction Stop |
                      Where-Object { $_.GroupComponent -like '*"Administrators"' } |
                      ForEach-Object {
                          ($_ -split '"')[1]  # Extract username from WMI output
                      }

            if ($admins -contains $User) {
                $Accessible += $c
                Write-Host "[+] $User has local admin on $c" -ForegroundColor Green
            } else {
                Write-Host "[-] $User not admin on $c" -ForegroundColor DarkGray
            }
        } catch {
            Write-Host "[!] Cannot query $c" -ForegroundColor Yellow
        }
    }

    return $Accessible
}

Write-Host "`n[*] Checking access for user: $Username`n" -ForegroundColor Cyan
ind-LocalAdminAccess -User $Username -TargetComputers $Computers
