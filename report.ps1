function Get-ProcessTokenGroup {
    param(
        [System.Diagnostics.Process]$Process = (Get-Process -Id $pid)
    )

    $sig = @"
    using System;
    using System.Runtime.InteropServices;
    public class TokenGroups {
        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool OpenProcessToken(IntPtr ProcessHandle, UInt32 DesiredAccess, out IntPtr TokenHandle);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool GetTokenInformation(IntPtr TokenHandle, int TokenInformationClass, IntPtr TokenInformation, int TokenInformationLength, out int ReturnLength);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool CloseHandle(IntPtr hObject);
    }
"@
    Add-Type $sig -ErrorAction SilentlyContinue

    $TOKEN_QUERY = 0x0008
    $TokenGroups = 2
    $tokenHandle = [IntPtr]::Zero

    if (-not [TokenGroups]::OpenProcessToken($Process.Handle, $TOKEN_QUERY, [ref]$tokenHandle)) {
        throw "[-] Could not open process token."
    }

    $retLen = 0
    [TokenGroups]::GetTokenInformation($tokenHandle, $TokenGroups, [IntPtr]::Zero, 0, [ref]$retLen) | Out-Null
    $ptr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($retLen)

    if (-not [TokenGroups]::GetTokenInformation($tokenHandle, $TokenGroups, $ptr, $retLen, [ref]$retLen)) {
        throw "[-] Could not get token information."
    }

    $count = [System.Runtime.InteropServices.Marshal]::ReadInt32($ptr)
    $offset = $ptr.ToInt64() + 4

    $sids = @()
    for ($i = 0; $i -lt $count; $i++) {
        $sidPtr = [System.IntPtr]::new($offset)
        $sid = New-Object System.Security.Principal.SecurityIdentifier($sidPtr)
        $sids += $sid.Value
        $offset += 12
    }

    [System.Runtime.InteropServices.Marshal]::FreeHGlobal($ptr)
    [TokenGroups]::CloseHandle($tokenHandle) | Out-Null

    return $sids
}

# Function: Get-ProcessTokenPrivilege
function Get-ProcessTokenPrivilege {
    param(
        [System.Diagnostics.Process]$Process = (Get-Process -Id $pid)
    )

    $sig = @"
    using System;
    using System.Runtime.InteropServices;
    public class TokenPrivileges {
        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct LUID {
            public uint LowPart;
            public int HighPart;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct LUID_AND_ATTRIBUTES {
            public LUID Luid;
            public UInt32 Attributes;
        }

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool OpenProcessToken(IntPtr ProcessHandle, UInt32 DesiredAccess, out IntPtr TokenHandle);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool GetTokenInformation(IntPtr TokenHandle, int TokenInformationClass, IntPtr TokenInformation, int TokenInformationLength, out int ReturnLength);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool LookupPrivilegeName(string lpSystemName, ref LUID lpLuid, System.Text.StringBuilder lpName, ref int cchName);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool CloseHandle(IntPtr hObject);
    }
"@
    Add-Type $sig -ErrorAction SilentlyContinue

    $TOKEN_QUERY = 0x0008
    $TokenPrivileges = 3
    $SE_PRIVILEGE_ENABLED = 0x2
    $tokenHandle = [IntPtr]::Zero

    if (-not [TokenPrivileges]::OpenProcessToken($Process.Handle, $TOKEN_QUERY, [ref]$tokenHandle)) {
        throw "[-] Could not open process token."
    }

    $retLen = 0
    [TokenPrivileges]::GetTokenInformation($tokenHandle, $TokenPrivileges, [IntPtr]::Zero, 0, [ref]$retLen) | Out-Null
    $ptr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($retLen)

    if (-not [TokenPrivileges]::GetTokenInformation($tokenHandle, $TokenPrivileges, $ptr, $retLen, [ref]$retLen)) {
        throw "[-] Could not get token information."
    }

    $count = [System.Runtime.InteropServices.Marshal]::ReadInt32($ptr)
    $offset = $ptr.ToInt64() + 4

    $results = @()
    for ($i = 0; $i -lt $count; $i++) {
        $luid = [System.Runtime.InteropServices.Marshal]::PtrToStructure([IntPtr]$offset, [type][TokenPrivileges+LUID_AND_ATTRIBUTES])
        $nameLen = 0
        [TokenPrivileges]::LookupPrivilegeName($null, [ref]$luid.Luid, $null, [ref]$nameLen) | Out-Null
        $sb = New-Object System.Text.StringBuilder $nameLen
        [TokenPrivileges]::LookupPrivilegeName($null, [ref]$luid.Luid, $sb, [ref]$nameLen) | Out-Null

        $results += [PSCustomObject]@{
            Privilege = $sb.ToString()
            Enabled   = (($luid.Attributes -band $SE_PRIVILEGE_ENABLED) -ne 0)
        }

        $offset += [System.Runtime.InteropServices.Marshal]::SizeOf([type][TokenPrivileges+LUID_AND_ATTRIBUTES])
    }

    [System.Runtime.InteropServices.Marshal]::FreeHGlobal($ptr)
    [TokenPrivileges]::CloseHandle($tokenHandle) | Out-Null

    return $results
}

Write-Host "`n[+] Process Token Groups (SIDs):" -ForegroundColor Cyan
Get-ProcessTokenGroup | ForEach-Object { Write-Host "  $_" }

Write-Host "`n[+] Process Token Privileges:" -ForegroundColor Cyan
Get-ProcessTokenPrivilege | Format-Table -AutoSize
