Configuration cEnsureWindowsFeature {
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$Name
        ,
        [Parameter(Mandatory=$false)]
        [ValidateSet('Present','Absent')]
        [string]$Presence = 'Present'
        ,
        [Parameter(Mandatory=$false)]
        [string[]]$Dependencies = $null
    )

    WindowsFeature $Name {
        Ensure = $Presence
        Name = $Name
        DependsOn = $Dependencies
    }
}

Configuration MyConfig {
    cEnsureWindowsFeature Feature1 {
        Name = 'Hyper-V'
    }

    cEnsureWindowsFeature Feature2 {
        Name = 'Hyper-V-PowerShell'
        Dependencies = ('[cEnsureWindowsFeature]Feature1')
    }
}

MyConfig -OutputPath (Join-Path -Path $PSScriptRoot -ChildPath 'Temp')