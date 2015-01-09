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

    if ($Dependencies) {
        Write-Error 'Dependencies do not work in composite resources.'
        throw
    }

    WindowsFeature ('WindowsFeature_' + $Name) {
        Ensure = $Presence
        Name = $Name
        #DependsOn = $Dependencies
    }
}