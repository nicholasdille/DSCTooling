Configuration Ensure_WindowsFeature {
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

    WindowsFeature ('WindowsFeature_' + $Name) {
        Ensure = $Presence
        Name = $Name
        DependsOn = $Dependencies
    }
}