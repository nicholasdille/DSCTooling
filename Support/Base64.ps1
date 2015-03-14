function ConvertTo-Base64 {
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]
        $SourcePath
        ,
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]
        $DestinationPath
    )

    $SourceData = Get-Content -Path $SourcePath -Encoding Byte
    [System.Convert]::ToBase64String($SourceData) | Out-File -FilePath $DestinationPath
}

function ConvertFrom-Base64 {
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]
        $SourcePath
        ,
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]
        $DestinationPath
    )

    $SourceData = Get-Content -Path $SourcePath
    [System.Convert]::FromBase64String($SourceData) | Set-Content -Path $DestinationPath -Encoding Byte
}