function ConvertTo-Base64 {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory=$true,ValueFromPipeline=$True,ValueFromPipelinebyPropertyName=$True)]
        [ValidateNotNullOrEmpty()]
        [string[]]
        $Data
    )

    BEGIN {
        $MultiLineData = @()
    }

    PROCESS {
        $MultiLineData += @($Data)
    }

    END {
        $RawData = $MultiLineData -join "`r`n"
        Write-Output ('RawData=<{0}>' -f $RawData)

        $ByteData = [system.Text.Encoding]::UTF8.GetBytes($RawData)

        $Base64Data = [System.Convert]::ToBase64String($ByteData)

        $Base64Data
    }
}

function ConvertFrom-Base64 {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory=$true,ValueFromPipeline=$True,ValueFromPipelinebyPropertyName=$True)]
        [ValidateNotNullOrEmpty()]
        [string]
        $Data
    )

    $ByteData = [System.Convert]::FromBase64String($Data)
    
    $RawData = [System.Text.Encoding]::ASCII.GetString($ByteData)

    $RawData
}