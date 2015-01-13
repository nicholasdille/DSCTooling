function Assert-OutputPath {
    [CmdletBinding()]
    param()

    Assert-PathVariable -VariableName PSDSC_OutputPath
}

function Clear-OutputPath {
    [CmdletBinding()]
    param()

    Assert-OutputPath
    Get-ChildItem "$PSDSC_OutputPath" | foreach {
        Remove-Item -Path "$($_.FullName)" -Force
    }
}

function Assert-DscCheckSum {
    [CmdletBinding()]
    param()

    Assert-OutputPath
    New-DscCheckSum -ConfigurationPath $PSDSC_OutputPath
}

function Invoke-DscConfig {
    [CmdletBinding()]
    param()

    Assert-BasePath

    . $PSDSC_DataFile
    Import-Module $PSDSC_ConfigFile

    Assert-OutputPath
    Clear-OutputPath

    LabConfiguration -OutputPath $PSDSC_OutputPath -ConfigurationData $ConfigData

    Assert-DscCheckSum
    Publish-DscConfig
}

function Get-DscResourcesFromTechNet {
    [CmdletBinding()]
    param(
        [string]$ResourceUrlCacheFile = (Join-Path -Path $PSDSC_TempPath -ChildPath 'PSDSC-ResourceDownloader.clixml')
        ,
        [switch]$IgnoreCachedUrls = $false
        ,
        [switch]$OverwriteExistingModules = $false
    )

    if (-Not (Test-Path -Path $ResourceUrlCacheFile) -Or $IgnoreCachedUrls) {
        $ModuleList = New-Object System.Collections.ArrayList

        $PageList = New-Object System.Collections.Stack
        $PageList.Push('https://gallery.technet.microsoft.com/scriptcenter/site/search?f%5B0%5D.Type=Tag&f%5B0%5D.Value=Windows%20PowerShell%20Desired%20State%20Configuration&f%5B0%5D.Text=Windows%20PowerShell%20Desired%20State%20Configuration&pageIndex=1')
        $PageBeenThere = New-Object System.Collections.ArrayList
        while ($PageList.Count -gt 0) {
            $url = $PageList.Pop()
            if (-Not $PageBeenThere.Contains($url)) {
                #'processing {0}' -f $url
                $PageBeenThere.Add($url) | Out-Null
                $page = Invoke-WebRequest $url

                $page.Links | where {$_.href -match 'pageIndex' -and $_.innerText -match '\d+'} | foreach {
                    $url = $_.href
                    $url = $url.Replace('about:', 'https://gallery.technet.microsoft.com')
                    $url = $url.Replace('&amp;', '&')
                    if (-Not $PageBeenThere.Contains($url)) {
                        $PageList.Push($url)
                    }
                }

                $page.Links | where {$_.href -match '^about:/scriptcenter/(.+)-[a-z0-9]{8}$'} | foreach {
                    $url = $_.href
                    $url = $url.Replace('about:', 'https://gallery.technet.microsoft.com')
                    $url = $url.Replace('&amp;', '&')
                    $ModuleList.Push($url)
                }

                Start-Sleep -Seconds 5
            }
        }

        $ModuleList | Export-Clixml -Path $ResourceUrlCacheFile

    } else {
        $ModuleList = Import-Clixml -Path $ResourceUrlCacheFile
    }

    Foreach ($ModuleUrl in $ModuleList) {
        $page = Invoke-WebRequest $ModuleUrl
        $page.Links | where {$_.href -match '^about:/scriptcenter/(.+-[a-z0-9]{8})/file/'} | select -First 1 | foreach {
            $ItemName = $Matches[1]
            $url = $_.href
            $url = $url.Replace('about:', 'https://gallery.technet.microsoft.com')
            $url = $url.Replace('&amp;', '&')
            $url -match '/([^/]+.zip$)' | Out-Null
            $FileName = $Matches[1]
            $FileName = (Join-Path -Path $PSDSC_BasePath -ChildPath ('\DSC-Modules\' + $FileName))
            if (-Not (Test-Path -Path $FileName) -Or $OverwriteExistingModules) {
                Invoke-WebRequest $url -OutFile $FileName
            }
        }
    }
}