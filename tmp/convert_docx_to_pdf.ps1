$ErrorActionPreference = 'Stop'
$sourcePath = 'D:\MAJORPROJECT_TEAMMATE_GUIDES\05_PROJECT_IMPROVEMENT_AUDIT_AND_ROADMAP.docx'
$targetPath = 'D:\MAJORPROJECT_TEAMMATE_GUIDES\05_PROJECT_IMPROVEMENT_AUDIT_AND_ROADMAP.pdf'
$statusPath = 'D:\MAJORPROJECT_TEAMMATE_GUIDES\05_PROJECT_IMPROVEMENT_AUDIT_AND_ROADMAP_QA\conversion-status.txt'
New-Item -ItemType Directory -Force -Path (Split-Path -Parent $statusPath) | Out-Null
$wordApp = $null
$docFile = $null
try {
    $wordApp = New-Object -ComObject Word.Application
    $wordApp.Visible = $false
    $wordApp.DisplayAlerts = 0
    $docFile = $wordApp.Documents.Open($sourcePath, $false, $true)
    $docFile.ExportAsFixedFormat($targetPath, 17)
    Set-Content -LiteralPath $statusPath -Value 'success'
}
catch {
    Set-Content -LiteralPath $statusPath -Value ("error: " + $_.Exception.Message)
}
finally {
    if ($null -ne $docFile) {
        $docFile.Close($false)
        [System.Runtime.InteropServices.Marshal]::ReleaseComObject($docFile) | Out-Null
    }
    if ($null -ne $wordApp) {
        $wordApp.Quit()
        [System.Runtime.InteropServices.Marshal]::ReleaseComObject($wordApp) | Out-Null
    }
}
