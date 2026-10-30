param(
    [Parameter(Mandatory=$true)][string]$InputDocument,
    [Parameter(Mandatory=$true)][string]$OutputPdf
)

$ErrorActionPreference = 'Stop'
$inputPath = (Resolve-Path -LiteralPath $InputDocument).Path
$pdfPath = [System.IO.Path]::GetFullPath($OutputPdf)
$word = $null
$document = $null
try {
    $word = New-Object -ComObject Word.Application
    $word.Visible = $false
    $word.DisplayAlerts = 0
    $document = $word.Documents.Open($inputPath, $false, $true, $false)
    $document.Repaginate()
    $pages = $document.ComputeStatistics(2)
    $document.ExportAsFixedFormat($pdfPath, 17)
    Write-Output "Rendered $pages pages to $pdfPath"
} finally {
    if ($null -ne $document) {
        $document.Close([ref]0)
        [void][System.Runtime.InteropServices.Marshal]::ReleaseComObject($document)
    }
    if ($null -ne $word) {
        $word.Quit([ref]0)
        [void][System.Runtime.InteropServices.Marshal]::ReleaseComObject($word)
    }
}
