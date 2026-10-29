# Create readable Excel copies next to ToN-IoT Core10 CSV.GZ splits.
# Requires Microsoft Excel desktop. Temporary CSVs are outside the project.
param(
    [string]$ProjectRoot = 'D:\J26-CS-336-Network-Flow-V2\network_flow_v2',
    [switch]$ReplaceExisting
)
$ErrorActionPreference = 'Stop'
$root = (Resolve-Path -LiteralPath $ProjectRoot).Path
$dir = Join-Path $root 'data\splits\ton_iot'
$reportFile = Join-Path $root 'reports\audits\ton_iot_v3_split_report.json'
if (!(Test-Path -LiteralPath $reportFile)) { throw "Missing Notebook 03 report: $reportFile" }
$report = Get-Content -LiteralPath $reportFile -Raw | ConvertFrom-Json
$columns = [int]$report.num_columns
if ($columns -ne 13) { throw "Expected 13 Core10 columns, got: $columns" }
$parts = @('train', 'validation', 'test')
foreach ($p in $parts) {
    $inputGzip = Join-Path $dir "ton_iot_core10_${p}_v3.csv.gz"
    if (!(Test-Path -LiteralPath $inputGzip)) { throw "Missing compressed split: $inputGzip" }
    if ([int]$report.counts.$p.rows -gt 1048575) { throw "Excel worksheet row limit exceeded for $p" }
}

$todo = @($parts | Where-Object {
    $part = $_
    $target = Join-Path $dir "ton_iot_core10_${part}_v3.xlsx"
    $inputGzip = Join-Path $dir "ton_iot_core10_${part}_v3.csv.gz"
    $ReplaceExisting -or !(Test-Path -LiteralPath $target) -or
        ((Get-Item -LiteralPath $target).Length -eq 0) -or
        ((Get-Item -LiteralPath $target).LastWriteTimeUtc -lt (Get-Item -LiteralPath $inputGzip).LastWriteTimeUtc)
})
if ($todo.Count -eq 0) {
    Write-Host 'Excel copies already exist and are newer than the frozen CSV.GZ files.' -ForegroundColor Green
    exit 0
}

try { $excel = New-Object -ComObject Excel.Application }
catch { throw 'Microsoft Excel desktop is required. CSV.GZ datasets are unchanged.' }
$excel.Visible = $false
$excel.DisplayAlerts = $false
$excel.ScreenUpdating = $false
try {
    foreach ($p in $todo) {
        $gz = Join-Path $dir "ton_iot_core10_${p}_v3.csv.gz"
        $dest = Join-Path $dir "ton_iot_core10_${p}_v3.xlsx"
        $partial = Join-Path $dir "ton_iot_core10_${p}_v3.partial.xlsx"
        $expectedRows = [int]$report.counts.$p.rows
        $csvTemp = Join-Path ([IO.Path]::GetTempPath()) ('ton_iot_excel_' + [guid]::NewGuid().ToString('N') + '.csv')
        $readStream = [IO.File]::OpenRead($gz)
        $gzip = New-Object IO.Compression.GzipStream($readStream, [IO.Compression.CompressionMode]::Decompress)
        $writeStream = [IO.File]::Create($csvTemp)
        try { $gzip.CopyTo($writeStream) }
        finally { $writeStream.Dispose(); $gzip.Dispose(); $readStream.Dispose() }
        $book = $null; $query = $null
        try {
            $book = $excel.Workbooks.Add()
            while ($book.Worksheets.Count -gt 1) {
                $book.Worksheets.Item($book.Worksheets.Count).Delete() | Out-Null
            }
            $sheet = $book.Worksheets.Item(1)
            $sheet.Name = $p
            $query = $sheet.QueryTables.Add("TEXT;$csvTemp", $sheet.Range('A1'))
            $query.TextFileParseType = 1
            $query.TextFileTextQualifier = 1
            $query.TextFileCommaDelimiter = $true
            $query.TextFilePlatform = 65001
            $types = New-Object 'int[]' $columns
            for ($j = 0; $j -lt $columns; $j++) { $types[$j] = 2 }  # all as text
            $query.TextFileColumnDataTypes = $types
            $null = $query.Refresh($false)
            $actualRows = [int]$sheet.UsedRange.Rows.Count
            $actualColumns = [int]$sheet.UsedRange.Columns.Count
            if ($actualRows -ne ($expectedRows + 1) -or $actualColumns -ne $columns) {
                throw "Excel import differs for $p : $actualRows rows / $actualColumns columns"
            }
            $query.Delete(); $query = $null
            $header = $sheet.Range($sheet.Cells(1, 1), $sheet.Cells(1, $columns))
            $header.Font.Bold = $true
            $header.Interior.ColorIndex = 15
            $header.AutoFilter() | Out-Null
            $sheet.Columns.Item(1).ColumnWidth = 24
            $sheet.Range($sheet.Cells(1,2), $sheet.Cells(1,$columns)).EntireColumn.ColumnWidth = 18
            $sheet.Activate() | Out-Null
            $excel.ActiveWindow.SplitRow = 1
            $excel.ActiveWindow.FreezePanes = $true
            if (Test-Path -LiteralPath $partial) { Remove-Item -LiteralPath $partial -Force }
            $book.SaveAs($partial, 51) | Out-Null
            $book.Close($false) | Out-Null
            $book = $null
            Move-Item -LiteralPath $partial -Destination $dest -Force
            Write-Host "Created: $dest ($expectedRows records, $columns columns)" -ForegroundColor Green
        } finally {
            if ($null -ne $book) { try { $book.Close($false) | Out-Null } catch {} }
            if ($null -ne $query) { try { $query.Delete() } catch {} }
            if (Test-Path -LiteralPath $csvTemp) { Remove-Item -LiteralPath $csvTemp -Force }
        }
    }
} finally {
    try { $excel.Quit() } catch {}
    [void][System.Runtime.InteropServices.Marshal]::ReleaseComObject($excel)
    [GC]::Collect()
    [GC]::WaitForPendingFinalizers()
}
Write-Host "Excel and CSV.GZ files are together in: $dir" -ForegroundColor Green
