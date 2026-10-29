# Creates full-size Excel REVIEW copies of the frozen V3 CSV.GZ splits.
# Requirements: Microsoft Excel desktop installed on Windows.
# Model training continues to read CSV.GZ; XLSX is never training input.
param(
  [string]$ProjectRoot = 'D:\J26-CS-336-Network-Flow-V2\network_flow_v2',
  [switch]$ReplaceExisting
)
$ErrorActionPreference = 'Stop'
$root = (Resolve-Path -LiteralPath $ProjectRoot).Path
$splitDir = Join-Path $root 'data\splits\x_iiotid'
$excelDir = $splitDir  # Excel files sit next to their CSV.GZ sources.
# Temporary import files are created outside this research project.
$tempDir = Join-Path ([IO.Path]::GetTempPath()) ('XIIoTID_ExcelExport_' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Force -Path $tempDir | Out-Null
$parts = @(
  [pscustomobject]@{Name='train';Expected=574585},
  [pscustomobject]@{Name='validation';Expected=123125},
  [pscustomobject]@{Name='test';Expected=123124}
)
$expectedCols = 23
foreach($part in $parts){
    $source = Join-Path $splitDir "x_iiotid_core19_$($part.Name)_v3.csv.gz"
    if (!(Test-Path -LiteralPath $source)) { throw "Missing split input: $source" }
}
# When the three complete workbooks are already present, reuse them without opening Excel.
if (!$ReplaceExisting) {
    $alreadyDone = $true
    foreach ($part in $parts) {
        $savedXlsx = Join-Path $excelDir "x_iiotid_core19_$($part.Name)_v3.xlsx"
        if (!(Test-Path -LiteralPath $savedXlsx -PathType Leaf) -or
            (Get-Item -LiteralPath $savedXlsx).Length -le 0) { $alreadyDone = $false }
    }
    if ($alreadyDone) {
        Write-Host 'Three Excel copies already exist beside their CSV.GZ files. Reusing them.' -ForegroundColor Green
        if (Test-Path -LiteralPath $tempDir) { Remove-Item -LiteralPath $tempDir -Recurse -Force }
        exit 0
    }
}
try { $excel=New-Object -ComObject Excel.Application }
catch { throw 'Microsoft Excel desktop is required for complete XLSX exports with this script. The original CSV.GZ files remain safe.' }
$excel.Visible=$false
$excel.DisplayAlerts=$false
$excel.ScreenUpdating=$false
try {
  foreach($part in $parts){
    $source=Join-Path $splitDir "x_iiotid_core19_$($part.Name)_v3.csv.gz"
    $tempCsv=Join-Path $tempDir "x_iiotid_core19_$($part.Name)_v3.csv"
    $dest=Join-Path $excelDir "x_iiotid_core19_$($part.Name)_v3.xlsx"
    $partial=Join-Path $excelDir "x_iiotid_core19_$($part.Name)_v3.partial.xlsx"
    if ((Test-Path -LiteralPath $dest) -and !$ReplaceExisting){
        Write-Host "Excel file exists; leaving unchanged: $dest (use -ReplaceExisting to refresh)"
        continue
    }
    Write-Host "Exporting $($part.Name): $($part.Expected) rows"
    $inputStream=[IO.File]::OpenRead($source)
    $zipStream=New-Object IO.Compression.GzipStream($inputStream,[IO.Compression.CompressionMode]::Decompress)
    $outputStream=[IO.File]::Create($tempCsv)
    try { $zipStream.CopyTo($outputStream) }
    finally { $outputStream.Dispose();$zipStream.Dispose();$inputStream.Dispose() }
    $book=$null;$ws=$null;$query=$null
    try{
      $book=$excel.Workbooks.Add()
      while ($book.Worksheets.Count -gt 1) { $book.Worksheets.Item($book.Worksheets.Count).Delete() | Out-Null }
      $ws=$book.Worksheets.Item(1)
      $ws.Name=$part.Name
      # Import as text to preserve source values exactly (including placeholders and row IDs).
      $query=$ws.QueryTables.Add("TEXT;$tempCsv",$ws.Range('A1'))
      $query.TextFileParseType=1                 # xlDelimited
      $query.TextFileTextQualifier=1            # Double quotes
      $query.TextFileCommaDelimiter=$true
      $query.TextFileTabDelimiter=$false
      $query.TextFileSemicolonDelimiter=$false
      $query.TextFilePlatform=65001             # UTF-8
      $textTypes=New-Object 'int[]' $expectedCols
      for($j=0;$j -lt $expectedCols;$j++){$textTypes[$j]=2} # xlTextFormat
      $query.TextFileColumnDataTypes=$textTypes
      $null=$query.Refresh($false)
      $rows=[int]$ws.UsedRange.Rows.Count
      $cols=[int]$ws.UsedRange.Columns.Count
      if($rows -ne ($part.Expected + 1) -or $cols -ne $expectedCols){
        throw "Excel import mismatch ($($part.Name)): rows=$rows vs $($part.Expected+1), columns=$cols vs $expectedCols."
      }
      $query.Delete()
      $query=$null
      $ws.Range('A1:W1').Font.Bold=$true
      $ws.Range('A1:W1').Interior.ColorIndex=15
      $ws.Range('A1:W1').AutoFilter() | Out-Null
      $ws.Range('A:A').ColumnWidth=24
      $ws.Range('B:W').ColumnWidth=17
      $ws.Activate() | Out-Null
      $excel.ActiveWindow.SplitColumn=0
      $excel.ActiveWindow.SplitRow=1
      $excel.ActiveWindow.FreezePanes=$true
      if(Test-Path -LiteralPath $partial){Remove-Item -LiteralPath $partial -Force}
      $book.SaveAs($partial,51) | Out-Null   # xlOpenXMLWorkbook
      $book.Close($false) | Out-Null
      $book=$null
      Move-Item -LiteralPath $partial -Destination $dest -Force
      Write-Host "Verified $($part.Expected) rows + header and 23 columns: $dest" -ForegroundColor Green
    }finally{
      if($null -ne $book){try{$book.Close($false) | Out-Null}catch{}}
      if($null -ne $query){try{$query.Delete()}catch{}}
      if(Test-Path -LiteralPath $tempCsv){Remove-Item -LiteralPath $tempCsv -Force}
    }
  }
}finally{
  try{$excel.Quit()}catch{}
  [System.Runtime.InteropServices.Marshal]::ReleaseComObject($excel) | Out-Null
  [GC]::Collect();[GC]::WaitForPendingFinalizers()
  if (Test-Path -LiteralPath $tempDir) {Remove-Item -LiteralPath $tempDir -Recurse -Force}
}
Write-Host "Excel copies are stored beside their CSV.GZ files: $excelDir" -ForegroundColor Green
