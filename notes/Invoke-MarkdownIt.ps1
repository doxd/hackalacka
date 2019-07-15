# Uses markdown-it to convert md AD notes to html 
$header = '<link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/css/bootstrap.min.css" integrity="sha384-BVYiiSIFeK1dGmJRAkycuHAHRg32OmUcww7on3RYdg4Va+PmSTsz/K68vbdEjh4u" crossorigin="anonymous">';
Get-ChildItem .\*.md -Include "AD_*","OWASP*" | ForEach-Object {
    $inFile = $_.Name
    $tmpFile = $infile.replace(".md",".tmp")
    $outFile = $inFile.replace(".md",".html")
    Write-Host "[*] Working on $inFile "
    Write-Host "[*] Temp file: $tmpFile "
    Write-Host "[*] Output to: $outFile "
    Start-Process -FilePath "$env:USERPROFILE\Desktop\dev\node*\markdown-it" -ArgumentList ("$inFile", "-o", "$tmpFile") -Wait
    Write-Output $header > $outFile
    Get-Content $tmpFile >> $outFile
    Remove-Item $tmpFile
    Write-Host "[*] Done.`n`n "
}
