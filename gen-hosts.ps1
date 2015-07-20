$sawsinfo = Get-Content "C:\saws-info.json"

$info = ConvertFrom-Json -InputObject $sawsinfo



$output = ""
foreach ($h in $info) {
  $hostname = $h.Tags[0].Value
  $addr = $h.PrivateIPAddress
  $output = $output + "$addr $hostname`r`n"
}

echo $output | Out-File "C:\windows\system32\drivers\etc\hosts"

