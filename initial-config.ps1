<powershell>

Set-ExecutionPolicy Unrestricted -Force

Start-Sleep -s 30

Set-AWSCredentials -AccessKey SAWS_ACCESS_KEY -SecretKey SAWS_SECRET_KEY
Read-S3Object -BucketName SAWS_S3BUCKET -Key package.zip -File C:\package.zip

$stillfailed = ""
while ($stillfailed -eq "") {
	try {
	  Read-S3Object -BucketName SAWS_S3BUCKET -Key saws-info.json -File C:\saws-info.json
	} catch {
	    echo "Waiting..."
	    Start-Sleep -s 5
	    continue
	}
	
	$stillfailed = "there"
}

mkdir C:\saws-package
[System.Reflection.Assembly]::LoadWithPartialName("System.IO.Compression.FileSystem")
[System.IO.Compression.ZipFile]::ExtractToDirectory("C:\package.zip", "C:\saws-package")

Rename-Computer -Force -NewName SAWS_HOSTNAME
C:\saws-package\gen-hosts.ps1

$src = "http://docs.saltstack.com/downloads/Salt-Minion-2015.5.3-AMD64-Setup.exe"
$dst = "C:\Users\Administrator\Salt-Minion-2015.5.3-AMD64-Setup.exe"
Invoke-Webrequest $src -Outfile $dst
C:\Users\Administrator\Salt-Minion-2015.5.3-AMD64-Setup.exe /S /master=salt /minion-name=SAWS_HOSTNAME

</powershell>
