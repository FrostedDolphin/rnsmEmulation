# Define the target directory on the public desktop
$folderName = "shopping cart"
$desktopPath = "C:\Users\Public\Desktop"
$folderPath = Join-Path -Path $desktopPath -ChildPath $folderName

# Create the directory
New-Item -Path $folderPath -ItemType Directory -Force

# Define file names
$fileNames = @("soup.txt", "golden raisens.docx", "marlboro.pdf", "kona.sqlite")

# Create each file inside the directory
foreach ($file in $fileNames) {
    $filePath = Join-Path -Path $folderPath -ChildPath $file
    New-Item -Path $filePath -ItemType File -Force
}

# Add service names and weak passwords to soup.txt
$soupContent = @(
    "Service: RDP | Password: Password123",
    "Service: MSSQL | Password: admin1!",
    "Service: FTP | Password: letmein",
    "Service: SSH | Password: 12345678",
    "Service: SMB | Password: qwerty"
)
$soupFilePath = Join-Path -Path $folderPath -ChildPath "soup.txt"
$soupContent | Out-File -FilePath $soupFilePath -Encoding UTF8

Write-Host "`nCreated 'shopping cart' directory and files at: $folderPath"
