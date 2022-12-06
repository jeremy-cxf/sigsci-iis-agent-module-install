#Requires -RunAsAdministrator
[CmdletBinding()]
param(
    [String]$modversion,
    [String]$agentversion,
    [String]$accesskeyid,
    [String]$secretaccesskey
)

# Set the rest of the variables
$TMP = $env:temp
$PROGRAMFILES = $env:ProgramFiles
$DLENDPOINT = "https://dl-signalsciences-net.s3-us-west-2.amazonaws.com/?delimiter=/&prefix=sigsci-module-iis/"
$AGENTDLENDPOINT = "https://dl-signalsciences-net.s3-us-west-2.amazonaws.com/?delimiter=/&prefix=sigsci-agent/"
$CONFDIR = "$PROGRAMFILES\Signal Sciences\Agent\agent.conf"

# Log Helpers
function LogInfo($text) {
    Write-Host "[i] INFO: " -ForegroundColor Yellow -NoNewline; Write-Host $text -ForegroundColor Green;
}

function LogWarning($text) {
    Write-Host "[!] WARNING: " -ForegroundColor Magenta -NoNewline; Write-Host $text -ForegroundColor Yellow;
}

Function ValidateModVersion() { 
    LogInfo "Checking for module version: $modversion"
    ## We download the XML from the sigsci mirror and check the prefixes for versions available.
    ## I don't see a reason to even bother trying anything less than version 2. 
    LogInfo "Downloading Module List..."
    $progressPreference = 'silentlyContinue'
    $rsp = Invoke-WebRequest -Uri $DLENDPOINT -Method Get -MaximumRedirection 0
    $rsp
    [xml]$xml = $rsp.Content
    $id = @($xml.ListBucketResult.CommonPrefixes.Prefix) 
    [array]::Reverse($id)
    $versions = $id | ForEach-Object { $_.split("/")[1] }
    $validversions = @($versions -ge [System.Version]"2.0.0")
    # Trim the prefixes to just the version Number.
    if ($validversions -notcontains $modversion) {
        Write-Error "Invalid Module Version provided ($modversion), please make sure its available and you're using the right version format (e.g 3.1.0)"
        LogInfo "Versions Available: `n"
        # We know latest is always going to be there.
        Write-Host latest
        $validversions 
        exit 1
    }
    else {
        LogInfo "$modversion exists, continuing..."
    }
}

Function ValidateAgentVersion($1, $agentversion, $xmlurl) {
    LogInfo "Checking for $1 version: $agentversion"
    ## We download the XML from the sigsci mirror and check the prefixes for versions available.
    ## I don't see a reason to even bother trying anything less than version 2 for the module and 4.6.0 for the agent.
    LogInfo "Downloading $1 version list..."
    $progressPreference = 'silentlyContinue'
    $rsp = Invoke-WebRequest -Uri $xmlurl -Method Get -MaximumRedirection 0
    $rsp
    [xml]$xml = $rsp.Content
    $versions = @($xml.ListBucketResult.CommonPrefixes.Prefix) | ForEach-Object {
        $_.Split("/")[1] 
    }
    [array]::Reverse($versions)

    # Because of the naming convention of the agent we can't really compare system version types.
    # We just check if its 5 or more and doesn't start with 1 or 3
    $validversions = @()
    foreach ($version in $versions) {
        if ($version -notmatch "^([0-3]|[4]\.[0-5].[1-10]$).*") {
            $validversions = $validversions += $version
        }
    }

    # Trim the prefixes to just the version Number.
    if ($agentversion -notcontains $validversions) {
        Write-Error "Invalid Agent Version, please make sure its available (>= 4.6.0) and you're using the right version format (e.g )"
        LogInfo "Versions Available: `n"
        Write-Host latest
        $validversions 
        exit 1
    }
    else {
        LogInfo "$modversion exists, continuing..."
    }   
}

Function VerifyHash($shafile, $file) {
    LogInfo "Verifying Hash"
    LogInfo "$shafile"
    $Hash = (Get-Content .\$shafile | ForEach-Object { $_.split(" ")[0] })
    $FileHash = (Get-FileHash ./$file -Algorithm SHA256).hash.tolower() 
    if ($FileHash -notmatch $Hash) {
        Write-Warning "Checksums do not match, make sure the download is not broken and 'latest' is recent"
        exit 1
    }
    else {
        LogInfo "Hash OK"
    }
}

Function ModCheck {
    $modules = @(& "$PROGRAMFILES\Signal Sciences\IIS Module\SigsciCtl.exe" Get-Modules)
    if ($modules -match ([String]"SigsciIISModule")) {
        $true
    }
    else {
        $false
    }
}

# Check if file we're downloading already exists before we download it.
# If the file already exists, skip the download.
Function FileExists ($file, $path) {
    if (-not(Test-Path -Path $file -PathType Leaf)) {
        LogInfo "$file Path:"; Write-Host $path -ForegroundColor Magenta 
        LogInfo "Downloading $file to $file..."
        Invoke-WebRequest $path -OutFile .\$file
    }
    else {
        LogInfo "$file exists, skipping download"
    }
}

# Start / Stop / Restart Service and Catch the Error.
# Sigsci doesn't really throw an exception in most cases unfortunately.
function ServiceCatch($ServiceName, $Method) {
    switch ( $Method ) {
        Restart { $cmd = 'Restart-Service $ServiceName -ErrorAction Stop' }
        Start { $cmd = 'Start-Service $ServiceName -ErrorAction Stop' }
        Stop { $cmd = 'Stop-Service $ServiceName -ErrorAction Stop' }
    } 
    try {
        Invoke-Expression $cmd
    }
    catch {
        Write-Host "[!] [ERROR]: Failed to $Method $ServiceName" -ForegroundColor Red
        Write-Error $_
        LogWarning "Check Event Viewer for further errors..."
        exit 1
    }
}

# Service Restart/Start Logic.
function CheckService($service) {
    $ServiceName = $service
    $arrService = Get-Service -Name $ServiceName
    $serviceStatus = $arrService.status
    LogInfo "$ServiceName is: $serviceStatus"
    if ($arrService.Status -eq 'Running') {
        LogInfo "Restarting $ServiceName"
        ServiceCatch  $ServiceName Restart
    }
    else {
        LogInfo "Starting $ServiceName"
        ServiceCatch  $ServiceName Start
    }

    LogInfo "Service $ServiceName starting..."
    Start-Sleep -seconds 15
    $arrService.Refresh()
    if ($arrService.Status -eq 'Running') {
        LogInfo "$ServiceName is now Running"
    }
    else {
        LogWarning "Failed to start $ServiceName"
    }
}



#  Check Arguments, these are mandatory for better automation (e.g they can be passed in from tooling / manifests).
if (-not($modversion)) { 
    Write-Error "-modversion MUST be supplied"
    exit 1
}
elseif (-not($agentversion)) {
    Write-Error "-agentversion MUST be supplied"
    exit 1
}


$t = @"
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|s|i|g|s|c|i|w|i|n|s|t|a|l|l|
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
"@

for ($i = 0; $i -lt $t.length; $i++) {
    if ($i % 2) {
        $c = "red"
    }
    elseif ($i % 5) {
        $c = "yellow"
    }
    elseif ($i % 7) {
        $c = "green"
    }
    else {
        $c = "white"
    }
    write-host $t[$i] -NoNewline -ForegroundColor $c
}
write-host "`r"
Write-Host "==============================" -ForegroundColor Magenta


# We check if the accesskey and secretaccesskey are passed in.
# If we find an agent.conf we'll use that instead.
if (-not($accesskeyid) -or -not($secretaccesskey) -and (Test-Path agent.conf) -eq $false) { 
    LogWarning "No agent.conf found"
    LogWarning "Neither accesskeyid nor secretaccesskey are set, the agent will not be able to start without them."
    LogWarning "Setting basic config file..."
    $noRestart = $true 
    $accesskeyid = "null"
    $secretaccesskey = "null"
}
elseif (-not($accesskeyid) -or -not($secretaccesskey) -and (Test-Path agent.conf) -eq $true) {
    LogInfo "Using supplied agent.conf file"
    $localConfig = $true 
}
else {
    $basicKeyConf = $true
    LogInfo "Writing base config with provided keys"
}




# We install IIS if not present on the server.
if ((Get-WindowsFeature Web-Server).InstallState -eq "Installed") {
    LogInfo "IIS is installed. Skipping Install"
}
else {
      
    LogInfo "IIS is not installed. Enabling..."
    Set-ExecutionPolicy Bypass -Scope Process
    Enable-WindowsOptionalFeature -Online -FeatureName IIS-WebServerRole
    Enable-WindowsOptionalFeature -Online -FeatureName IIS-WebServer
    Enable-WindowsOptionalFeature -Online -FeatureName IIS-CommonHttpFeatures
    Enable-WindowsOptionalFeature -Online -FeatureName IIS-HttpErrors
    Enable-WindowsOptionalFeature -Online -FeatureName IIS-HttpRedirect
    Enable-WindowsOptionalFeature -Online -FeatureName IIS-ApplicationDevelopment
    Enable-WindowsOptionalFeature -online -FeatureName NetFx4Extended-ASPNET45
    Enable-WindowsOptionalFeature -Online -FeatureName IIS-NetFxExtensibility45
    Enable-WindowsOptionalFeature -Online -FeatureName IIS-HealthAndDiagnostics
    Enable-WindowsOptionalFeature -Online -FeatureName IIS-HttpLogging
    Enable-WindowsOptionalFeature -Online -FeatureName IIS-LoggingLibraries
    Enable-WindowsOptionalFeature -Online -FeatureName IIS-RequestMonitor
    Enable-WindowsOptionalFeature -Online -FeatureName IIS-HttpTracing
    Enable-WindowsOptionalFeature -Online -FeatureName IIS-Security
    Enable-WindowsOptionalFeature -Online -FeatureName IIS-RequestFiltering
    Enable-WindowsOptionalFeature -Online -FeatureName IIS-Performance
    Enable-WindowsOptionalFeature -Online -FeatureName IIS-WebServerManagementTools
    Enable-WindowsOptionalFeature -Online -FeatureName IIS-IIS6ManagementCompatibility
    Enable-WindowsOptionalFeature -Online -FeatureName IIS-Metabase
    Enable-WindowsOptionalFeature -Online -FeatureName IIS-ManagementConsole
    Enable-WindowsOptionalFeature -Online -FeatureName IIS-BasicAuthentication
    Enable-WindowsOptionalFeature -Online -FeatureName IIS-WindowsAuthentication
    Enable-WindowsOptionalFeature -Online -FeatureName IIS-StaticContent
    Enable-WindowsOptionalFeature -Online -FeatureName IIS-DefaultDocument
    Enable-WindowsOptionalFeature -Online -FeatureName IIS-WebSockets
    Enable-WindowsOptionalFeature -Online -FeatureName IIS-ApplicationInit
    Enable-WindowsOptionalFeature -Online -FeatureName IIS-ISAPIExtensions
    Enable-WindowsOptionalFeature -Online -FeatureName IIS-ISAPIFilter
    Enable-WindowsOptionalFeature -Online -FeatureName IIS-HttpCompressionStatic
    Enable-WindowsOptionalFeature -Online -FeatureName IIS-ASPNET45
}


# Set TLS for download:
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# We grab and set the filenames based on the path hierarchy
if ($modversion -Match "latest") {
    $modpath = "https://dl.signalsciences.net/sigsci-module-iis/sigsci-module-iis_latest.msi" 
    $modsha = "https://dl.signalsciences.net/sigsci-module-iis/sigsci-module-iis_latest.msi.sha256"
    $modfile = $modpath.split("/")[4]
    $modShaFile = $modsha.Split("/")[4]
}
else {
    ValidateModVersion
    $modpath = "https://dl.signalsciences.net/sigsci-module-iis/$modversion/sigsci-module-iis-x64-$modversion.msi"
    $modsha = "https://dl.signalsciences.net/sigsci-module-iis/$modversion/sigsci-module-iis-x64-$modversion.msi.sha256"
    $modfile = $modpath.split("/")[5]
    $modShaFile = $modsha.split("/")[5]
}
LogInfo "Shafile: $modShafile"
LogInfo "Modfile: $modfile"

FileExists $modfile $modpath

# Verify the Hash of the downloaded file, we should always get a fresh one (incase the file that exists is broken).
# We could probably loop this and re-download the file if its broken but i cba atm.
Invoke-WebRequest $modsha -OutFile $modShaFile
VerifyHash $modShaFile $modfile

# Download the Agent and Verify
if ($agentversion -Match "latest") {
    $agentpath = "https://dl.signalsciences.net/sigsci-agent/sigsci-agent_latest.msi" 
    $agentsha = "https://dl.signalsciences.net/sigsci-agent/sigsci-agent_latest.msi.sha256"
    $agentfile = $agentpath.split("/")[4]
    $agentShaFile = $agentsha.Split("/")[4]
}
else {
    ValidateAgentVersion "Agent" $agentversion $AGENTDLENDPOINT
    $agentpath = "https://dl.signalsciences.net/sigsci-agent/$agentversion/windows/sigsci-agent_$agentversion.msi"
    $agentsha = "https://dl.signalsciences.net/sigsci-agent/$agentversion/windows/sigsci-agent_$agentversion.msi.sha256"
    $agentfile = $agentpath.split("/")[7]
    $agentShaFile = $agentShaFile = $agentsha.Split("/")[7]
}

FileExists $agentfile $agentpath
LogInfo "Saving SHA too $agentShaFile"
Invoke-WebRequest $agentsha -OutFile $agentShaFile
VerifyHash $agentShaFile $agentfile

# Start the Install:
LogInfo "Installing $agentfile..."
$agentfile = Start-Process msiexec "/i $agentfile /quiet" -Wait
if ($agentfile.ExitCode -gt 0) {
    throw $($agentfile.ExitCode)
}

LogInfo "Stopping IIS..."
Write-Host "==============================" -ForegroundColor Magenta -NoNewline
Invoke-command -scriptblock { iisreset /noforce /stop }
Write-Host "==============================" -ForegroundColor Magenta

LogInfo "Installing SigSci IIS Module..."
LogInfo "Installing $modfile"

$modfile = Start-Process msiexec "/qn /i .\$modfile" -Wait
if ($modfile.ExitCode -gt 0) {
    throw $($modfile.ExitCode)
}
elseif ($INPUT -eq 'N') {
    Write-Warning "IIS has not been stopped. IIS module will not be installed."
}

# Access keys for Signal Sciences agent activation and configuration
if ($localConfig -eq $true) {
    $configValues = [ordered]@{}
    # Seperate the [block values]
    $section = "rootConfig"
    $configValues[$section] = [ordered]@{}
    switch -regex -file .\agent.conf {
        "^\[(.+)\]$" {
            $section = $matches[1].Trim()
            $configValues[$section] = [ordered]@{}
        }
        "^\s*([^#].+?)\s*=\s*(.*)" {
            $name, $value = $matches[1..2]
            # skip comments that start with hash:
            if (!($name.StartsWith("#"))) {
                $configValues[$section][$name] = $value.Trim()
            }
        }
    }   
    if (-not($configValues.rootConfig.Contains("accesskeyid")) -or -not($configValues.rootConfig.Contains("accesskeyid"))) {
        LogWarning "Provided agent.conf does not contain an access key..."
        exit 1
    }
    Copy-Item -Path .\agent.conf -Destination $CONFDIR
    if ((Test-Path $CONFDIR) -eq $false) {
        LogWarning "[ERROR] Config couldn't be written to $CONFDIR, you will need to manually add one..."
    }
}
elseif ($noRestart -eq $true ) {
    LogInfo "Stopping Agent to write to configuration file..."
    ServiceCatch "sigsci-agent" Stop
    Set-Content -Path $CONFDIR -Value @"
accesskeyid = "NULL"
secretaccesskey = "NULL"
rpc-address = "127.0.0.1:737"
rpc-version = 1
"@
}
else {
    LogInfo "Stopping Agent to write to configuration file..."
    ServiceCatch "sigsci-agent" Stop
    Set-Content -Path $CONFDIR -Value @"
accesskeyid = "$accesskeyid"
secretaccesskey = "$secretaccesskey"
rpc-address = "127.0.0.1:737"
rpc-version = 1
"@
}

LogInfo 'Restarting IIS for agent config re-initialisation...' 
Write-Host "==============================" -ForegroundColor Magenta -NoNewline
Invoke-command -scriptblock { iisreset }
Write-Host "==============================" -ForegroundColor Magenta

# Check if the module is registered
LogInfo "Checking module is registered with IIS"
$modRegistered = ModCheck
if ($modRegistered -eq $false) {
    LogWarning "Module was not registered, please verify the install."
    & "$PROGRAMFILES\Signal Sciences\IIS Module\SigsciCtl.exe" Get-Modules
}
else {
    LogInfo "Module is registered..."
    $modules
}

if ($noRestart) {
    LogWarning "Please make sure you add your keys and start the agent service manually in order for the agent to successfully start"
}
else {
    CheckService "sigsci-agent"
} 