#!/user/bin/pwsh -Command
<#
	.SYNOPSIS
	
	.DESCRIPTION
	
	.PARAMETER inputString
	
	.EXAMPLE
	
	.NOTES
	
#>

<## Miscellaneous Functions ##>

# function for right padding
function RPAD ($inputString, $paddingLength)
{
	$inputString.PadRight($paddingLength)
}

# function for left padding
function LPAD ($inputString, $paddingLength)
{
	$inputString.PadLeft($paddingLength)
}
function Plural ($Integer) {
	If ($Integer -eq 1) {$S = ""} Else {$S = "s"}
	Return $S
}

function Debug ($DebugOutput, $callingFunctionName)
{
	$callingFunctionName = (Get-PSCallStack)[1].FunctionName
	$LNoPad = (LPAD ($MyInvocation.ScriptLineNumber.ToString()) 4) # Convert $lineNo to string as padding with integer is not possible
	$FNamePad = (RPAD ($callingFunctionName -replace '.*\.([^\.\s]+).*', '\$1') 20)
	
	If ($VerboseFile) { Write-Output "$(Get-Date -f "dd/MM/yyyy hh:mm:ss tt") : Line $LNoPad - [$FNamePad] - $DebugOutput" | Out-File $DebugLog -Encoding ASCII -Append }
	If ($VerboseConsole) { Write-Host "$(Get-Date -f "dd/MM/yyyy hh:mm:ss tt") : Line $LNoPad - [$FNamePad] - $DebugOutput" }
}

function EmailResults
{
	$Subject = $DBType + " - Nightly Backup"
	$EmailFrom = $server.ToUpper() + " - " + $DBType + "<" + $EmailFrom + ">"
	Try
	{
		$Body = (Get-Content -Path $EmailBody | Out-String)
		$Message = New-Object System.Net.Mail.Mailmessage $EmailFrom, $EmailTo, $Subject, $Body
		$Message.IsBodyHTML = $UseHTML
		
		$PSErrorLog = Join-Path $PSScriptRoot "PSError.log"
		if (Test-Path $PSErrorLog)
		{
			$fileContent = Get-Content $PSErrorLog -Raw
			if ($fileContent -ne '')
			{
				$Message.Attachments.Add($PSErrorLog)
			}
		}
		
		if (Test-Path $SQLDumpLog)
		{
			if ((Get-Item $SQLDumpLog).length -gt 0)
			{
				$Message.Attachments.Add($SQLDumpLog)
			}
			else
			{
				Remove-Item -Force -Path $SQLDumpLog
			}
		}
		
		if ($SendMail)
		{
			If (($AttachDebugLog) -and (Test-Path $DebugLog) -and (((Get-Item $DebugLog).length/1MB) -lt $MaxAttachmentSize)) { $Message.Attachments.Add($DebugLog) }
			$SMTP = New-Object System.Net.Mail.SMTPClient $SMTPServer, $SMTPPort
			$SMTP.EnableSsl = $SSL
			# Disable SSL certificate validation
			[System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $Disable_SSL_Validation }
			$SMTP.Credentials = New-Object System.Net.NetworkCredential($SMTPAuthUser, (ConvertTo-SecureString -String $SMTPAuthPass -AsPlainText -Force));
			$SMTP.Send($Message)
			Debug "Email Sent Successfully"
		}
		else
		{
			Debug "Switch to Send Email is OFF, Saving Eamil Contents to file"
			$FileName = "SQL-Email_$DateString.html"
			$FilePath = Join-Path $PSScriptRoot $FileName
			$MessageBody = "<html><body><p><strong>From:</strong> $EmailFrom</p><p><strong>To:</strong> $EmailTo</p><p><strong>Subject:</strong> $Subject</p><h1>Email Contents:</h1><p>$Body</p></body></html>"
			Set-Content -Path $FilePath -Value $MessageBody
			Debug "Email contents saved to HTML file: $FileName"
		}
	}
	Catch
	{
		Debug "Email ERROR : $($Error[0])"
	}
}

function Email ($EmailOutput)
{
	If ($UseHTML)
	{
		If ($EmailOutput -match "\[OK\]") { $EmailOutput = $EmailOutput -Replace "\[OK\]", "<span style=`"background-color:#4CAF50;color:white;font-weight:bold;font-family:Cambria;`">[OK]</span>" }
		If ($EmailOutput -match "\[INFO\]") { $EmailOutput = $EmailOutput -Replace "\[INFO\]", "<span style=`"background-color:#ADD8E6;color:#000000;font-weight:bold;font-family:Cambria;`">[INFO]</span>" }
		If ($EmailOutput -match "\[WARN\]") { $EmailOutput = $EmailOutput -Replace "\[WARN\]", "<span style=`"background-color: #FFFF00;;color:#000000;font-weight:bold;font-family:Cambria;`">[WARN]</span>" }
		If ($EmailOutput -match "\[ERROR\]") { $EmailOutput = $EmailOutput -Replace "\[ERROR\]", "<span style=`"background-color:#800000;color:#FFFFFF;font-weight:bold;font-family:Cambria;`">[ERROR]</span>" }
		If ($EmailOutput -match "\[ALERT\]") { $EmailOutput = $EmailOutput -Replace "\[ALERT\]", "<span style=`"background-color:#FFA500;color:#FFFFFF;font-weight:bold;font-family:Cambria;`">[ALERT]</span>" }
		If ($EmailOutput -match "^\s$") { $EmailOutput = $EmailOutput -Replace "\s", "&nbsp;" }
		Write-Output "<tr><td>$EmailOutput</td></tr>" | Out-File $EmailBody -Encoding ASCII -Append
	}
	Else
	{
		Write-Output $EmailOutput | Out-File $EmailBody -Encoding ASCII -Append
	}
}

function GmailResults ($GBody)
{
	Try
	{
		$Subject = "!!! SQL Backup Problem !!!"
		$GmailUser = $server.ToUpper() + " - " + $DBMSInfo.DBType + "<" + $GmailUser + ">"
		
		$PSErrorLog = Join-Path $PSScriptRoot "PSError.log"
		if (Test-Path $PSErrorLog)
		{
			$fileContent = Get-Content $PSErrorLog -Raw
			if ($fileContent -ne '')
			{
				$Message.Attachments.Add($PSErrorLog)
			}
		}
		
		$Message = New-Object System.Net.Mail.Mailmessage $GmailUser, $GmailTo, $Subject, $GBody
		$Message.IsBodyHTML = $False
		$SMTP = New-Object System.Net.Mail.SMTPClient("smtp.gmail.com", 587)
		$SMTP.EnableSsl = $True
		$SMTP.Credentials = New-Object System.Net.NetworkCredential($GmailUser, (ConvertTo-SecureString -String $GmailPass -AsPlainText -Force));
		$SMTP.Send($Message)
		Debug "Email using GMAIL sent successfully."
	}
	Catch
	{
		Debug "Failed to send GMAIL: : $_"
		Debug "Gmail ERROR : $($Error[0])"
	}
}

## Error Email Sending
function EmailInitError
{
	param (
		[Parameter(Mandatory = $true)]
		[string]$ErrorMessage
	)
	
	$Subject = "ERROR - " + $DBType + " - Nightly Backup"
	$EmailFrom = $server.ToUpper() + " - " + $DBType + "<" + $EmailFrom + ">"
	$Body = $ErrorMessage
	
	$Message = New-Object System.Net.Mail.Mailmessage $EmailFrom, $EmailTo, $Subject, $Body
	$Message.IsBodyHTML = $False
	$SMTP = New-Object System.Net.Mail.SMTPClient $SMTPServer, $SMTPPort
	$SMTP.EnableSsl = $UseSSL
	$SMTP.Credentials = New-Object System.Net.NetworkCredential($SMTPAuthUser, $SMTPAuthPass);
	$SMTP.Send($Message)
}

## function to Get Linux Distro Details
function Get-LinuxDistro {
	$releaseFiles = @("/etc/*release")

	foreach ($file in $releaseFiles) {
		$filePaths = Get-ChildItem -Path $file -ErrorAction SilentlyContinue
		foreach ($filePath in $filePaths) {
			$releaseInfo = Get-Content $filePath.FullName

			foreach ($line in $releaseInfo) {
				if ($line -match '^ID=') {
					$distroName = $line.Substring(3).Trim('"')

					$debianMatch = 'Ubuntu|Debian|Mint|elementary|Kali'
					$rhelMatch = 'CentOS|Fedora|RHEL|Red Hat|Oracle|Rocky|AlmaLinux|CloudLinux'
					$distroType = if ($distroName -match $debianMatch) { "Debian-based" }
								  elseif ($distroName -match $rhelMatch) { "RHEL-based" }
								  else { "Unknown" }

					return @{
						DistroName   = $distroName
						DistroType   = $distroType
					}
				}
			}
		}
	}

	return @{
		DistroName = "Unknown"
		DistroType = "Unknown"
	}
}

## function to GET Required OS details
function Get-OS
{
	$platform = [System.Environment]::OSVersion.Platform
	switch ($platform)
	{
		{ ($_ -eq 'Win32NT') -or ($_ -eq 'Win32S') -or ($_ -eq 'Win32Windows') -or ($_ -eq 'WinCE') } {
			$os = "Windows"
			$ComputerName = $env:COMPUTERNAME
			$bootTime = Get-CimInstance -ClassName Win32_OperatingSystem | Select-Object LastBootUpTime | ForEach-Object { $_.LastBootUpTime.ToString("yyyy-MM-dd HH:mm:ss") }
			$primaryNIC = Get-NetAdapter | Where-Object Status -eq Up | Sort-Object InterfaceIndex | Select-Object -First 1
			# Retrieve all IP addresses based on the ifIndex
			$ipAddresses = (Get-NetIPAddress | Where-Object ifIndex -eq $primaryNIC.ifIndex | Sort-Object -Property InterfaceIndex | Select-Object -ExpandProperty IPAddress)
			# Filter out and select only the IPv4 address
			$ipv4 = $ipAddresses | Where-Object { $_ -match '\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}' } | Select-Object -First 1
		}
		{ $_ -eq 'Unix' } {
			$uname = uname
			if ($uname -eq 'Linux')
			{
				$os = "Linux"
				$ComputerName = hostname
				$uptime = Get-Content /proc/uptime
				$uptimeSeconds = $uptime.Split()[0]
				# Convert uptime to DateTime
				$bootTimeOutput = (Get-Date).AddSeconds(-$uptimeSeconds)
				$bootTime = $bootTimeOutput.ToString('yyyy-MM-dd HH:mm:ss')
				$primaryNIC = ip -o addr show | grep 'scope global' | grep -Eo 'inet ([0-9]{1,3}\.){3}[0-9]{1,3}' | awk '{print $2}'
				$ipv4 = $primaryNIC.Split('/')[0]
				# Get Linux distro details
                $distroDetails = Get-LinuxDistro
                $distroName = $distroDetails.DistroName
                $distroType = $distroDetails.DistroType
			}
			elseif ($uname -eq 'Darwin')
			{
				$os = "macOS"
				## macOS IPv4 retrieval code here
				Debug "MAC OS is not yet Tested, Exiting..."
				Exit 1
			}
			else
			{
				$os = "Unknown OS, Exiting..."
				Exit 1
			}
		}
		default {
			$os = "Unknown OS"
		}
	}
	
	return @{
		OSName		 = $os
		ComputerName = $ComputerName
		OSBootTime   = $bootTime
		IPv4		 = $ipv4
		DistroName   = $distroName
		DistroType   = $distroType
	}
}

function Install-7Zip {
	[CmdletBinding()]
	param(
		[Parameter()]
		[ValidateSet('64', '32', 'Detect')]
		[string]$Architecture = "Detect"
	)

	try {
		# Setting TLS version for web requests
		[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

		# Website and temporary file variables
		$TempFolder = "C:\Users\$env:username\AppData\Local\Temp\7Zip"
		$7zipWebsite = 'https://7-zip.org/'

		# Detect Architecture if 'Detect' mode is selected
		if ($Architecture -eq 'Detect') {
			Debug "Detecting OS architecture to Check the appropriate version of 7-Zip"
			# Determine if the system is 64-bit
			if ([Environment]::Is64BitOperatingSystem) {
				Debug "OS 64-bit, Using 7-zip 64 bit"
				$Architecture = '64'
				$architectureFilter = "*-x64.exe"
			} else {
				Debug "OS 32-bit, Using 7-zip 32 bit"
				$Architecture = '32'
				$architectureFilter = "*"
			}
		} elseif ($Architecture -eq '32') {
			Debug "OS Bit Manual, Using 7-zip 32 bit"
			$architectureFilter = "*"
		} elseif ($Architecture -eq '64') {
			Debug "OS Bit Manual, Using 7-zip 64 bit"
			$architectureFilter = "*-x64.exe"
		} else {
			Debug "User specified Unknown $Architecture-bit architecture."
			return  # Exit if user has specified an unsupported architecture
		}
		
		# Retrieve the download link based on architecture filter
		$webLocation = $7zipWebsite + (Invoke-WebRequest -Uri $7zipWebsite | Select-Object -ExpandProperty Links | Where-Object {($_.innerHTML -eq 'Download') -and ($_.href -like "a/*") -and (($Architecture -eq '64' -and $_.href -like "*-x64.exe") -or ($Architecture -eq '32' -and $_.href -notlike "*-x64.exe"))} | Select-Object -ExpandProperty href).Split(' ')[0]
		
		# Extract version number and set variables
		if ($webLocation -match "7z(\d+)(-x64)?.exe") {
			$version = $matches[1]
			$7zipexename = "7z${version}$($matches[2]).exe"
			$filename = "7z${version}-extra.7z"
			$7zaextra = "${7zipWebsite}a/${filename}"
		} else {
			throw "Could not extract version number from the link for architecture: $Architecture"
		}
		
		#Debug "Link to 7-Zip executable found: $webLocation"
		#Debug "Link to extra file: $7zaextra"
		

		# Check if 7-Zip is already installed
		$7zipPath64 = Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Where-Object { $_.DisplayName -like "7-Zip*" } | Select-Object -ExpandProperty InstallLocation -First 1
		$7zipPath32 = Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Where-Object { $_.DisplayName -like "7-Zip*" } | Select-Object -ExpandProperty InstallLocation -First 1

		$7zipPath = if ($Architecture -eq '64') { $7zipPath64 } else { $7zipPath32 }

		if (-not $7zipPath) {

			# Ensure temporary download folder exists
			#Debug "Creating temporary work directory in $TempFolder"
			if (-not (Test-Path $TempFolder -PathType Container)) {
				New-Item -Path $TempFolder -ItemType Directory | Out-Null
			}

			Debug "7-Zip not detected. Downloading $Architecture-bit and installing it."
			$Temp7zipFile = Join-Path -Path $TempFolder -ChildPath $7zipexename
			# Remove any existing temporary download file
			if (Test-Path $Temp7zipFile) {
				Remove-Item $Temp7zipFile
			}

			# Download 7-Zip installer
			#Debug "Start the download of $weblocation to $Temp7zipFile"
			Invoke-WebRequest -Uri $webLocation -OutFile $Temp7zipFile

			# Install 7-Zip
			#Debug "Installing 7-Zip from $Temp7zipFile"
			try {
				Start-Process -FilePath "$Temp7zipFile" -ArgumentList '/S' -Verb Runas -Wait
			}
			catch {
				Debug "Failed to install 7-Zip: $_"
				return $null
			}

			# Recheck installation path after installation
			$7zipPath64 = Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Where-Object { $_.DisplayName -like "7-Zip*" } | Select-Object -ExpandProperty InstallLocation -First 1
			$7zipPath32 = Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Where-Object { $_.DisplayName -like "7-Zip*" } | Select-Object -ExpandProperty InstallLocation -First 1	
			
			$7zipPath = if ($Architecture -eq '64') { $7zipPath64 } else { $7zipPath32 }
			if (-not $7zipPath) {
				throw "7-Zip NOT detected"
			}
		} else {
			#Debug "7-Zip detected at $7zipPath"
		}

		# Check if 7za.exe exists in the installation path
		$7zaPath = Join-Path -Path $7zipPath -ChildPath '7za.exe'
		if (-not (Test-Path $7zaPath)) {
			Debug "7za.exe not found in `"$7zipPath`", Downloading and copying it."
			
			#Debug "Creating temporary work directory in $TempFolder"
			if (-not (Test-Path $TempFolder -PathType Container)) {
				New-Item -Path $TempFolder -ItemType Directory | Out-Null
			}

			$Temp7zipExtraFile = Join-Path -Path $TempFolder -ChildPath $filename
			# Remove any existing temporary download file
			if (Test-Path $Temp7zipExtraFile) {
				Remove-Item $Temp7zipExtraFile -Force
			}

			# Download 7za.exe
			#Debug "Downloading 7za extra zip from $7zaextra to $Temp7zipExtraFile"
			Invoke-WebRequest -Uri $7zaextra -OutFile $Temp7zipExtraFile

			# Extract 7za.exe
			#Debug "Extracting 7za.exe to $7zipPath"
			$SpecificFileName = if ($Architecture -eq '64') { "x64\7za.exe" } else { "7za.exe" }
			try {
				$command = "& '$7zipPath\7z.exe' e '$Temp7zipExtraFile' -o'$7zipPath' $SpecificFileName -aoa"
				Invoke-Expression $command 2>&1 | Out-Null
				Debug "Copied 7za.exe to $7zipPath"
			} catch {
				# Handle any errors caught during execution
				Debug "Error occurred while executing 7-Zip command: $_"
				return $null
			}

			# Verify extraction
			if (-not (Test-Path $7zaPath)) {
				throw "No 7za.exe Found."
			}
		} else {
			#Debug "7za.exe found in $7zipPath"
		}

		# Clean up temporary files
		if (Test-Path $TempFolder -PathType Container) {
			#Debug "Cleaning up the temporary work directory"
			Remove-Item $TempFolder -Recurse -Force
		} else {
			# Nothing to Do
		}

		# Return paths to 7z.exe and 7za.exe hash table need to be in quotes as variables start with numeral
		return @{
			Szip = Join-Path -Path $7zipPath -ChildPath '7z.exe'
			Szipa = $7zaPath
		}
	}
	catch {
		Debug "An error occurred: $_"
		return $null
	}
}

## function to Set Seven Zip Path
function Set-SevenZipExePath {
	param (
		[string]$DistroType = ""
	)

	$os = $OSname

	switch ($os) {
		"Windows" {
			$SevenZipA = $SevenZipPath
			if (-not $SevenZipPath) {
				Debug "CONFIG: SevenZipPath is blank, Checking 7-Zip Auto Mode"
				$7zipPaths = Install-7Zip
				# Check if Install-7Zip function executed successfully
				if ($7zipPaths) {
					# Access paths to 7z.exe and 7za.exe from the returned hashtable
					$SevenZipExe = $($7zipPaths.Szip)
					$SevenZipA = $($7zipPaths.Szipa)
					#Debug "Path to 7z.exe: $($SevenZipExe)"
					#Debug "Path to 7za.exe: $($SevenZipA)"
				} else {
					Debug "Failed to install 7-Zip, Can't continue..."
					Eamil "Failed to install 7-Zip, Can't continue..."
					Exit 1
				}
			} else {
				Debug "Manual 7-Zip Path Used: $($SevenZipPath)"
			}
		}
		"Linux" {
			$SevenZipA = $(which 7za)
			if (-not $SevenZipA) {
				if ($DistroType -eq "") {
					Debug "DistroType is required for Linux. Exiting..."
					exit 1
				}
				switch ($DistroType) {
					"Debian-based" {
						Debug "Debian-based distribution detected. Installing 7-Zip..."
						sudo apt update
						sudo apt-get install p7zip-full -y -q
					}
					"RHEL-based" {
						Debug "RHEL-based distribution detected. Installing 7-Zip..."
						sudo dnf install p7zip p7zip-plugins -y -q
					}
					default {
						Debug "Unsupported Linux distribution type. Can't install 7-Zip."
						exit 1
					}
				}
				$SevenZipA = $(which 7za)
			}
		}
		"macOS" {
			Debug "MAC OS is not yet Tested, Exiting..."
			Exit
		}
		default {
			Debug "Unsupported operating system."
			return
		}
	}
	#Debug "DEBUG: Path to 7zipA: $SevenZipA"
	return $SevenZipA
}

## function to Check if required Powershell Module is installed if not install it
function Confirm-Module
{
	Param
	(
		[Parameter(Mandatory = $true, Position = 0)]
		[string]$ModuleName,
		[Parameter(Mandatory = $true, Position = 1)]
		[string]$Version
	)
	Debug "------------------------------------------------------------------------"
	$os = $OSname
	switch ($os)
	{
		"Windows" {
			# Check If the current user has administrator privileges
			If (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator"))
			{
				Debug "Script is not running with administrator privileges. Relaunching as administrator..."
				# If not, relaunch as administrator
				Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
				Exit
			}
		}
		"Linux" {
			# Check if the script is being run as root
			If (-not $(id -u) -eq 0)
			{
				Debug "Script is not running with root privileges maybe I cannot install Module."
				
				# Get the current user name
				#$userName = $env:USER
				
				# Get the current user's primary group
				#$groupName = $(id -gn)
			}
		}
	}
	
	Debug "Checking If $($ModuleName) module version $($Version) is installed..."
	
	# Check If module is installed
	$TestModule = Get-InstalledModule -Name $ModuleName
	If ($TestModule)
	{
		#Check if required version is present
		$CurrentVersion = $TestModule.Version
		Debug "$($ModuleName) module version $CurrentVersion is installed."
		If ($CurrentVersion -ne $Version)
		{
			Debug "Upgrading $($ModuleName) module to version $($Version)..."
			# Upgrade module to version specified if not
			Try
			{
				Install-Module -Name $ModuleName -AllowClobber -RequiredVersion $Version -Repository PSGallery -Scope AllUsers -NoConfirmation -Force -ErrorAction Stop
				Email "[OK] PS $($ModuleName) v $($Version) installed Successfully"
			}
			Catch
			{
				$errorMessage = $_.Exception.Message
				Debug "Error occurred while upgrading $($ModuleName) module: $errorMessage"
				# Send email notIfication about the error
				Email "Error occurred while upgrading $($ModuleName) module: $errorMessage"
				Exit
			}
		}
		Else
		{
			Debug "$($ModuleName) module is up to date."
		}
	}
	Else
	{
		Debug "$($ModuleName) module is not installed. Installing version $($Version)..."
		# Install module to version specified
		Try
		{
			Install-Module -Name $ModuleName -AllowClobber -RequiredVersion $Version -Repository PSGallery -Scope AllUsers -NoConfirmation -Force -ErrorAction Stop
			Email "[OK] PS Module $($ModuleName) v $($Version) installed Successfully"
		}
		Catch
		{
			$errorMessage = $_.Exception.Message
			Debug "Error occurred while installing $($ModuleName) module: $errorMessage"
			# Send email notIfication about the error
			Email "Error occurred while installing $($ModuleName) module: $errorMessage"
			Exit
		}
	}
	Debug "------------------------------------------------------------------------"
}

## function to Check if required Path is valid
function Confirm-Path ($Location)
{
	If (-not (Test-Path $Location))
	{
		Debug "[ERROR] Folder location $Location does not exist : Quitting script"
		Email "[ERROR] Folder location $Location does not exist : Quitting script"
		EmailResults
		Exit 1
	}
}

## function to Calculate Elapsed time of a process, script ot whatever
function ElapsedTime ($EndTime)
{
	$TimeSpan = New-Timespan $EndTime
	If (([math]::Floor(($TimeSpan).Days)) -eq 0) { $Days = "" }
	ElseIf (([math]::Floor(($TimeSpan).Days)) -eq 1) { $Days = "1 day " }
	Else { $Days = "$([math]::Floor(($TimeSpan).Days)) days " }
	If (([math]::Floor(($TimeSpan).Hours)) -eq 0) { $Hours = "" }
	ElseIf (([math]::Floor(($TimeSpan).Hours)) -eq 1) { $Hours = "1 hour " }
	Else { $Hours = "$([math]::Floor(($TimeSpan).Hours)) hours " }
	If (([math]::Floor(($TimeSpan).Minutes)) -eq 0) { $Minutes = "" }
	ElseIf (([math]::Floor(($TimeSpan).Minutes)) -eq 1) { $Minutes = "1 minute " }
	Else { $Minutes = "$([math]::Floor(($TimeSpan).Minutes)) minutes " }
	If (([math]::Floor(($TimeSpan).Seconds)) -eq 1) { $Seconds = "1 second" }
	Else { $Seconds = "$([math]::Floor(($TimeSpan).Seconds)) seconds" }
	
	If (($TimeSpan).TotalSeconds -lt 1)
	{
		$Return = "less than 1 second"
	}
	Else
	{
		$Return = "$Days$Hours$Minutes$Seconds"
	}
	Return $Return
}

## function to TEST LOCAL CNF File for MySQL (To stop warning in console for insecure Password)
function DBServiceCheck ($ServiceName)
{
	$os = $OSname
	switch ($os)
	{
		"Windows" {
			# Check if the service is already running
			$Service = Get-Service $ServiceName -ErrorAction SilentlyContinue
			if ($null -ne $Service -and $Service.Status -eq 'Running')
			{
				Debug "SERVICE: `"$ServiceName`" is running."
				return
			}
			
			# IF not Running Start the service
			Debug "$ServiceName Service Not Running, Trying to Start it"
			$BeginStartupRoutine = Get-Date
			try
			{
				Start-Service $ServiceName -ErrorAction Stop
				Start-Sleep -Seconds 5 # Wait for service initialization
				$Service = Get-Service $ServiceName -ErrorAction SilentlyContinue
				$ServiceStatus = $Service.Status
				$Timeout = $false
				while (($ServiceStatus -ne 'Running') -and (-not $Timeout))
				{
					$ElapsedTime = New-TimeSpan -Start $BeginStartupRoutine
					if ($ElapsedTime.TotalMinutes -gt $ServiceTimeout)
					{
						$Timeout = $true
						break
					}
					Start-Sleep -Seconds 1
					$Service.Refresh()
					$ServiceStatus = $Service.Status
				}
				
				if ($ServiceStatus -ne 'Running')
				{
					$errorMessage = "$ServiceName failed to start within $ServiceTimeout minutes."
					Debug $errorMessage
					GmailResults $errorMessage
					exit
				}
				else
				{
					$elapsedTime = (Get-Date) - $BeginStartupRoutine
					Debug "$ServiceName successfully started in $($elapsedTime.TotalSeconds) seconds."
					GmailResults "$($ServiceName) was not running... [OK] $($ServiceName) Service Started, Trying for Backup now"
				}
			}
			catch
			{
				$errorMessage = "Failed to start DB $ServiceName : " + $_
				Debug $errorMessage
				GmailResults $errorMessage
				exit
			}
		}
		"Linux" {
			$Service = systemctl status $ServiceName
			
			if ($Service -match 'Active: active')
			{
				Debug "SERVICE: `"$ServiceName`" is running."
				return
			}
			else
			{
				Debug "$ServiceName is not running, Trying to Start it"
				$BeginStartupRoutine = Get-Date
				try
				{
					sudo systemctl start $ServiceName
					Start-Sleep -Seconds 5 # Wait for service initialization
					$ServiceStatus = $(systemctl is-active $ServiceName)
					$Timeout = $false
					
					while (($ServiceStatus -ne 'active') -and (-not $Timeout))
					{
						$ElapsedTime = New-TimeSpan -Start $BeginStartupRoutine
						if ($ElapsedTime.TotalMinutes -gt $ServiceTimeout)
						{
							$Timeout = $true
							break
						}
						Start-Sleep -Seconds 1
						$Service.Refresh()
						$ServiceStatus = $(systemctl is-active $ServiceName)
					}
					
					if ($ServiceStatus -ne 'active')
					{
						$errorMessage = "$ServiceName failed to start within $ServiceTimeout minutes."
						Debug $errorMessage
						GmailResults $errorMessage
						exit
					}
					else
					{
						$elapsedTime = (Get-Date) - $BeginStartupRoutine
						Debug "$ServiceName successfully started in $($elapsedTime.TotalSeconds) seconds."
						GmailResults "$($ServiceName) was not running... 
						[OK] $($ServiceName) Service Started..
						Trying for Backup now."
					}
				}
				catch
				{
					$errorMessage = "Failed to start $ServiceName : " + $_
					Debug $errorMessage
					GmailResults $errorMessage
					exit
				}
			}
		}
	}
}

## function to TEST LOCAL CNF File for MySQL (To stop warning in console for insecure Password)
function Test-MySQLCnf
{
	$MySQLConfigContent = @"
[client]
user=$($Username)
password="$($Password)"

[mysql]
user=$($Username)
password="$($Password)"

[mysqldump]
user=$($Username)
password="$($Password)"
"@
	if (-not (Test-Path $MySQLConfFile))
	{
		$MySQLConfigContent | Out-File -FilePath $MySQLConfFile -Encoding ASCII
		Debug "MySQL Custom cnf file created at `"$MySQLConfFile`""
	}
	else
	{
		$RawContent = Get-Content -Path $MySQLConfFile -Raw
		$existingContent = $RawContent -replace '\s', '' # Remove extra spaces and line breaks
		
		$newContent = $MySQLConfigContent -replace '\s', '' # Remove extra spaces and line breaks
		
		if ($existingContent -eq $newContent)
		{
			Debug "MySQL Custom cnf contains the current credentials"
		}
		else
		{
			$MySQLConfigContent | Set-Content -Path $MySQLConfFile -Encoding ASCII
			Debug "MySQL Custom cnf updated to match new credentials"
		}
	}
}

## function to TEST DBMS Credentials
function Test-DBCon
{
	param (
		[Parameter(Mandatory = $true)]
		[string]$MyOS,
		[string]$DBType
	)
	
	if ($DBType -match "MySQL")
	{
		#$MySQLDumpPass = "-p$Password"
		$systemDatabase = "mysql"
		$query = "SHOW DATABASES;"
		try
		{
			if ($OSname -eq "Windows")
			{
				try
				{
					#$mysqlCommand = & $MySQLExe -u $Username $MySQLDumpPass -e $query | ForEach-Object { $_.Trim() } -ErrorAction Stop
					$mysqlCommand = & $MySQLExe --defaults-extra-file="$MySQLConfFile" -e $query | ForEach-Object { $_.Trim() } -ErrorAction Stop
					if ([string]::IsNullOrEmpty($mysqlCommand))
					{
						Debug "An error occurred testing the MySQL Credentials. Possiblely Credentials are Wrong"
						Exit
					}
					$result = $mysqlCommand
					
					foreach ($row in $result -split "`n")
					{
						$databaseName = $row.Trim()
						if ($databaseName -eq $systemDatabase)
						{
							Debug "$DBType Connection on $OSname successful, Moving Forward"
							return
						}
					}
					
					if ($existingDatabases -notcontains $systemDatabase)
					{
						Debug "System database Test Failed."
						Exit
					}
				}
				catch
				{
					Debug "Connection to $DBType on $OSname failed: $($Error[0])"
					Exit
				}
			}
			elseif ($OSname -eq "Linux" -or $OSname -eq "macOS")
			{
				
				try
				{
					#$mysqlCommand = & $MySQLExe -u $Username $MySQLDumpPass -e $query | ForEach-Object { $_.Trim() } -ErrorAction Stop
					$mysqlCommand = & $MySQLExe --defaults-extra-file="$MySQLConfFile" -e $query | ForEach-Object { $_.Trim() } -ErrorAction Stop
					if ([string]::IsNullOrEmpty($mysqlCommand))
					{
						Debug "An error occurred testing the MySQL Credentials. Possiblely Credentials are Wrong"
						Exit
					}
					$result = $mysqlCommand
					
					foreach ($row in $result -split "`n")
					{
						$databaseName = $row.Trim()
						if ($databaseName -eq $systemDatabase)
						{
							Debug "$DBType Connection on $OSname successful, Moving Forward"
							return
						}
					}
					
					if ($existingDatabases -notcontains $systemDatabase)
					{
						Debug "System database Test Failed."
						Exit
					}
				}
				catch
				{
					Debug "Connection to MySQL on $OSname failed: $($Error[0])"
					Exit
				}
			}
		}
		catch
		{
			Debug "MySQL Connection failed: $($Error[0])"
			Exit
		}
	}
	elseif ($DBType -match "MSSQL")
	{
		$CredPassword = ConvertTo-SecureString $Password -AsPlainText -Force
		$Credential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $Username, $CredPassword
		$systemDatabase = "master"
		$query = "SELECT name FROM sys.databases;"
		try
		{
			if ($OSname -eq "Windows")
			{
				try
				{
					$result = Invoke-Sqlcmd -ServerInstance $SQLInstance -Credential $Credential -Database $systemDatabase -Query $query -TrustServerCertificate -ErrorAction Stop
					
					foreach ($row in $result)
					{
						$databaseName = $row.name
						if ($databaseName -eq $systemDatabase)
						{
							Debug "$DBType Connection on $OSname successful, Moving Forward"
							return
						}
					}
					
					if ($existingDatabases -notcontains $systemDatabase)
					{
						Debug "System database Test Failed."
						Exit
					}
				}
				catch
				{
					Debug "Connection to MSSQL on $OSname failed: $($Error[0])"
					Exit
				}
				
			}
			elseif ($OSname -eq "Linux" -or $OSname -eq "macOS")
			{
				try
				{
					$result = Invoke-Sqlcmd -ServerInstance $SQLInstance -Credential $Credential -Database $systemDatabase -Query $query -TrustServerCertificate -ErrorAction Stop
					
					foreach ($row in $result)
					{
						$databaseName = $row.name
						if ($databaseName -eq $systemDatabase)
						{
							Debug "$DBType Connection on $OSname successful, Moving Forward"
							return
						}
					}
					
					if ($existingDatabases -notcontains $systemDatabase)
					{
						Debug "System database Test Failed."
						Exit
					}
				}
				catch
				{
					Debug "Connection to MSSQL on $OSname failed: $($Error[0])"
					Exit
				}
			}
		}
		catch
		{
			Debug "MSSQL Connection failed: $($Error[0])"
			Exit
		}
	}
	else
	{
		Debug "CREDENTIAL FAULT $($Error[0])"
		return
	}
}

## function to GET MYSQL Boot Time 
function Get-MySQLBootTime
{
	param (
		[Parameter(Mandatory = $true)]
		[string]$SQLExePath # Add this parameter for the SQL executable path
	)
	
	#mariadb
	$query1 = "SELECT NOW() - INTERVAL variable_value SECOND AS 'MySQL started on' FROM information_schema.global_status WHERE variable_name='Uptime';"
	#mysql
	$query2 = "SELECT NOW() - INTERVAL variable_value SECOND AS MySQL_Started FROM performance_schema.global_status WHERE variable_name='Uptime';"
	
	try
	{
		$commandOutput1 = & $SQLExePath --defaults-extra-file="$MySQLConfFile" -e $query1 2>$null
		if ([string]::IsNullOrWhiteSpace($commandOutput1)) {
			$commandOutput2 = & $SQLExePath --defaults-extra-file="$MySQLConfFile" -e $query2 2>$null
			if ([string]::IsNullOrWhiteSpace($commandOutput2)) {
				throw "Both queries returned null or empty result."
			}
			else {
				$startTimeString = [regex]::Match($commandOutput2, '\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}').Value
				$startTime = [DateTime]::ParseExact($startTimeString, "yyyy-MM-dd HH:mm:ss", $null)
				$MySQLBootTime = $startTime.ToString("yyyy-MM-dd HH:mm:ss")
				return $MySQLBootTime
			}
		}
		else {
			$startTimeString = [regex]::Match($commandOutput1, '\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}').Value
			$startTime = [DateTime]::ParseExact($startTimeString, "yyyy-MM-dd HH:mm:ss", $null)
			$MySQLBootTime = $startTime.ToString("yyyy-MM-dd HH:mm:ss")
			return $MySQLBootTime
		}
	}
	catch
	{
		Debug "Failed to retrieve MySQL start time:", $_.Exception.Message
		return
	}
}

## function to GET MSSQL Boot Time 
function Get-MSSQLBootTime
{
	# Define the SQL query
	$query = "SELECT sqlserver_start_time FROM sys.dm_os_sys_info;"
	
	try
	{
		# Execute the SQL query using Invoke-Sqlcmd
		$startTime = Invoke-Sqlcmd -ServerInstance $IPv4 -Username $Username -Password $Password -Query $query -Database "master" -TrustServerCertificate -ErrorAction Sto
		$MSSQLBootTime = Get-Date $startTime.sqlserver_start_time -Format "yyyy-MM-dd HH:mm:ss"
		# Return the formatted start time
		return $MSSQLBootTime
	}
	catch
	{
		Debug "Failed to retrieve SQL Server start time: $_"
		return $null
	}
}


## function To Get SQL Details Required by Script Service Name, Path to Exe and Boot time
function Set-SQLDetails
{
	param (
		[Parameter(Mandatory = $true)]
		[string]$MyOS,
		[string]$DBType
	)
	
	$os = $MyOS
	switch ($os)
	{
		"Windows" {
			try
			{
				if ($DBType -match "MySQL")
				{
					try
					{
						$SQLService = Get-CimInstance -Class Win32_Service | Where-Object { $_.Name -match '^mysql\d*' -and $_.PathName -match 'mysqld.exe' -or ($_.Name -match '^mariadb\d*' -and $_.PathName -match 'mysqld.exe') } | Select-Object -Skip 1 -First 1 ## To select second in list Select-Object -Skip 1 -First 1, To select ther 3rd Select-Object -Skip 2 -First 1 and so on
						$MySQLPath = Split-Path -Path ($SQLService.PathName.Split('"')[1]) -Parent
						#Debug "Display Name: $($SQLService.DisplayName)"
						
						if ($SQLService)
						{
							$SQLServiceName = $SQLService.Name
							DBServiceCheck $SQLServiceName ## Check Service if running or not
							Test-MySQLCnf ## Check for MySQL cnf File
							$MySQLExe = Join-Path -Path $MySQLPath -ChildPath "mysql.exe"
							$MySQLDumpExe = Join-Path -Path $MySQLPath -ChildPath "mysqldump.exe"
							Test-DBCon -MyOS $MyOS -DBType $DBType
							$SQLBootTime = Get-MySQLBootTime -SQLExePath $MySQLExe
							$sqlResult = @{
								ServiceName  = $SQLServiceName
								MySQLExe	 = $MySQLExe
								MySQLDumpExe = $MySQLDumpExe
								SQLBootTime  = $SQLBootTime
							}
							return $sqlResult
						}
						else
						{
							Debug "$($DBType) Database service on $($os) not found."
							Exit 1
						}
					}
					catch
					{
						Debug "Error processing MySQL Database service on $($os): $($_.Exception.Message)"
						exit 1
					}
				}
				elseif ($DBType -match "MSSQL")
				{
					try
					{
						$SQLService = Get-CimInstance -Class Win32_Service | Where-Object { ($_.DisplayName -like "MSSQL$*" -or $_.DisplayName -like "MSSQLSERVER" -or $_.DisplayName -like "SQL Server (*") } | Select-Object Name, DisplayName, @{ Name = "Path"; Expression = { $_.PathName.Split('"')[1] } }
						#$MSSQLPath = Split-Path -Path $SQLService.Path -Parent
						
						if ($SQLService)
						{
							$SQLServiceName = $SQLService.Name
							DBServiceCheck $SQLServiceName ## Check Service if running or not
							Test-DBCon -MyOS $MyOS -DBType $DBType
							$SQLBootTime = Get-MSSQLBootTime
							$sqlResult = @{
								ServiceName = $SQLServiceName
								SQLBootTime = $SQLBootTime
							}
							return $sqlResult
						}
						else
						{
							Debug "$($DBType) Database service on $($os) not found."
							Exit 1
						}
					}
					catch
					{
						Debug "Error processing MSSQL Database service on $($os): $($_.Exception.Message)"
						Exit 1
					}
				}
				else
				{
					Debug "Invalid DBType specified: $DBType"
					Exit
				}
				
			}
			catch
			{
				Debug "Error processing Windows case: $($_.Exception.Message)"
				return
			}
		}
		"Linux" {
			try
			{
				if ($DBType -match "MySQL")
				{
					try
					{
						#$SQLService = systemctl list-units --type=service --all | grep 'mysql*' | awk '{print $1}'
						$SQLService = systemctl list-units --type=service --all | grep -E 'mysql*|maria*' | awk '{print $1}'
						
						if ($SQLService)
						{
							$SQLServiceName = $SQLService
							DBServiceCheck $SQLServiceName ## Check Service if running or not
							Test-MySQLCnf ## Check for MySQL cnf File
							$MySQLExe = $(which mysql)
							$MySQLDumpExe = $(which mysqldump)
							Test-DBCon -MyOS $MyOS -DBType $DBType
							$SQLBootTime = Get-MySQLBootTime -SQLExePath $MySQLExe
							
							$sqlResult = @{
								ServiceName  = $SQLServiceName
								MySQLExe	 = $MySQLExe
								MySQLDumpExe = $MySQLDumpExe
								SQLBootTime  = $SQLBootTime
							}
							return $sqlResult
						}
						else
						{
							Debug "$($DBType) Database service on $($os) not found."
							Exit 1
						}
					}
					catch
					{
						Debug "Error processing MySQL Database service on $($os): $($_.Exception.Message)"
						Exit 1
					}
				}
				elseif ($DBType -match "MSSQL")
				{
					try
					{
						$SQLService = systemctl list-units --type=service --all | grep 'mssql*' | awk '{print $1}'
						
						if ($SQLService)
						{
							$SQLServiceName = $SQLService
							DBServiceCheck $SQLServiceName ## Check Service if running or not
							Test-DBCon -MyOS $MyOS -DBType $DBType
							$SQLBootTime = Get-MSSQLBootTime
							$sqlResult = @{
								ServiceName = $SQLServiceName
								SQLBootTime = $SQLBootTime
							}
							return $sqlResult
						}
						else
						{
							Debug "$($DBType) Database service on $($os) not found."
							Exit 1
						}
					}
					catch
					{
						Debug "Error processing MSSQL Database service on $($os): $($_.Exception.Message)"
						Exit 1
					}
				}
				else
				{
					Debug "Invalid DBType specified: $DBType"
					Exit
				}
			}
			catch
			{
				Debug "Error processing Linux case: $($_.Exception.Message)"
				return
			}
		}
	}
}

<#  Backup database function  #>
function BackupDatabases
{
	$Error.Clear()
	$BeginBackup = Get-Date
	If ($DBType -match "MySQL")
	{
		#$MySQLDumpPass = "-p$Password"
		$retrymax = 3
		$retrycount = 0
		$dumpSuccess = $false
		Debug "------------------------------------------------------------------------"
		Debug "Begin backing up $DBType Database"
		Debug " "
		$DBListToDump = @()
		while (-not $dumpSuccess -and $retrycount -lt $retrymax)
		{
			$retrycount++
			Try
			{
				If ($BackupAllDB)
				{
					$DBNameslist = $SQLDbList -split ',' | ForEach-Object { $_.Trim() }
					Debug "Specified List of DB to Process : [ $($DBNameslist -join ',') ]"
				}
				Else
				{
					$DBNameslist = ($SQLDbList -split ',')[0].Trim()
					Debug "Single DB Specified Named : $($DBNameslist)"
				}
				Debug "------------------------------------------------------------------------"
				$query = "SHOW DATABASES;"
				# Define the command to execute using mysql.exe
				$mysqlCommand = & $MySQLExe --defaults-extra-file="$MySQLConfFile" -e $query | ForEach-Object { $_.Trim() }
				#$mysqlCommand = & $MySQLExe -u $Username $MySQLDumpPass -e $query | ForEach-Object { $_.Trim() }
				# Execute the command and capture the output
				$result = $mysqlCommand
				# Initialize an empty array to store existing database names
				$existingDatabases = @()
				
				# Iterate through each line in the result
				foreach ($line in $result -split "`n")
				{
					$databaseName = $line.Trim()
					if ($databaseName -ne "Database")
					{
						$existingDatabases += $databaseName
					}
				}
				
				# Initialize empty arrays
				$databasesWithWildcard = @()
				$foundDatabases = @()
				$nonexistDB = @()
				
				# Iterate through each database name in the provided list
				foreach ($DBName in $DBNameslist.Split(','))
				{
					if ($DBName -like "*%*")
					{
						$foundMatch = $false
						foreach ($existingDB in $existingDatabases)
						{
							$pattern = "^" + ($DBName -replace '%', '.*') + "$"
							if ($existingDB -match $pattern)
							{
								Debug "Found Database with name : `"$existingDB`" for wildcard `"$DBName`""
								$databasesWithWildcard += $existingDB
								$foundMatch = $true
							}
						}
						if (-not $foundMatch)
						{
							$nonexistDB += $DBName
							Debug "No matching db wildcard  : `"$DBName`""
						}
					}
					else
					{
						if ($existingDatabases -contains $DBName)
						{
							Debug "Found Database with name : `"$DBName`""
							$foundDatabases += $DBName
						}
						else
						{
							Debug "Skipping non-existent db : `"$DBName`""
							$nonexistDB += $DBName
						}
					}
				}
				Debug " "
				
				$databasesWithWildcardstring = $databasesWithWildcard -join ","
				if ($databasesWithWildcard -ne $NULL)
				{
					Debug "List of databases with wildcard : $databasesWithWildcardstring"
					Debug " "
				}
				
				$foundDatabasesstring = $foundDatabases -join ","
				if ($foundDatabases -ne $NULL)
				{
					Debug "List of databases without wildcard : $foundDatabasesstring"
					Debug " "
				}
				
				$nonexistDBstring = $nonexistDB -join ","
				if ($nonexistDB -ne $NULL)
				{
					Debug "List of non Existant databases : $nonexistDBstring"
					Debug " "
				}
				
				$allFoundDatabases = $foundDatabases + $databasesWithWildcard
				
				if (-not $allFoundDatabases)
				{
					Debug "No database found in the list"
					return
				}
				
				$DBListToDump = $allFoundDatabases
				$DBListToDumpstring = $DBListToDump -join ', '
				Debug "------------------------------------------------------------------------"
				Debug "Final List of DB to Backup : $DBListToDumpstring"
				
				foreach ($DBName in $DBListToDump)
				{
					$DoBackupDB++
					$BeginDBtime = Get-Date
					Debug "------------------------------------------------------------------------"
					Debug "Creating Dump for database: `"$($DBName)`""
					$MySQLDumpFile = Join-Path -Path $BackupTempDir -ChildPath "$($DBName)_$((Get-Date).ToString('yyyy-MM-dd')).sql"
					Debug "At Path $($MySQLDumpFile)"
					$MySQLDumpCommand = "& '$MySQLDumpExe' --defaults-extra-file='$MySQLConfFile' --log-error='$SQLDumpLog' $DBName --result-file='$MySQLDumpFile' --default-character-set=utf8"
					#$MySQLDumpCommand = "& '$MySQLDumpExe' -u $Username $MySQLDumpPass --log-error='$SQLDumpLog' $DBName --result-file='$MySQLDumpFile'"
					Invoke-Expression -Command $MySQLDumpCommand
					
					# Check the return code of mysqldump and report accordingly
					$exitCode = $LastExitCode
					switch ($exitCode)
					{
						0 {
							Debug "Dump for `"$($DBName)`" finished in $(ElapsedTime $BeginDBtime)"
							Email "[OK] Dump for Database: `"$($DBName)`""
						}
						1 {
							Debug "mysqldump for `"$($DBName)`" EX_USAGE 1 <-- command syntax issue"
							Email "[ERROR] Dump for Database: `"$($DBName)`" : Command syntax issue"
							throw "Command syntax issue with mysqldump"
						}
						2 {
							Debug "mysqldump for `"$($DBName)`" EX_MYSQLERR 2 <-- privilege problem or other issue completing the command"
							Email "[ERROR] Dump for Database: `"$($DBName)`" : Privilege problem or other issue"
							throw "Privilege problem or other issue completing the command with mysqldump"
						}
						3 {
							Debug "mysqldump for `"$($DBName)`" EX_CONSCHECK 3 <-- consistency check problem"
							Email "[ERROR] Dump for Database: `"$($DBName)`" : Consistency check problem"
							throw "Consistency check problem with mysqldump"
						}
						4 {
							Debug "mysqldump for `"$($DBName)`" EX_EOM 4 <-- End of Memory"
							Email "[ERROR] Dump for Database: `"$($DBName)`" : End of Memory"
							throw "End of Memory with mysqldump"
						}
						5 {
							Debug "mysqldump for `"$($DBName)`" EX_EOF 5 <-- Result file problem writing to file, space issue?"
							Email "[ERROR] Dump for Database: `"$($DBName)`" : Result file problem writing to file, space issue?"
							throw "Result file problem writing to file, space issue with mysqldump"
						}
						6 {
							Debug "mysqldump for `"$($DBName)`" EX_ILLEGAL_TABLE 6"
							Email "[ERROR] Dump for Database: `"$($DBName)`" : Illegal table"
							throw "Illegal table with mysqldump"
						}
						default {
							Debug "Backup for `"$($DBName)`" presumed failed Unknown exit code `"$exitCode`" from mysqldump"
							Email "[ERROR] Dump for Database: `"$($DBName)`" : Unknown exit code `"$exitCode`" from mysqldump"
							throw "Unknown exit code $exitCode from mysqldump"
						}
					}
					#Debug "Wait a few seconds to make sure Dump is finished"
					Start-Sleep -Seconds 3
					$BackupSuccess++
					$dumpSuccess = $true
				}
				Debug "------------------------------------------------------------------------"
				Debug "Backing up MySQL Database finished in $(ElapsedTime $BeginBackup)"
				Debug "------------------------------------------------------------------------"
			}
			Catch
			{
				Debug "[ERROR] MySQL Dump : $($Error[0])"
				Email "[ERROR] MySQL Dump : Check Debug Log"
				if ($retrycount -lt $retrymax)
				{
					Debug "Retry attempt $retrycount failed. Retrying..."
					Debug "------------------------------------------------------------------------"
				}
				else
				{
					Debug "Critical Error: Retry attempts exhausted. Exiting script."
					Email "Critical Error: Retry attempts exhausted. Exiting script."
					Exit
				}
			}
		}
	}
	elseif ($DBType -match "MSSQL")
	{
		## MSSQL Database
		$retrymax = 3
		$retrycount = 0
		$dumpSuccess = $false
		$CredPassword = ConvertTo-SecureString $Password -AsPlainText -Force
		$Credential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $Username, $CredPassword
		Debug "------------------------------------------------------------------------"
		Debug "Begin backing up $DBType Database"
		Debug " "
		while (-not $dumpSuccess -and $retrycount -lt $retrymax)
		{
			$retrycount++
			Try
			{
				if ($BackupAllDB)
				{
					$DBNameslist = $SQLDbList -split ',' | ForEach-Object { $_.Trim() }
					Debug "Specified List of DB to Process : [ $($DBNameslist -join ',') ]"
				}
				else
				{
					$DBNameslist = ($SQLDbList -split ',')[0].Trim()
					Debug "Single DB Specified Named : $($DBNameslist)"
				}
				Debug "------------------------------------------------------------------------"
				$query = "SELECT name FROM sys.databases;"
				$result = Invoke-Sqlcmd -ServerInstance $SQLInstance -Credential $Credential -Database "master" -Query $query -TrustServerCertificate -ErrorAction Stop
				
				# Initialize an empty array to store existing database names
				$existingDatabases = @()
				
				# Iterate through each row in the result
				foreach ($row in $result)
				{
					$databaseName = $row.name
					$existingDatabases += $databaseName
				}
				
				# Initialize empty arrays
				$databasesWithWildcard = @()
				$foundDatabases = @()
				$nonexistDB = @()
				
				# Iterate through each database name in the provided list
				foreach ($DBName in $DBNameslist.Split(','))
				{
					if ($DBName -like "*%*")
					{
						$foundMatch = $false
						foreach ($existingDB in $existingDatabases)
						{
							$pattern = "^" + ($DBName -replace '%', '.*') + "$"
							if ($existingDB -match $pattern)
							{
								Debug "Found Database with name : `"$existingDB`" for wildcard `"$DBName`""
								$databasesWithWildcard += $existingDB
								$foundMatch = $true
							}
						}
						if (-not $foundMatch)
						{
							$nonexistDB += $DBName
							Debug "No matching db wildcard  : `"$DBName`""
						}
					}
					else
					{
						if ($existingDatabases -contains $DBName)
						{
							Debug "Found Database with name : `"$DBName`""
							$foundDatabases += $DBName
						}
						else
						{
							$nonexistDB += $DBName
							Debug "Skipping non-existent db : `"$DBName`""
						}
					}
				}
				
				Debug " "
				
				$databasesWithWildcardstring = $databasesWithWildcard -join ","
				if ($databasesWithWildcard -ne $NULL)
				{
					Debug "List of databases with wildcard : $databasesWithWildcardstring"
					Debug " "
				}
				
				$foundDatabasesstring = $foundDatabases -join ","
				if ($foundDatabases -ne $NULL)
				{
					Debug "List of databases without wildcard : $foundDatabasesstring"
					Debug " "
				}
				
				$nonexistDBstring = $nonexistDB -join ","
				if ($nonexistDB -ne $NULL)
				{
					Debug "List of non Existant databases : $nonexistDBstring"
					Debug " "
				}
				
				# Merge found databases with wildcard databases
				$allFoundDatabases = $foundDatabases + $databasesWithWildcard
				
				# Check if $allFoundDatabases is empty
				if (-not $allFoundDatabases)
				{
					Debug "No database found in the list"
					return
				}
				
				# Output the list of databases with wildcard characters for debugging purposes
				$DBListToDump = $allFoundDatabases
				$DBListToDumpstring = $DBListToDump -join ', '
				Debug "------------------------------------------------------------------------"
				Debug "Final List of DB to Backup : $DBListToDumpstring"
				
				foreach ($DBName in $DBListToDump)
				{
					$DBName = $DBName.Trim()
					$query = "SELECT state_desc FROM sys.databases WHERE name = '$DBName';"
					$state = Invoke-Sqlcmd -ServerInstance $SQLInstance -Credential $Credential -Database "master" -Query $query -TrustServerCertificate -ErrorAction SilentlyContinue
					if ($state -and $state.state_desc -eq "ONLINE")
					{
						$query = "SELECT compatibility_level FROM sys.databases WHERE name = '$DBName';"
						$complevel = Invoke-Sqlcmd -ServerInstance $SQLInstance -Credential $Credential -Database "master" -Query $query -TrustServerCertificate -ErrorAction SilentlyContinue
						if ($complevel)
						{
							$complevel = $complevel.compatibility_level
						}
						else
						{
							$complevel = "NaN"
						}
						$DoBackupDB++
						$BeginDBtime = Get-Date
						Debug "------------------------------------------------------------------------"
						Debug "Creating Dump for database: `"$($DBName)`" Status: $($state.state_desc)"
						$MsSQLDumpFile = "$BackupTempDir$DS$($DBName)-lvl-$complevel`_$((Get-Date).ToString('yyyy-MM-dd')).bak"
						Backup-SqlDatabase -ServerInstance $SQLInstance -Credential $Credential -Database $DBName -BackupFile $MsSQLDumpFile -Checksum -ErrorAction Stop
						Debug "Backup Done At Path: $($MsSQLDumpFile) in $(ElapsedTime $BeginDBtime)"
								<# 
								#INJECT DELAY TO MANIPULATE BACKUP FILE TO TEST IF VERIFICATION WORKS
								Debug "DEBUG: Backup Done sleeping"
								Start-Sleep -Seconds 120		## 2 minutes Delay
								Debug "DEBUG: Moving forward to verify"
								#INJECT DELAY TO MANIPULATE BACKUP FILE TO TEST IF VERIFICATION WORKS
								#>
						# Verify backup
						If ($null -ne $MsSQLDumpFile)
						{
							$BeginVerify = Get-Date
							Debug "Testing Backup File: $($MsSQLDumpFile)"
							$query = "RESTORE VERIFYONLY FROM DISK = '$($MsSQLDumpFile)' WITH CHECKSUM"
							$Verbose = $($Verbose = Invoke-Sqlcmd -ServerInstance $SQLInstance -Credential $Credential -Database $DBName -Query $query -TrustServerCertificate -QueryTimeout 0 -Verbose) 4>&1
							If ($Verbose -like '*The backup set on file 1 is valid*')
							{
								Debug "SUCCESS: Latest Backup Verification for `"$($DBName)`" database on $($SQLInstance) is Valid."
								Debug "Verification finished in $(ElapsedTime $BeginVerify)"
								Email "[OK] Dump for Database: `"$($DBName)`""
								$BackupSuccess++
								$dumpSuccess = $true
								Continue
							}
							else
							{
								Debug "FAILED: Latest Backup for `"$($DBName)`" database on $($SQLInstance), Verification Finished in $(ElapsedTime $BeginVerify)"
								Email "[ALERT] There was a problem with Dump for `"$($DBName)`", Discarded"
								# Delete the failed backup file and try backup one more time
								Remove-Item $MsSQLDumpFile
								Debug "Deleted failed backup file $($MsSQLDumpFile), Retrying"
								
								# Retry backup process
								$BeginDBtime = Get-Date
								Backup-SqlDatabase -ServerInstance $SQLInstance -Credential $Credential -Database $DBName -BackupFile $MsSQLDumpFile -Checksum -ErrorAction Stop
								Debug "Fresh Backup Done Re verifying"
								If (Test-Path $MsSQLDumpFile)
								{
									# Verify the backup again
									$BeginVerify = Get-Date
									$Verbose = $($Verbose = Invoke-Sqlcmd -ServerInstance $SQLInstance -Username $Username -Password $Password -Database $DBName -Query $query -TrustServerCertificate -QueryTimeout 0 -Verbose) 4>&1
									If ($Verbose -like '*The backup set on file 1 is valid*')
									{
										Debug "SUCCESS: Latest Backup Verification for `"$($DBName)`" database on $($SQLInstance) is Valid."
										Debug "Verification finished in $(ElapsedTime $BeginVerify)"
										Email "[OK] Dump for Database: `"$($DBName)`""
										$BackupSuccess++
										$dumpSuccess = $true
										Continue
									}
									else
									{
										Debug "FAILED: Latest Backup for `"$($DBName)`" database on $($SQLInstance) after retry. Finished in $(ElapsedTime $BeginDBtime)"
										Email "[ERROR] Dump for Database: `"$($DBName)`", Try: 1"
										# Continue with the next database
										Continue
									}
								}
								else
								{
									Debug "FAILED: Backup for `"$($DBName)`" database on `"$($SQLInstance)`" after retry."
									Email "[ERROR] Dump for `"$($DBName)`" after Retry, Discarding"
									# Continue with the next database
									Continue
								}
							}
						}
						else
						{
							# Backups are not being performed, Just in Case
							Debug "No backups available for $($DBName) database on $($SQLInstance)"
							# Continue with the next database
							Continue
						}
					}
					else
					{
						# If the database is OFFLINE, skip it and continue with the next one
						Debug "------------------------------------------------------------------------"
						Debug "Skipping OFFLINE database: `"$($DBName)`""
						Debug "------------------------------------------------------------------------"
						Email "[ALERT] Skipping OFFLINE database: `"$($DBName)`""
						# Continue with the next database
						continue
					}
				}
				
				Debug "------------------------------------------------------------------------"
				Debug "Backing up All MSSQL Database finished in $(ElapsedTime $BeginBackup)"
				Debug "------------------------------------------------------------------------"
			}
			Catch
			{
				Debug "[ERROR] MSSQL Dump : $($Error[0])"
				Email "[ERROR] MSSQL Dump : Check Debug Log"
				if ($retrycount -lt $retrymax)
				{
					Debug "Retry attempt $retrycount failed. Retrying..."
					Debug "------------------------------------------------------------------------"
				}
				else
				{
					Debug "Critical Error: Retry attempts exhausted. Exiting script."
					Email "Critical Error: Retry attempts exhausted. Exiting script."
					Exit
				}
			}
		}
	}
	else
	{
		Debug "Backup Database FAULT"
		exit
	}
}

<## function To Archive or move the backup files to Backup Location ##>
function MakeArchive
{
	Email "--------------------"
	$Error.Clear()
	$os = $OSname
	$StartFunction = Get-Date
	Debug "------------------------------------------------------------------------"
	Debug "Switch to Zip is     : $UseSevenZip"
	
	$VolumeSwitch = "-v$VolumeSize"
	$PWSwitch = "-p$ArchivePassword"
	switch ($os)
	{
		"Windows" {
			Try
			{
				if ($UseSevenZip)
				{
					Debug "Multi Volume Archive : $MultiVolume"
					Debug "Archiving SQL Dumps to Backup Location"
					if ($PassProtected)
					{
						Debug "Backup Location: $($BackupPath)"
						Debug "Creating Password Protected Archives"
						Debug "------------------------------------------------------------------------"
					}
					else
					{
						Debug "Backup Location: $($BackupPath)"
						Debug "Creating Archives without Password Protection"
						Debug "------------------------------------------------------------------------"
					}
					
					foreach ($file in (Get-ChildItem $BackupTempDir))
					{
						$DoArchive++
						$StartArchive = Get-Date
						Debug "Creating archive for Dump: $($file.BaseName)"
						Debug "------------------------------------------------------------------------"
						$archiveName = Join-Path -Path $BackupPath -ChildPath "$($file.BaseName).7z"
						Debug "Archive Name: $($archiveName)"
						# Check if the file exists and remove it if it does
						if (Test-Path $archiveName)
						{
							Remove-Item -Path $archiveName -Force
						}
						Debug "File to zip: $($file.FullName)"
						
						if ($MultiVolume)
						{
							if ($PassProtected)
							{
								$SevenZipCommand = & cmd /c $SevenZipA a $VolumeSwitch -t7z -m0=lzma2 -mx=9 -mfb=64 -md=32m -ms=on -mhe=on $PWSwitch $archiveName $file.FullName | Out-String
							}
							else
							{
								$SevenZipCommand = & cmd /c $SevenZipA a $VolumeSwitch -t7z -m0=lzma2 -mx=9 -mfb=64 -md=32m -ms=on -mhe=on $archiveName $file.FullName | Out-String
							}
						}
						else
						{
							if ($PassProtected)
							{
								$SevenZipCommand = & cmd /c $SevenZipA a -t7z -m0=lzma2 -mx=9 -mfb=64 -md=32m -ms=on -mhe=on $PWSwitch $archiveName $file.FullName | Out-String
							}
							else
							{
								$SevenZipCommand = & cmd /c $SevenZipA a -t7z -m0=lzma2 -mx=9 -mfb=64 -md=32m -ms=on -mhe=on $archiveName $file.FullName | Out-String
								
							}
						}
						#Debug $SevenZipCommand # This code outputs all operation for Debug
						Debug "Archive creation for Dump `"$($file.Name)`" finished in $(ElapsedTime $StartArchive)"
						#Debug "Wait a few seconds to make sure archive is finished" 
						Start-Sleep -Seconds 3
						Debug "Deleting Sql Dump `"$($file.Name)`""
						Remove-Item -Path $file.FullName
						Debug "------------------------------------------------------------------------"
						Email "[OK] Archive: `"$([System.IO.Path]::GetFileName($archiveName))`""
						$BackupSuccess++
					}
					
				}
				else
				{
					# If makearchive switch is false
					Debug "Moving SQL Dumps to Backup Location"
					Debug "Backup Location: $($BackupPath)"
					Debug "------------------------------------------------------------------------"
					foreach ($file in (Get-ChildItem $BackupTempDir))
					{
						$DoMove++
						$SourcePath = $BackupTempDir
						$DestinationPath = $BackupPath
						$RoboCopy = & robocopy $SourcePath $DestinationPath /MOV /R:3 /W:2 | Out-String
						# TODO Check if the file was successfully moved
						Debug "[OK] Moved: `"$($file.Name)`""
						Email "[OK] Moved: `"$($file.Name)`""
						# Extract and print summary
						$header = ($RoboCopy.Trim() -split [Environment]::NewLine)[0 .. 12] -join [Environment]::NewLine
						$summary = ($RoboCopy.Trim() -split [Environment]::NewLine)[-12 .. -1] -join [Environment]::NewLine
						$RoboStats = $RoboCopy.Split([Environment]::NewLine) | Where-Object { $_ -match 'Files\s:\s+\d' }
						$RoboStats | ConvertFrom-String -Delimiter "\s+" -PropertyNames Nothing, Files, Colon, Total, Copied, Skipped, Mismatch, Failed, Extras | ForEach-Object {
							$Copied = $_.Copied
							$Mismatch = $_.Mismatch
							$Failed = $_.Failed
							$Extras = $_.Extras
						}
						If (($Mismatch -gt 0) -or ($Failed -gt 0))
						{
							Throw "Robocopy MISMATCH or FAILED exists"
						}
						$BackupSuccess++
					}
					
					Debug ([Environment]::NewLine + [Environment]::NewLine + $header + [Environment]::NewLine + $summary + [Environment]::NewLine)
					Debug "------------------------------------------------------------------------"
					Debug "Robocopy backup success: $Extras moved, $Mismatch mismatched, $Failed failed"
					Debug "------------------------------------------------------------------------"
				}
				
				Debug "Function Archive FINISHED in $(ElapsedTime $StartFunction)"
				Debug "------------------------------------------------------------------------"
			}
			Catch
			{
				Debug "[ERROR] Archive Creation : $($Error[0])"
				Email "[ERROR] Archive Creation : $($file.BaseName) Check Debug Log"
				Email "[ERROR] Archive Creation : $($Error[0])"
				EmailResults
				Exit
			}
		}
		"Linux" {
			Try
			{
				if ($UseSevenZip)
				{
					$SevenZipA = $(which 7za)
					Debug "7zip Path: $SevenZipA"
					Debug "Archiving SQL Dumps to Backup Location"
					if ($PassProtected)
					{
						Debug "Backup Location: $($BackupPath)"
						Debug "Creating Password Protected Archives"
						Debug "------------------------------------------------------------------------"
					}
					else
					{
						Debug "Backup Location: $($BackupPath)"
						Debug "Creating Archives without Password Protection"
						Debug "------------------------------------------------------------------------"
					}
					
					foreach ($file in (Get-ChildItem $BackupTempDir))
					{
						$DoArchive++
						$StartArchive = Get-Date
						Debug "Creating archive for Dump: $($file.BaseName)"
						Debug "------------------------------------------------------------------------"
						$archiveName = Join-Path -Path $BackupPath -ChildPath "$($file.BaseName).7z"
						Debug "Archive Name: $($archiveName)"
						# Check if the file exists and remove it if it does
						if (Test-Path $archiveName)
						{
							Remove-Item -Path $archiveName -Force
						}
						Debug "File to zip: $($file.FullName)"
						
						if ($MultiVolume)
						{
							if ($PassProtected)
							{
								$SevenZipCommand = & $SevenZipA a $VolumeSwitch -t7z -m0=lzma2 -mx=9 -mfb=64 -md=32m -ms=on -mhe=on $PWSwitch $archiveName $file.FullName | Out-String
							}
							else
							{
								$SevenZipCommand = & $SevenZipA a $VolumeSwitch -t7z -m0=lzma2 -mx=9 -mfb=64 -md=32m -ms=on -mhe=on $archiveName $file.FullName | Out-String
							}
						}
						else
						{
							if ($PassProtected)
							{
								$SevenZipCommand = & $SevenZipA a -t7z -m0=lzma2 -mx=9 -mfb=64 -md=32m -ms=on -mhe=on $PWSwitch $archiveName $file.FullName | Out-String
							}
							else
							{
								$SevenZipCommand = & $SevenZipA a -t7z -m0=lzma2 -mx=9 -mfb=64 -md=32m -ms=on -mhe=on $archiveName $file.FullName | Out-String
							}
						}
						#Debug $SevenZipCommand # This code outputs all operation for Debug
						Debug "Archive creation for Dump `"$($file.Name)`" finished in $(ElapsedTime $StartArchive)"
						#Debug "Wait a few seconds to make sure archive is finished" 
						Start-Sleep -Seconds 3
						Debug "Deleting Sql Dump `"$($file.Name)`""
						Remove-Item -Path $file.FullName
						Debug "------------------------------------------------------------------------"
						Email "[OK] Archive: `"$([System.IO.Path]::GetFileName($archiveName))`""
						$BackupSuccess++
					}
				}
				else
				{
					<#
					Debug "DEBUG: Inject Delay"
					Start-Sleep -Seconds 60		## 1 minutes Delay
					Debug "DEBUG: Inject End"
					#>
					## If makearchive switch is false then Move Files
					Debug "Moving SQL Dumps to Backup Location"
					Debug "Backup Location: $($BackupPath)"
					Debug "------------------------------------------------------------------------"
					$Source = $BackupTempDir
					$Destination = $BackupPath
					$totalSourceFiles = 0
					$totalSourceFolders = 0
					$errorLog = "$PSScriptRoot$DSrsync_error.log"
					$Listoffiles = Get-ChildItem -Path "$Source"
					# Count total number of files and folders in the source directory before rsync
					$totalSourceFiles = (find $source/* -type f | wc -l) # Count total files
					$totalSourceFolders = (find $Source/* -type d | wc -l) # Count total directories
					
					# List files with numbering
					if ($totalSourceFiles -gt 0)
					{
						Debug "Total Source files: $totalSourceFiles"
						$fileList = find $Source/* -type f -printf "%T@ %p\n" | sort -n | foreach { $_ -replace "^\d+.\d+\s", "" } ## sort and foreach are linux commands here
						Debug "List of files:"
						$fileList | ForEach-Object -Begin { $counter = 1 } -Process {
							Debug "$counter. $_"
							$counter++
						}
					}
					
					# List folders with numbering
					if ($totalSourceFolders -gt 0)
					{
						Debug "---------------------------------"
						Debug "Total Source folders: $totalSourceFolders"
						$folderList = find $Source/* -type d -printf "%T@ %p\n" | sort -n | foreach { $_ -replace "^\d+.\d+\s", "" } ## sort and foreach are linux commands here
						Debug "List of folders:"
						$folderList | ForEach-Object -Begin { $counter = 1 } -Process {
							Debug "$counter. $_"
							$counter++
						}
						Debug "---------------------------------"
					}
					
					Debug "---------------------------------"
					
					# Initialize variables and arrays
					$totalFiles = 0
					$successfulfiles = 0
					$successfulfolders = 0
					$failedFiles = 0
					$deletedFiles = 0
					$files = @()
					$folders = @()
					$deletedFiles = @()
					$failedFilesList = @()
					
					# Loop through each file in the backup location
					foreach ($file in $Listoffiles)
					{
						# Execute rsync command and capture output and errors
						$rsyncOutput = & rsync -avi --remove-source-files --partial --append-verify --out-format="%i %o %n" "$file" "$Destination" 2> $errorLog
						
						if ($LASTEXITCODE -eq 0)
						{
							foreach ($line in $rsyncOutput)
							{
								$line = $line.Trim() # Trim extra spaces
								#Debug "Processing line: $line"
								if ($line -match '^\*deleting\s+del\. (.+)$')
								{
									$DoMove++
									# Deletion line
									Debug "Matched deletion line: $line"
									$totalFiles++
									$deletedFiles += $matches[1]
									$BackupSuccess++
								}
								elseif ($line -match '(?<=^>f\+{9}\s+send\s+)(.*\.\w+$)')
								{
									$DoMove++
									# File transfer line
									Debug "Matched file transfer line: $line"
									$totalFiles++
									$successfulfiles++
									$files += $matches[1]
									$BackupSuccess++
								}
								elseif ($line -match '(?<=^cd\+{9}\s+send\s+)(.*)(?=/)')
								{
									$DoMove++
									# Folder transfer line
									Debug "Matched folder transfer line: $line"
									$totalFiles++
									$successfulfolders++
									$folders += $matches[1]
									$BackupSuccess++
								}
							}
						}
						else
						{
							$failedFiles++
							$failedFilesList += $file.Name
							Debug "[ERROR] Failed to move: - $($file.Name)"
							Email "[ERROR] Failed to move: - $($file.Name)"
							#An error occurred during rsync operation
							Write-Host "An error occurred while transferring $($file.Name):"
							# TO TEST Read the error log content to extract file/folder names causing errors
							$errorContent = Get-Content $errorLog
							foreach ($line in $errorContent)
							{
								if ($line -match '^rsync:\s(.+)$')
								{
									$failedFileName = $Matches[1]
									Debug "[ERROR] Failed to move - $failedFileName"
									Email "[ERROR] Failed to move - $failedFileName"
								}
							}
						}
						
					}
					Debug " ------------------------------------------------------------------------"
					Debug "Total files/folders to Process: $totalFiles"
					Debug " ------------------------------------------------------------------------"
					
					if ($files.Count -gt 0)
					{
						$successfulTotal = $successfulfiles + $successfulfolders
						Debug "Successful transfers: $successfulfiles files + $successfulfolders folders = Total: $successfulTotal successes"
						Debug "List of successful files transferred:"
						Debug "---------------------------------"
						$files | ForEach-Object -Begin { $counter = 1 } -Process {
							Debug "[OK] Moved: $counter. `"$_`""
							Email "[OK] Moved: `"$_`""
							$counter++
						}
					}
					else
					{
						Debug "No files transferred."
					}
					
					Debug "---------------------------------"
					
					if ($folders.Count -gt 0)
					{
						Debug "Total Folders: $($folders.Count)"
						Debug "List of successful folders transferred:"
						Debug "---------------------------------"
						$folders | ForEach-Object -Begin { $counter = 1 } -Process {
							Debug "$counter. $_"
							$counter++
						}
					}
					else
					{
						Debug "No folders transferred."
					}
					
					if ($deletedFiles.Count -gt 0)
					{
						Debug "Total Files Deleted: $($deletedFiles.Count)"
						Debug "List of deleted files:"
						Debug "---------------------------------"
						$deletedFiles | ForEach-Object -Begin { $counter = 1 } -Process {
							Debug "$counter. $_"
							$counter++
						}
					}
					else
					{
						Debug "No files deleted."
					}
					
					function Remove-EmptyFolders
					{
						param (
							[string]$directory
						)
						
						do
						{
							$emptyFolders = find $directory -depth -type d -empty -print0 | xargs -0 rmdir
							foreach ($folder in $emptyFolders)
							{
								Debug "Removed empty folder: $folder"
							}
						}
						while ($emptyFolders)
						# Check if there are any remaining non-empty directories and remove them
						$nonEmptyFolders = find $directory -mindepth 1 -depth -type d -print0 | xargs -0 rmdir
						foreach ($folder in $nonEmptyFolders)
						{
							Debug "Removed non-empty folder: $folder"
						}
						Debug "Empty folder cleanup complete."
					}
					
					# Call the function to remove empty folders
					if ($totalSourceFolders -gt 0)
					{
						Remove-EmptyFolders -directory $BackupTempDir
					}
					
					# Check if the file exists and its content is empty
					if (Test-Path $errorLog)
					{
						$content = Get-Content $errorLog
						if ($content -eq $null)
						{
							Remove-Item $errorLog
						}
					}
					
					Debug "------------------------------------------------------------------------"
				}
				Debug "Function Archive FINISHED in $(ElapsedTime $StartFunction)"
				Debug "------------------------------------------------------------------------"
			}
			Catch
			{
				Debug "[ERROR] Archive Creation : $($Error[0])"
				Email "[ERROR] Archive Creation : $($file.BaseName) Check Debug Log"
				Email "[ERROR] Archive Creation : $($Error[0])"
				EmailResults
				Exit
			}
		}
	}
}

<#  Prune Backups function  #>
function PruneBackups
{
	$FilesToDel = Get-ChildItem -Path "$BackupLocation" | Where-Object { $_.LastWriteTime -lt ((Get-Date).AddDays(-$DaysToKeepBackups)) }
	$CountDel = $FilesToDel.Count
	If ($CountDel -gt 0)
	{
		Debug "------------------------------------------------------------------------"
		Debug "Begin pruning local backups older than $DaysToKeepBackups days"
		Debug "Prune Location: $BackupLocation"
		Debug " "
		$EnumCountDel = 0
		Try
		{
			$FilesToDel | ForEach-Object {
				$FullName = $_.FullName
				$Name = $_.Name
				If (Test-Path $_.FullName -PathType Container)
				{
					Remove-Item -Force -Recurse -Path $FullName
					Debug "Deleted folder: $Name"
					$EnumCountDel++
				}
				If (Test-Path $_.FullName -PathType Leaf)
				{
					Remove-Item -Force -Path $FullName
					Debug "Deleted file  : $Name"
					$EnumCountDel++
				}
			}
			If ($CountDel -eq $EnumCountDel)
			{
				Debug "Successfully pruned $CountDel item$(Plural $CountDel)"
				Debug "------------------------------------------------------------------------"
				Email "[OK] Pruned backups older than $DaysToKeepBackups days"
			}
			Else
			{
				Debug "[ERROR] Prune backups : Filecount does not match delete count"
				Email "[ERROR] Prune backups : Check Debug Log"
			}
		}
		Catch
		{
			Debug "[ERROR] Prune backups : $($Error[0])"
			Debug "------------------------------------------------------------------------"
			Email "[ERROR] Prune backups : Check Debug Log"
		}
	}
	else
	{
		Debug "------------------------------------------------------------------------"
		Debug "Prune Location: $BackupLocation"
		Debug "There is Nothing to Prune older than $DaysToKeepBackups days"
		Debug "------------------------------------------------------------------------"
	}
}

<#  Backup to NAS Backup Location #>
function NASBackup
{
	$os = $OSname
	Debug "------------------------------------------------------------------------"
	Debug "Transfer Backup to NAS"
	Debug "Local Location : $BackupLocation"
	Debug "NAS Location   : $NASBackupPath"
	$BeginRobocopy = Get-Date
	switch ($os)
	{
		"Windows" {
			Try
			{
				$DoNAS++
				NET USE $NASBackupPath /user:$NasAdmin $NasAdminpass /persistent:no | Out-Null
				#$NASDrive = (NET USE * $NASBackupPath /user:$NasAdmin $NasAdminpass | Where-Object {$_ -like "*$NASBackupLocation*"}).Split(" ")[1]
				#Debug "Drive Letter mapped for NAS: $NASDrive"
				$RoboCopy = & robocopy $BackupLocation $NASBackupPath /mir /ndl /r:43200 /np /w:1 | Out-String
				# Extract the header and summary from the RoboCopy output
				$header = ($RoboCopy.Trim() -split [Environment]::NewLine)[0 .. 12] -join [Environment]::NewLine
				$summary = ($RoboCopy.Trim() -split [Environment]::NewLine)[-12 .. -1] -join [Environment]::NewLine
				If ($VerboseNAS)
				{
					Debug $RoboCopy
				}
				Else
				{
					Email "[INFO] NAS Robocopy Operation not Logged"
					Debug ("***		Verbose Logging Disabled		***")
					Debug ([Environment]::NewLine + [Environment]::NewLine + $header + [Environment]::NewLine + $summary + [Environment]::NewLine)
				}
				
				Debug " "
				Debug "------------------------------------------------------------------------"
				Debug "Finished uploading up to NAS in $(ElapsedTime $BeginRobocopy)"
				
				$RoboStats = $RoboCopy.Split([Environment]::NewLine) | Where-Object { $_ -match 'Files\s:\s+\d' }
				$RoboStats | ConvertFrom-String -Delimiter "\s+" -PropertyNames Nothing, Files, Colon, Total, Copied, Skipped, Mismatch, Failed, Extras | ForEach-Object {
					$Copied = $_.Copied
					$Mismatch = $_.Mismatch
					$Failed = $_.Failed
					$Extras = $_.Extras
				}
				NET USE $NASBackupPath /D | Out-Null
				#NET USE $NASDrive /D
				
				If (($Mismatch -gt 0) -or ($Failed -gt 0))
				{
					NET USE $NASBackupPath /D | Out-Null
					#NET USE $NASDrive /D
					Throw "Robocopy to NAS MISMATCH or FAILED exists"
				}
				$BackupSuccess++
				Debug "------------------------------------------------------------------------"
				Debug "Robocopy backup to NAS success: $Copied new, $Extras deleted, $Mismatch mismatched, $Failed failed"
				Debug "------------------------------------------------------------------------"
				Email "[OK] Backup Transfer to NAS: $Copied new, $Extras del"
			}
			Catch
			{
				Debug "[ERROR] Backup Transfer to NAS : $($Error[0])"
				Email "[ERROR] Backup Transfer to NAS : Check Debug Log"
				Email "[ERROR] Backup Transfer to NAS : $($Error[0])"
			}
		}
		"Linux" {
			$tempMount = "$HOME/nas/" #"/mnt/nas/" ## !! IMPORTANT End with a /
			If (-not (Test-Path "$tempMount" -PathType Container))
			{
				mkdir "$tempMount"
				Debug "Temp Mount Directory Created"
			}
			
			$Source = $BackupLocation
			$Destination = $tempMount
			$totalSourceFiles = 0
			$totalSourceFolders = 0
			$errorLog = "$PSScriptRoot$DSrsync_NAS_error.log"
			$Listoffiles = Get-ChildItem -Path "$Source"
			# Count total number of files and folders in the source directory before rsync
			$totalSourceFiles = (find $source/* -type f | wc -l) # Count total files
			$totalSourceFolders = (find $Source/* -type d | wc -l) # Count total directories
			
			# List files with numbering
			if ($totalSourceFiles -gt 0)
			{
				Debug "Total Source files: $totalSourceFiles"
				$fileList = find $Source/* -type f -printf "%T@ %p\n" | sort -n | foreach { $_ -replace "^\d+.\d+\s", "" } ## sort and foreach are linux commands here
				Debug "List of files:"
				$fileList | ForEach-Object -Begin { $counter = 1 } -Process {
					Debug "$counter. $_"
					$counter++
				}
			}
			Debug "---------------------------------"
			# List folders with numbering
			if ($totalSourceFolders -gt 0)
			{
				Debug "Total Source folders: $totalSourceFolders"
				$folderList = find $Source/* -type d -printf "%T@ %p\n" | sort -n | foreach { $_ -replace "^\d+.\d+\s", "" } ## sort and foreach are linux commands here
				Debug "List of folders:"
				$folderList | ForEach-Object -Begin { $counter = 1 } -Process {
					Debug "$counter. $_"
					$counter++
				}
			}
			Debug "---------------------------------"
			Debug "---------------------------------"
			
			# Mount NAS
			try {
				$MountCommand = "sudo mount -t cifs $NASBackupPath $tempMount -o username=$NasAdmin,password=$NasAdminpass"
				Invoke-Expression $MountCommand
				if ($LASTEXITCODE -ne 0)
				{
					Debug "Error: Failed to mount NAS. Exit Code: $LASTEXITCODE"
				}else {
					Debug "NAS mounted at : `"$($tempMount)`""
				}
			} catch {
				Debug "Error occurred while Mounting NAS: $_"
				Email "[ERROR] Error Occured Mounting NAS, Check Log"
				return
			}
			
			# Initialize variables
			$totalFiles = 0
			$successfulfiles = 0
			$successfulfolders = 0
			$failedFiles = 0
			$deletedFiles = 0
			$files = @()
			$folders = @()
			$deletedFiles = @()
			$failedFilesList = @()
			
			# Loop through each file in the backup location
			foreach ($file in $Listoffiles)
			{
				# Execute rsync command and capture output and errors
				$rsyncOutput = & rsync -avi --delete --partial --append-verify --progress --stats --out-format="%i %o %n" "$file" "$tempMount" 2> $errorLog
				
				if ($LASTEXITCODE -eq 0)
				{
					foreach ($line in $rsyncOutput)
					{
						$line = $line.Trim() # Trim extra spaces
						#Debug "Processing line: $line"
						if ($line -match '^\*deleting\s+del\. (.+)$')
						{
							$DoNAS++
							# Deletion line
							Debug "Matched deletion line: $line"
							$totalFiles++
							$deletedFiles += $matches[1]
							$BackupSuccess++
						}
						elseif ($line -match '(?<=^>f\+{9}\s+send\s+)(.*\.\w+$)')
						{
							$DoNAS++
							# File transfer line
							Debug "Matched file transfer line: $line"
							$totalFiles++
							$successfulfiles++
							$files += $matches[1]
							$BackupSuccess++
						}
						elseif ($line -match '(?<=^cd\+{9}\s+send\s+)(.*)(?=/)')
						{
							$DoNAS++
							# Folder transfer line
							Debug "Matched folder transfer line: $line"
							$totalFiles++
							$successfulfolders++
							$folders += $matches[1]
							$BackupSuccess++
						}
					}
				}
				else
				{
					$failedFiles++
					$failedFilesList += $file.Name
					Debug "[ERROR] Failed to Sync: - $($file.Name)"
					Email "[ERROR] Failed to Sync: - $($file.Name)"
					#An error occurred during rsync operation
					Write-Host "An error occurred while transferring $($file.Name):"
					# Read the error log content to extract file/folder names causing errors
					$errorContent = Get-Content $errorLog
					foreach ($line in $errorContent)
					{
						if ($line -match '^rsync:\s(.+)$')
						{
							$failedFileName = $Matches[1]
							#$failedFiles++
							#$failedFilesList += $failedFileName
							Debug "[ERROR] Failed to Sync - $failedFileName"
							Email "[ERROR] Failed to Sync - $failedFileName"
						}
					}
				}
				
			}
			Debug " ------------------------------------------------------------------------"
			Debug "Total files/folders to Process: $totalFiles"
			Debug " ------------------------------------------------------------------------"
			
			# Disconnect from NAS
			try {
				Start-Sleep -Seconds 10
				$UnmountCommand = "sudo umount $tempMount"
				Invoke-Expression $UnmountCommand
				if ($LASTEXITCODE -ne 0)
				{
					Debug "Error: Failed to un-mount NAS. Exit Code: $LASTEXITCODE"
				}else {
					Debug "NAS Un-mounted"
				}
			} catch {
				Debug "Error occurred while un-mounting NAS: $_"
				Email "[ERROR] Error Occured un-mounting NAS, Check Log"
				return
			}
			
			if ($files.Count -gt 0)
			{
				$successfulTotal = $successfulfiles + $successfulfolders
				Debug "Successful transfers: $successfulfiles files + $successfulfolders folders = Total: $successfulTotal successes"
				Debug "List of successful files transferred:"
				Debug "---------------------------------"
				$files | ForEach-Object -Begin { $counter = 1 } -Process {
					Debug "$counter. $_"
					$counter++
				}
			}
			else
			{
				Debug "No files transferred."
			}
			Debug "---------------------------------"
			if ($folders.Count -gt 0)
			{
				Debug "Total Folders: $($folders.Count)"
				Debug "List of successful folders transferred:"
				Debug "---------------------------------"
				$folders | ForEach-Object -Begin { $counter = 1 } -Process {
					Debug "$counter. $_"
					$counter++
				}
			}
			else
			{
				Debug "No folders transferred."
			}
			Debug "---------------------------------"
			if ($deletedFiles.Count -gt 0)
			{
				Debug "Total Files Deleted: $($deletedFiles.Count)"
				Debug "List of deleted files:"
				Debug "---------------------------------"
				$deletedFiles | ForEach-Object -Begin { $counter = 1 } -Process {
					Debug "$counter. $_"
					$counter++
				}
			}
			else
			{
				Debug "No files deleted."
			}
			
			if ((Get-Content $errorLog) -eq $null)
			{
				Remove-Item $errorLog
			}
			
			Debug "------------------------------------------------------------------------"
		} ## Linux END
	}
}

<#  Check for updates  #>
function CheckForUpdates
{
	Debug "------------------------------------------------------------------------"
	Debug "Checking for script update at GitHub"
	$GitHubVersion = $LocalVersion = $NULL
	$GetGitHubVersion = $GetLocalVersion = $False
	$GitHubVersionTries = 1
	Do
	{
		Try
		{
			$GitHubVersion = [decimal](Invoke-WebRequest -UseBasicParsing -Method GET -URI https://raw.githubusercontent.com/gotspatel/SQL_Backup/main/version.txt).Content
			$GetGitHubVersion = $True
		}
		Catch
		{
			Debug "[ERROR] Obtaining GitHub version : Try $GitHubVersionTries : Obtaining version number: $($Error[0])"
		}
		$GitHubVersionTries++
	}
	Until (($GitHubVersion -gt 0) -or ($GitHubVersionTries -eq 6))
	If (Test-Path "$PSScriptRoot\version.txt")
	{
		$LocalVersion = [decimal](Get-Content "$PSScriptRoot\version.txt")
		$GetLocalVersion = $True
	}
	If (($GetGitHubVersion) -and ($GetLocalVersion))
	{
		If ($LocalVersion -lt $GitHubVersion)
		{
			Debug "[INFO] Upgrade to version $GitHubVersion available at https://github.com/gotspatel/SQL_Backup"
			If ($UseHTML)
			{
				Email "[INFO] Upgrade to version $GitHubVersion available at <a href=`"https://github.com/gotspatel/SQL_Backup`">GitHub</a>"
			}
			Else
			{
				Email "[INFO] Upgrade to version $GitHubVersion available at https://github.com/gotspatel/SQL_Backup"
			}
		}
		Else
		{
			Debug "Backup & Upload script is latest version: $GitHubVersion"
		}
	}
	Else
	{
		If ((-not ($GetGitHubVersion)) -and (-not ($GetLocalVersion)))
		{
			Debug "[ERROR] Version test failed : Could not obtain either GitHub nor local version information"
			Email "[ERROR] Version check failed"
		}
		ElseIf (-not ($GetGitHubVersion))
		{
			Debug "[ERROR] Version test failed : Could not obtain version information from GitHub"
			Email "[ERROR] Version check failed"
		}
		ElseIf (-not ($GetLocalVersion))
		{
			Debug "[ERROR] Version test failed : Could not obtain local install version information"
			Email "[ERROR] Version check failed"
		}
		Else
		{
			Debug "[ERROR] Version test failed : Unknown reason - file issue at GitHub"
			Email "[ERROR] Version check failed"
		}
	}
}