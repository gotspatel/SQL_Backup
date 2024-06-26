#!/user/bin/pwsh -Command

<#
	## Purpose:
		The PowerShell script automates database backup tasks for MSSQL OR MySQL (MySQL or Mariadb) databases, including archiving/ moving, and NAS backups.

	## Features:
		- Loads supporting files for configuration and functions.
		- Validates and selects the type of database to backup (MSSQL or MySQL).
		- Retrieves system and database-specific variables.
		- Cleans up old files and creates necessary directories.
		- Initiates database backup based on user input.
		- Creates archives if enabled, prunes backups, and performs NAS backups.
		- Reports backup success and any errors.
		- Checks for updates (commented out).
		- Sends email notifications with backup results.

	## Key Components:
		- `SQLBackupConfig.ps1`: Configuration file for database backup settings.
		- `SQLBackupFunctions.ps1`: Functions for database backup operations.
		- `$SelectType`: Parameter to specify the type of database (MSSQL or MySQL).
		- `$DBType`: Variable to store the selected database type.
		- `$BackupLocation`, `$NASBackupLocation`, `$BackupTempDir`: Directories for backup operations.
		- Functions: `BackupDatabases`, `MakeArchive`, `PruneBackups`, `NASBackup`, `EmailResults`, and others for backup tasks and email notifications.

	## Usage:
		chmod +x /root/Documents/script/SQLBackup.ps1
		1. Run the script with the appropriate database type parameter (`mssql` or `mysql`).
		2. Optionally configure backup settings in supporting files.
		3. Monitor backup progress and receive email notifications for success or errors.
	
	## Notes:
		- Error handling includes logging errors to a file and sending email notifications.
		- Debugging information is logged for troubleshooting and monitoring.
		- HTML formatting is available for email notifications if enabled.
		- Updates checking functionality is commented out but can be enabled as needed.
	
	.SYNOPSIS
		Automates database backup tasks for MSSQL and MySQL databases with features like archiving, moving, and NAS backups.

	.DESCRIPTION
		The PowerShell script facilitates automated backup operations for MSSQL and MySQL databases, managing various tasks including directory setup, backup initiation, archival, and reporting. It's designed to streamline database backup processes while providing error handling and email notifications.

	.FUNCTIONALITY
		- Loads supporting files and configures necessary variables.
		- Validates and selects the type of database for backup.
		- Cleans up old files and prepares directories for backup operations.
		- Initiates database backup based on user input.
		- Performs archival, pruning, and NAS backups as required.
		- Reports backup success and errors through logging and email notifications.

	.PARAMETER
		- `$SelectType`: Specifies the type of database to backup (MSSQL or MySQL).

	.NOTES
		- The script is designed for flexibility and scalability, allowing customization of backup settings and configurations.
		- It's recommended to review and adjust settings in supporting files (`SQLBackupConfig.ps1`) according to specific requirements.
		- Debugging information is available for troubleshooting and monitoring backup tasks.
		- Email notifications provide status updates on backup success or errors.
		
		Linux Cron details
		With CRON DEBUG
		MIN HOUR DOM MON DOW CMD
		50 12 * * * /snap/bin/pwsh "/mnt/scripts/SQLBackup.ps1" >> /mnt/scripts/cron.log 2>&1

		Without CRON DEBUG
		MIN HOUR DOM MON DOW CMD
		50 12 * * * /snap/bin/pwsh "/mnt/scripts/SQLBackup.ps1"

	.EXAMPLE
		.\SQLBackup.ps1 mssql
		Runs the script to initiate backup operations for MSSQL databases.

		.\SQLBackup.ps1 mysql
		Runs the script to initiate backup operations for MySQL databases.
#>

Param (
	[string]$SelectType
)

If ($SelectType -notmatch '^[mM][sS][sS][qQ][lL]$|^[mM][yY][sS][qQ][lL]$')
{
	Write-Host "[ERROR] Failed to provide proper parameter." 
	Write-Host "Use 'mssql' for Microsoft SQL"
	Write-Host "          OR                 "
	Write-Host "Use 'mysql' for Mysql or Mariadb"
	Write-Host "Quitting Script"
	Exit
}
Else
{
	If ($SelectType -match 'mssql')
	{
		$DBType = "MSSQL"
	}
	ElseIf ($SelectType -match 'mysql')
	{
		$DBType = "MYSQL"
	}
}

<###   LOAD SUPPORTING FILES   ###>
Try
{
	.(Join-Path -Path $PSScriptRoot -ChildPath "SQLBackupConfig.ps1")
	.(Join-Path -Path $PSScriptRoot -ChildPath "SQLBackupFunctions.ps1")
}
Catch
{
	$PSLogFile = Join-Path -Path $PSScriptRoot -ChildPath "PSError.log"
	Write-Output "$(Get-Date -f "dd/MM/yyyy hh:mm:ss tt") : ERROR : Unable to load supporting PowerShell Scripts" | Out-File $PSLogFile -Encoding ASCII -Append
	Write-Output "$(Get-Date -f "dd/MM/yyyy hh:mm:ss tt") : ERROR : $($Error[0])" | Out-File $PSLogFile -Encoding ASCII -Append
	Start-Sleep -Seconds 5
	Write-Host "[ERROR] Check Powershell Error Log"
	Exit
}


<###   BEGIN SCRIPT DO NOT CHANGE ANY SEQUENCE AFTER THIS  ###>

<###   SYSTEM VARIABLES   ###>
$Error.Clear()
$DS              = [IO.Path]::DirectorySeparatorChar # Determine the appropriate directory separator, Required for some process on linux (backup database)
$ScriptDirectory = Split-Path -Parent $MyInvocation.MyCommand.Path
$StartScript     = Get-Date
$DateString      = $($StartScript).ToString("yyyy-MM-dd")
$MyOSinfo        = Get-OS
$OSname          = $($MyOSinfo.OSName)
$server          = $($MyOSinfo.ComputerName)
$BootTime        = $($MyOSinfo.OSBootTime)
$IPv4            = $($MyOSinfo.IPv4)
$LinuxName       = $null
$LinuxType       = $null

if ($OSname -eq 'Linux') {
    $LinuxName = $($MyOSinfo.DistroName)
    $LinuxType = $($MyOSinfo.DistroType)
}

$SQLInstance       = $IPv4 ## TODO: To be Changed in future to get instance Automatic from system
$NASBackupString   = ($server.ToUpper() + "-" + $DBType)
$NASBackupPath     = $NASBackupLocation + "\" + $NASBackupString
$BackupPathString  = "$DateString-$DBType"
$backupRoutineInfo = ":::   $($DBType) on $($server.ToUpper()) Backup Routine $(Get-Date -f D)   :::"

# MySQL Credential Conf File Path
switch ($OSname)
{
	"Windows" {
		$MySQLConfFile  = Join-Path $PSScriptRoot -ChildPath "my.cnf"
	}
	"Linux" {
		$MySQLConfFile  = "/etc/my.cnf" # Default WORKING Path for Custom config file under LINUX Refer Table 6.2 https://dev.mysql.com/doc/refman/8.0/en/option-files.html
	}
}

<#  Remove trailing slashes from folder locations  #>
if ($OSname -eq "Windows")
{
	$BackupTempDir  = $BackupTempDir -Replace ("\\$", '')
	$BackupLocation = $BackupLocation -Replace ("\\$", '')
	$NASBackupPath  = $NASBackupPath -Replace ("\\$", '')
}
elseif ($OSname -eq "Linux" -or $OSname -eq "macOS")
{
	$BackupTempDir  = $BackupTempDir -replace '/\$', ''
	$BackupLocation = $BackupLocation -replace '/\$', ''
	$NASBackupPath  = $NASBackupPath -replace '/\$', ''
}

$BackupPath = Join-Path -Path $BackupLocation -ChildPath $BackupPathString
If (-not (Test-Path $BackupPath -PathType Container))
{
	mkdir $BackupPath
}
Confirm-Path $BackupPath

<#  Delete old debug file and create new  #>
$DebugLog = Join-Path -Path $BackupLocation -ChildPath "$DBType`_Backup-$DateString.log"
If (Test-Path $DebugLog) { Remove-Item -Force -Path $DebugLog }
New-Item $DebugLog | Out-Null

<###   GET PARAMETERS FROM FUNCTIONS   ###>
switch ($OSname)
{
	"Windows" {
		$SevenZipA    = Set-SevenZipExePath
	}
	"Linux" {
		$SevenZipA    = Set-SevenZipExePath -DistroType $LinuxType
	}
}

$sqlResult      = Set-SQLDetails -MyOS $OSname -DBType $DBType
$SQLServiceName = $sqlResult.ServiceName
$MySQLExe       = $sqlResult.MySQLExe
$MySQLDumpExe   = $sqlResult.MySQLDumpExe
$SQLBootTime    = $sqlResult.SQLBootTime

if ($DBType -match "MySQL")
{
	Confirm-Path $MySQLConfFile
}
elseif ($DBType -match "MSSQL")
{
	Confirm-Module -ModuleName "SqlServer" -Version "22.2.0"
}
else
{
	Debug "SQL MODULE FAULT"
	exit
}

<###   BEGIN SCRIPT DO NOT CHANGE ANY SEQUENCE AFTER THIS  ###>

<#  Set counting variables that pass through functions  #>
Set-Variable -Name BackupSuccess -Value 0 -Option AllScope
Set-Variable -Name DoBackupDB    -Value 0 -Option AllScope
Set-Variable -Name DoArchive     -Value 0 -Option AllScope
Set-Variable -Name DoMove        -Value 0 -Option AllScope
Set-Variable -Name DoNAS         -Value 0 -Option AllScope

<# Create Backup Temp Dir if it doesn't exist #>
if (-not (Test-Path "$BackupTempDir" -PathType Container))
{
	Debug "Backup Temp Directory Created"
	mkdir "$BackupTempDir"
	Confirm-Path $BackupTempDir
}
else
{
	try
	{
		Get-ChildItem -Path $BackupTempDir -Recurse | Remove-Item -Force -Recurse -ErrorAction Stop
	}
	catch
	{
		Debug "Backup Temp Directory Cleanup failed: $_.Exception.Message"
	}
}

<#  Delete old files and create new  #>
$EmailBody = Join-Path -Path $PSScriptRoot -ChildPath "EmailBody.log"
If (Test-Path $EmailBody) { Remove-Item -Force -Path $EmailBody }
New-Item $EmailBody | Out-Null

$SQLDumpLog = Join-Path -Path $BackupLocation -ChildPath "$DBType`_DEBUG-$DateString.log"
If (Test-Path $SQLDumpLog) { Remove-Item -Force -Path $SQLDumpLog }
New-Item $SQLDumpLog | Out-Null
Debug "------------------------------------------------------------------------"
Debug $backupRoutineInfo
Debug "------------------------------------------------------------------------"
$PAD = 26
Debug "$(RPAD "Script Directory" $PAD): $($ScriptDirectory)"
Debug "$(RPAD "Switch to Send Mail" $PAD): $SendMail"
if ($OSname -eq 'Linux') {
	Debug "$(RPAD "Operating System" $PAD): $($OSname), Distro: $($LinuxName) - $($LinuxType)"
} else {
	Debug "$(RPAD "Operating System" $PAD): $($OSname)"
}
Debug "$(RPAD "Computer Name" $PAD): $($server.ToUpper())"
Debug "$(RPAD "IPv4 Address" $PAD): $IPv4"
Debug "$(RPAD "$($server.ToUpper()) Last Reboot" $PAD): $($BootTime) [$(ElapsedTime $BootTime)]"
Debug "$(RPAD "DB Type to Backup" $PAD): $DBType"
Debug "$(RPAD "DB Service Name" $PAD): $SQLServiceName"
if ($DBType -match "MSSQL")
{
	Debug "$(RPAD "SQL Instance Used" $PAD): $($SQLInstance)"
}
else
{
	# Nothing to print
}
Debug "$(RPAD "$($DBType) Last Reboot" $PAD): $($SQLBootTime) [$(ElapsedTime $SQLBootTime)]"

Debug "------------------------------------------------------------------------"

If ($UseSevenZip)
{
	Confirm-Path $SevenZipA
}

If ($UseHTML)
{
	Write-Output "
	<!DOCTYPE html>
	<html>
	<head>
		<meta name=`"viewport`" content=`"width=device-width, initial-scale=1.0 `" />
		<style>
			body {
				font-family: Arial, sans-serif;
			}
			.header {
				background-color: #4CAF50;
				color: white;
				padding: 10px;
				font-size: 20px;
				text-align: center;
			}
			.content {
				padding: 20px;
			}
			.footer {
				background-color: #f2f2f2;
				padding: 10px;
				text-align: center;
			}
		</style>
	</head>
	<body>
		<div class="header">
			$backupRoutineInfo
		</div>
		<div class="content"><table>
	" | Out-File $EmailBody -Encoding ASCII -Append
}

If ($UseHTML)
{
	$PAD = 30
	Email " "
	Email "$(RPAD "<b>$($server.ToUpper())</b> Last Reboot" $PAD): $($BootTime)"
	Email "$(RPAD "<b>$($DBType)</b> Last Reboot" $PAD): $($SQLBootTime)"
	Email " "
}
Else
{
	Email ":::   $($DBType)  Backup Routine          $(Get-Date -f D)   :::"
	Email " "
	Email "Server Last Reboot: $($BootTime)"
	Email " "
}
<#  Backup database files  #>

<# 
$response = Read-Host "Do you want to backup databases? (y/n)"
if ($response -eq "y") {
    If ($BackupDB) {BackupDatabases}
} elseif ($response -eq "n") {
    # Do nothing or handle the case when user doesn't want to backup databases
	return
} else {
    Write-Host "Invalid input Backup Database. Please enter 'y' or 'n'."
}

#>

If ($BackupDB) { BackupDatabases }
MakeArchive
If ($PruneBackups) { PruneBackups }
If ($NASBackup) { NASBackup }

<# Report backup success #>
If (($BackupSuccess -eq ($DoBackupDB + $DoArchive + $DoMove + $DoNAS)))
{
	Debug "------------------------------------------------------------------------"
	Debug "Backup Count: $DoBackupDB"
	if ($UseSevenZip)
	{
		Debug "Archive Count: $DoArchive"
	}
	else
	{
		Debug "Move Count: $DoMove"
	}
	if ($NASBackup)
	{
		Debug "NAS Backup Count: $DoNAS"
	}
	Debug "Total Backup Success Count: $BackupSuccess"
	Debug "------------------------------------------------------------------------"
	if ($UseSevenZip)
	{
		Debug "All files archived successfully"
	}
	else
	{
		Debug "All files moved successfully"
	}
	Email "[OK] All Database backed up successfully"
}
Else
{
	Debug "------------------------------------------------------------------------"
	Debug "Backup Count: $DoBackupDB"
	if ($UseSevenZip)
	{
		Debug "Archive Count: $DoArchive"
	}
	else
	{
		Debug "Move Count: $DoMove"
	}
	if ($NASBackup)
	{
		Debug "NAS Backup Count: $DoNAS"
	}
	Debug "Total Backup Success Count: $BackupSuccess"
	Debug "------------------------------------------------------------------------"
	Debug "[ERROR] Backup count mismatch."
	Email "[ERROR] Backup count mismatch : Check Debug Log"
}

<##Cleanup debug logs if empty##>
if ((Get-Content -Path $SQLDumpLog -Raw) -eq '') {
    # If blank, remove the file
    Remove-Item -Force -Path $SQLDumpLog
} else {
    # If not blank, do nothing
}

<#  Check for updates  #>
CheckForUpdates

<#  Finish up and send email  #>
Debug "------------------------------------------------------------------------"
If (((Get-Item $DebugLog).length/1MB) -ge $MaxAttachmentSize)
{
	Debug "Debug log larger than specified max attachment size. Do not attach to email message."
	Email "[INFO] Debug log larger than specified max attachment size. Log file stored in backup folder on server file system."
}
$backupDoneInfo = ":::   $($DBType) Backup & Upload routine COMPLETED in $(ElapsedTime $StartScript) at $(Get-Date -Format "hh:mm:ss tt")   :::"
#Debug "$($DBType) Backup & Upload routine COMPLETED in $(ElapsedTime $StartScript)" 
Debug "$backupDoneInfo"
Debug "------------------------------------------------------------------------"
Email " "
#Email "<center>:::&nbsp;&nbsp;&nbsp;$($DBType) Backup & Upload routine COMPLETED in $(ElapsedTime $StartScript) at $(Get-Date -Format "hh:mm:ss tt")&nbsp;&nbsp;&nbsp;:::</center>"
If ($UseHTML)
{
	Write-Output "</table></div>
<div class="footer">
	$backupDoneInfo
</div>
</body>
</html>" | Out-File $EmailBody -Encoding ASCII -Append
}

EmailResults