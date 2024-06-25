#!/snap/bin/pwsh -Command
<#
	.SYNOPSIS
	
	.DESCRIPTION
	
	.PARAMETER inputString
	
	.EXAMPLE
	
	.NOTES
	
#>

<###   DEBUG VARIABLES   ###>
$VerboseConsole = $True 							# If true, will output debug to console
$VerboseFile    = $True 							# If true, will output debug to file

<###   PATH LOCATIONS   ###>
$BackupTempDir  = "" 								# Temporary Folder for use in backup
$BackupLocation = "" 								# Final Location of archive files / db backup to store

<###  SERVICE VARIABLES  ###>
$ServiceTimeout = 5

<###   DATABASE LIST  ###>
## % can be used as wildcard character in Database Name
$SQLDbList = ""

<## SQL CREDENTIALS ##>
$Username = "root_user"
$Password = "The First SeCr3T"

<## BACKUP SELECTION ##>
$BackupDB    = $True 								# Specifies whether to run BackupDatabases function (FALSE will skip)
$BackupAllDB = $True 								# True will backup all databases, not just first one - must use ROOT user for this

<###   ARCHIVE VARIABLES   ###>
$UseSevenZip     = $True 							# True will compress backup files into archive
$SevenZipPath    = ""								# Blank for Auto / or set manually path to 7za.exe
$MultiVolume     = $False 							# False = no-multi-volume zip archive, True = multi-volume 7z archive
$VolumeSize      = "180m" 							# Size of archive volume parts - maximum 200m recommended - valid suffixes for size units are (b|k|m|g)
$PassProtected   = $False 							# False = no-password zip archive, True = AES-256 encrypted multi-volume 7z archive
$ArchivePassword = "Second SeCr3T" 					# Password to 7z archive

<###   PRUNE BACKUPS VARIABLES   ###>
$PruneBackups      = $True 							# If true, will delete local backups older than N days
$DaysToKeepBackups = 7 								# Number of days to keep backups - older backups will be deleted

<###   NAS VARIABLES  ###>
$VerboseNAS        = $False                        	# True will Log Backed up files to NAS
$NASBackup         = $False                         # Enable or disable NAS Backup
$NASBackupLocation = "" 							# Location of NAS Shared Folder "\\192.168.10.10\DB_Backup"
$NasAdmin          = "admin"                       	# Nas admin User
$NasAdminpass      = "Another SeCr3T"               # Nas admin User Password

<###   EMAIL VARIABLES   ###>
$SendMail               = $False
$EmailFrom              = "sender@mydomain.com"
$EmailTo                = "receiver@mydomain.com"
$SMTPServer             = "Email.Server.Here"
$SMTPAuthUser           = "sender@mydomain.com"
$SMTPAuthPass           = "One More SeCr3T"
$SMTPPort               = 587
$SSL                    = $True 					# If true, will use tls connection to send email
$UseHTML                = $True 					# If true, will format and send email body as html (with color!)
$Disable_SSL_Validation = $True 					# Disable SSL certificate validation # Set to $False to Enable SSL certificate validation
$AttachDebugLog         = $True 					# If true, will attach debug log to email report - must also select $VerboseFile
$MaxAttachmentSize      = 1 						# Size in MB

<###   GMAIL VARIABLES   ###>
<#  Alternate messaging in case of MySQL failure  #>
<#  "Less Secure Apps" must be enabled in gmail account settings  #>
$GmailUser = "GmailSENDER@gmail.com"
$GmailPass = "I Pormise this is the Last SeCr3T"
$GmailTo   = "receiver@anotherdomain.com"
