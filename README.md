# PowerShell Database Backup Script

This PowerShell script automates database backup for MSSQL and MySQL/MariaDB servers based on user input.

## Usage

Run the script with the parameter `-SelectType` to specify the database type:

- Use `'mssql'` for Microsoft SQL Server.
- Use `'mysql'` for MySQL or MariaDB.
- For Example: SQLBackup.ps1 mssql OR SQLBackup.ps1 mysql

## Prerequisites

Ensure PowerShell supports running scripts (`Set-ExecutionPolicy RemoteSigned` may be required). Additionally, install required modules and configure paths as needed. Some are taken care ofby the script itself.

## Parameters

- **SelectType**: Specifies the database type to backup (`'mssql'` or `'mysql'`).
- Can run from Windows Task Scheduler or Linux Cronjob

## Functionality

- Loads necessary supporting PowerShell scripts (`SQLBackupConfig.ps1` and `SQLBackupFunctions.ps1`).
- Determines system variables like script directory, OS information, server details, etc.
- Sets MySQL configuration file path based on operating system (`Windows` or `Linux`).
- Creates necessary directories and cleans up old files.
- Retrieves SQL service and executable details based on database type.
- Executes backup, archival, pruning, and NAS backup operations based on user configuration.
- Logs debug information, checks for updates, and sends email notifications on completion.

## Error Handling

- Logs errors encountered during script execution to `PSError.log`.
- Provides detailed debug logs (`$DBType_DEBUG-$DateString.log`).

## Script Completion

Upon completion:

- Outputs debug logs.
- Sends email notifications confirming successful or failed backup operations.
- Cleans up debug logs if empty.

## Note

- Modify paths, configurations, and behavior as per specific environment requirements.
- Ensure all dependencies and paths (`$BackupLocation`, `$NASBackupLocation`, etc.) are correctly set before executing the script.
