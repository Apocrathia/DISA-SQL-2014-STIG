 $script:LocalNames = @(".", "localhost", "127.0.0.1", "")
[System.String[]]$script:IgnoreNames = @("##*##", "NT SERVICE\*", "NT AUTHORITY\*", "sys", "INFORMATION_SCHEMA")
[System.String[]]$script:DatabaseAudits = @("SELECT", "INSERT", "UPDATE", "DELETE", "EXECUTE")
[System.String[]]$script:LogLevels = @("Always", "Never", "OnFailure", "OnSuccess")

#region Top Level Functions

Function Set-SQLInstanceStigItems {
<#
  .SYNOPSIS
   Executes all of the SQL 2014 INSTANCE STIG settings included in the module.
 
  .DESCRIPTION
   The cmdlet runs each audit and configuration setting in the module.
 
   This cmdlet will take the following actions:
 
   1) Sets permissions on the audit files identified in the database
   2) Sets permissions and auditing on the installation location of the shared files and directories
   3) Sets permissions on the directory structure holding the SQL Instance database and log files
   4) Enables the default trace
   5) Disables xp_cmdshell
   6) Renames the built in sa account
   7) Disabled the built in sa account
   8) Creates logins and builds 2 roles with those logins as members that have permissions for Instance and Database auditing respectively
   9) Creates the required auditing for the Instance and optionally on every database
   10) Creates logins and builds 4 roles with those logins as members that supplement the built in fixed roles, sysadmin, serveradmin, and dbcreator. It also creates a
    role for the CONNECT SQL permission. Any existing logins that have the permissions assigned to these roles explicity will have those permissions revoked and moved to
    the new role. Additionally, any existing logins that are members of the built in fixed roles will be moved into the new role. The 4 roles are named SYSADMIN_ROLE, SERVERADMIN_ROLE,
    DBCREATOR_ROLE, and CONNECT_SQL_ROLE. This action ignores login principals like ##*##, NT SERVICE\*, NT AUTHORITY\*, sys, and INFORMATION_SCHEMA.
   11) Forces encrypted connections, if no certificate is defined for the SQL instance, this setting is ignored
   12) Creates a job category for STIG Audits
   13) Sets the password policy and expiration for local SQL accounts, including the sa account.
 
  .PARAMETER ComputerName
   The server running the SQL instance to be configured or the virtual resource name of a clustered SQL instance. This defaults to localhost.
 
  .PARAMETER InstanceName
   The name of the instance to be configured, this defaults to the default instance name of MSSQLSERVER.
 
  .PARAMETER AuditorAdministratorsName
   The name of the user or group responsible for the audit administrator role.
 
  .PARAMETER AuditorsName
   The name of the user or group responsible for auditing databases, primarily accessing audit log files.
 
  .PARAMETER EncryptConnection
   Specifies that connections made to the SQL instance are encrypted. The SQL instance must have a trusted certificate configured for this to work.
 
  .PARAMETER Version
   The version of SQL being configured, select from either 10 (SQL 2005), 11 (SQL 2008), 12 (SQL 2014), or 13 (SQL 2016). This defaults to 12. It is used to locate the correct modules in the filesystem.
 
  .PARAMETER SqlCredential
   The credentials to use for SQL Authentication.
 
  .PARAMETER Credential
   The credential to use to connect to the host node to set the force encryption registry key.
 
  .PARAMETER Port
   The port to connect to the SQL Instance on, this defaults to using the SQL Browser service to determine the correct port for the instance.
 
  .PARAMETER SQLAdministratorsName
   The Windows User or Group that is granted full control over the SQL Instance directory structure.
 
  .PARAMETER ServerAuditor
   The Windows User or Group that is granted ALTER ANY SERVER AUDIT on the SQL Instance via role membership.
 
  .PARAMETER DatabaseAuditor
   The Windows User or Group that is granted ALTER ANY DATABASE AUDIT on every database on the SQL Instance via role membership.
 
  .PARAMETER NewSAName
   The new name to assign to the built in sa account. This defaults to xsa.
 
  .PARAMETER AuditDestination
   The destination to send audits, either the ApplicationLog, SecurityLog, or File. The are special considerations when choosing the SecurityLog option, see https://msdn.microsoft.com/en-us/library/cc645889.aspx.
    
  .PARAMETER AuditFileDestinationPath
   If the AuditDestination parameter is set to File, this is the location the audit file will be written. If the AuditDestination is set to ApplicationLog or SecurityLog, this setting is ignored.
 
  .PARAMETER SysAdminRoleMembers
   The names of Windows Users or Groups or local SQL accounts that should have a new Server Login created, if it doesn't already exist, and made a member of the new SYSADMIN role.
 
  .PARAMETER ServerAdminRoleMembers
   The names of Windows Users or Groups or local SQL accounts that should have a new Server Login created, if it doesn't already exist, and made a member of the new SERVERADMIN role.
 
  .PARAMETER DBCreatorRoleMembers
   The names of Windows Users or Groups or local SQL accounts that should have a new Server Login created, if it doesn't already exist, and made a member of the new DBCREATOR role.
 
  .PARAMETER ConnectSqlRoleMembers
   The names of Windows Users or Groups or local SQL accounts that should have a new Server Login created, if it doesn't already exist, and made a member of the new CONNECTSQL role.
 
  .PARAMETER IncludeDatabaseLevelAuditing
   This parameter specifies that all INSERT, UPDATE, SELECT, DELETE, and EXECUTE actions on every database except the master are audited. Use with caution since this will fill up the logs quickly.
 
  .PARAMETER IsManagedSQL
   This parameter specifies that the SQL Instance being STIG'd is a managed service, so the configurations at the OS level, such as file and folder permissions and auditing will not be applied.
 
  .INPUTS
   None
 
  .OUTPUTS
   None
 
        .EXAMPLE
   Set-SQLInstanceStigItems -SqlAdministratorsName "Contoso\UG-SQL-Admins" `
                        -AuditorAdministratorsName "Contoso\UG-SQL-Audit-Admins" `
                        -AuditorsName "Contoso\UG-SQL-Auditors" `
                        -ServerAuditor "Contoso\UG-SQL-ServerAuditors" `
                        -DatabaseAuditor "Contoso\UG-SQL-DatabaseAuditors" `
                        -ComputerName "SQL2014" `
                        -AuditDestination "ApplicationLog" `
                        -SysAdminRoleMembers @("Contoso\UG-SQL-DEV_001-SysAdmins") `
                        -ServerAdminRoleMembers @("Contoso\UG-SQL-DEV_001-ServerAdmins") `
                        -DBCreatorRoleMembers @("Contoso\UG-SQL-DEV_001-DBCreators") `
                        -Verbose
 
   Configures all of the settings in this module.
 
  .NOTES
   This cmdlet must be run with sysadmin permissions on the SQL instance and local admin access on the node or server supporting the instance.
    
   AUTHOR: Michael Haken
   LAST UPDATE: 5/10/2016
 
  .FUNCTIONALITY
 
   STIG
    Microsoft SQL Server 2014 Instance V1R0
   STIG ID
    SQL4-00-011300
    SQL4-00-030400
    SQL4-00-011900
    SQL4-00-012000
    SQL4-00-012100
    SQL4-00-012200
    SQL4-00-012300
    SQL4-00-012400
    SQL4-00-030600
    SQL4-00-034000
    SQL4-00-035600
    SQL4-00-037500
    SQL4-00-037600
    SQL4-00-037700
    SQL4-00-037800
    SQL4-00-037900
    SQL4-00-038000
    SQL4-00-017100
    SQL4-00-010200
    SQL4-00-017200
    SQL4-00-018700
    SQL4-00-020500
    SQL4-00-032500
    SQL4-00-033900
    SQL4-00-038900
    SQL4-00-013600
    SQL4-00-013700
    SQL4-00-013800
    SQL4-00-015350
    SQL4-00-031400
    SQL4-00-017100
 #>

[CmdletBinding()]
Param(
[Parameter(Position=0, Mandatory=$true)]
[System.String]$SQLAdministratorsName,
[Parameter(Position=1, Mandatory=$true)]
[System.String]$AuditorAdministratorsName,
[Parameter(Position=2, Mandatory=$true)]
[System.String]$AuditorsName,
[Parameter(Mandatory=$true)]
[System.String]$ServerAuditor,
[Parameter(Mandatory=$true)]
[System.String]$DatabaseAuditor,
[Parameter(Position=3)]
[System.String]$ComputerName = "localhost",
[Parameter(Position=4)]
[System.String]$InstanceName = "MSSQLSERVER",
[Parameter(Position=5)]
[switch]$EncryptConnection,
[Parameter(Position=6)]
[ValidateSet(10,11,12,13)]
[System.Int32]$Version = 12,
[Parameter()]
[System.String]$NewSAName = "xsa",
[Parameter()]
[ValidateSet("ApplicationLog","SecurityLog","File")]
[System.String]$AuditDestination,
[Parameter()]
[System.String]$AuditFileDestinationPath = [System.String]::Empty,
[Parameter()]
[System.String[]]$SysAdminRoleMembers,
[Parameter()]
[System.String[]]$ServerAdminRoleMembers,
[Parameter()]
[System.String[]]$DBCreatorRoleMembers,
[Parameter()]
[System.String[]]$ConnectSqlRoleMembers,
[Parameter()]
[switch]$IncludeDatabaseLevelAuditing,
[Parameter()]
[switch]$IsManagedSQL,
[Parameter()] 
[System.Management.Automation.PSCredential]
[System.Management.Automation.Credential()]
$Credential = [System.Management.Automation.PSCredential]::Empty,
[Parameter()] 
[System.Management.Automation.PSCredential]
[System.Management.Automation.Credential()]
$SqlCredential = [System.Management.Automation.PSCredential]::Empty,
[Parameter()]
[System.Int32]$Port = -1
)

Begin {
Import-SqlModule -Version $Version

if ($Credential -eq $null) {
$Credential = [System.Management.Automation.PSCredential]::Empty 
}

if ($SqlCredential -eq $null) {
$SqlCredential = [System.Management.Automation.PSCredential]::Empty 
}

if ([System.String]::IsNullOrEmpty($InstanceName)) {
$InstanceName = "MSSQLSERVER"
}

if ([System.String]::IsNullOrEmpty($NewSAName)) {
$NewSAName = "xsa"
}
}

Process {
$SqlServer = Get-SQLServer -ComputerName $ComputerName -InstanceName $InstanceName -Credential $SqlCredential -Port $Port

if(!$IsManagedSQL) {
Write-Verbose -Message "The instance is not Managed SQL, implementing OS level configurations."
Write-Host "Setting audit file permissions."
Set-SQLInstanceAuditFilePermissions -ComputerName $ComputerName -InstanceName $InstanceName -AuditorsName $AuditorsName -AuditorAdministratorsName $AuditorAdministratorsName

Write-Host "Setting installation directory permissions and auditing."
Set-SQLInstanceInstallationFilesPermissionsAndAuditing -ComputerName $ComputerName -InstanceName $InstanceName -InheritDefault

Write-Host "Setting database directory and file permissions."
Set-SQLInstanceDatabaseFilePermissions -ComputerName $ComputerName -InstanceName $InstanceName -SQLAdministratorsName $SQLAdministratorsName -IncludeLocalAdministrators

Write-Host "Setting force encryption."
Set-SQLInstanceForceEncryption -SqlServer $SqlServer -Enable $true -Credential $Credential
}
else {
Write-Verbose -Message "The instance is Managed SQL, not implementing OS level configurations."
}

Write-Host "Enabling default trace."
Set-SQLInstanceDefaultTrace -SqlServer $SqlServer -Enabled $true

Write-Host "Disabling xp_cmdshell."
Set-SQLInstanceXPCmdShell -SqlServer $SqlServer -Enabled $false

Write-Host "Setting auditors."
Set-SQLInstanceAuditors -SqlServer $SqlServer -ServerAuditors $ServerAuditor -DatabaseAuditors $DatabaseAuditor

Write-Host "Setting auditing."
Set-SQLInstanceAuditing -SqlServer $SqlServer -AuditName "STIG_Audit" -AuditSpecificationName "STIG_Audit_Specification" -AuditDestination $AuditDestination -FilePath $AuditDestinationPath -IncludeDatabaseLevelAudting:$IncludeDatabaseLevelAuditing

Write-Host "Setting management roles and logins."
Set-SQLInstanceManagementRoles -SqlServer $SqlServer -ConnectSqlRoleMembers $ConnectSqlRoleMembers -SysAdminRoleMembers $SysAdminRoleMembers -ServerAdminRoleMembers $ServerAdminRoleMembers -DBCreatorRoleMembers $DBCreatorRoleMembers -DefaultSysAdmins $SQLAdministratorsName

Write-Host "Creating Job Category"
New-SQLInstanceJobCategory -SqlServer $SqlServer -Name "STIG Audits"

Write-Host "Setting password polices."
Set-SQLInstanceLoginPasswordPolicies -SqlServer $SqlServer -IncludeSA

Write-Host "Renaming sa account to $NewSAName."
Rename-SQLInstanceAccount -SqlServer $SqlServer -Sid 0x01 -NewName $NewSAName

Write-Host "Disabling sa account."
Disable-SQLInstanceAccount -SqlServer $SqlServer -Sid 0x01 
}

End {
Set-Location -Path $env:SystemDrive
Write-Host "Completed STIG." -ForegroundColor Green
}
}

Function Set-SQLDatabaseStigItems {
<#
  .SYNOPSIS
   Executes all of the SQL 2014 DATABASE STIG settings included in the module.
 
  .DESCRIPTION
   This cmdlet assumes there is a Mail Profile and at least 1 Operator set up with email addresses to utilize for sending notifications from the jobs that are created.
 
   This cmdlet will take the following actions:
  
   1) Creates a job to review the default trace file for CREATE, ALTER, and DROP commands targetted at functions, the job will email the results of the query
   2) Creates a job to review the default trace file for CREATE, ALTER, and DROP commands targetted at triggers
   3) Creates a job to review the default trace file for CREATE, ALTER, and DROP commands targetted at stored procedures
   4) If the database has an owner in a built in role, and the database is set to trustworthy, disables the trustworthy setting
   5) Optionally creates a Database DDL trigger to proactively notify administrators when CREATE, ALTER, and DROP commands are issued for functions, triggers, and stored procedures
 
  .PARAMETER ComputerName
   The server running the SQL instance to be configured or the virtual resource name of a clustered SQL instance. This defaults to localhost.
 
  .PARAMETER InstanceName
   The name of the instance to be configured, this defaults to the default instance name of MSSQLSERVER.
 
  .PARAMETER DatabaseName
   The name of the database to run the commands against. In the case of the nightly jobs, these are created to run against every database and will not be recreated each time the cmdlet is run.
 
  .PARAMETER AllDatabases
   This parameter specifies that the trustworthy setting and Database DDL Trigger (if selected) should be run against every database.
 
  .PARAMETER SqlCredential
   The credentials to use for SQL Authentication.
 
  .PARAMETER Port
   The port to connect to the SQL Instance on, this defaults to using the SQL Browser service to determine the correct port for the instance.
 
  .PARAMETER OperatorToEmail
   The Operator name who has an email address configured. The email property is extracted from the Operator object and used with the sp_send_dbmail procedure to send HTML formatted emails.
   The job results and DDL Trigger notifications are sent to these email addresses.
 
  .PARAMETER JobCategory
   The Job Category name to create the 3 jobs in. The defaults to "STIG Audits".
 
  .PARAMETER AlterFunctionJobName
   The name to use when the job to monitor function modifications is created. This defaults to Alter_Function_Audit. This name is also used to name the Job Step.
   
  .PARAMETER AlterTriggerJobName
   The name to use when the job to monitor trigger modifications is created. This defaults to Alter_Trigger_Audit. This name is also used to name the Job Step.
   
  .PARAMETER AlterXPJobName
   The name to use when the job to monitor stored procedure modifications is created. This defaults to Alter_XP_Audit. This name is also used to name the Job Step.
 
  .PARAMETER JobTime
   A TimeSpan object indicating the time of day the jobs should be run. This defaults to 0200.
 
  .PARAMETER MailProfile
   The mail profile to use when sending database mail.
 
  .PARAMETER CreateAuditTrigger
   This parameter specifies that Database DDL Triggers should be created to proactively notify administrators when CREATE, ALTER, or DROP statements are executed against functions, triggers, and stored procedures.
 
   This is a much more reliable way to accomplish the intent of the scheduled jobs, but does not explicitly meet the STIG requirements. Results of the trigger are sent via HTML email.
 
  .INPUTS
   None
 
  .OUTPUTS
   None
 
  .EXAMPLE
   Set-SQLDatabaseStigItems -ComputerName "SQL2014" `
                            -AllDatabases `
                            -OperatorToEmail "Database Administrators" `
                            -MailProfile "MSSQLSERVER Profile" `
                            -Verbose
 
   Implements the database STIG against all databases in the MSSQLSERVER instance on the SQL2014 server.
 
  .EXAMPLE
   Set-SQLDatabaseStigItems -ComputerName "SQL2014" `
       -InstanceName "MyInstance" `
                            -DatabaseName "msdb" `
                            -OperatorToEmail "Database Administrators" `
                            -MailProfile "MSSQLSERVER Profile" `
                            -Verbose
 
   Implements the database STIG against the msdb database on the MyInstance instance on the SQL2014 server.
 
  .EXAMPLE
   Set-SQLDatabaseStigItems -ComputerName "SQL2014" `
                            -AllDatabases `
                            -OperatorToEmail "Database Administrators" `
                            -MailProfile "MSSQLSERVER Profile" `
       -CreateAuditTrigger `
                            -Verbose
 
   Implements the database STIG against all databases in the MSSQLSERVER instance on the SQL2014 server and creates the Database DDL Trigger on all databases.
 
  .NOTES
   This cmdlet must be run with sysadmin permissions on the SQL instance and local admin access on the node or server supporting the instance.
    
   AUTHOR: Michael Haken
   LAST UPDATE: 5/10/2016
 
  .FUNCTIONALITY
   STIG
    Microsoft SQL Server 2014 Instance V1R0
   STIG ID
    SQL4-00-014900
    SQL4-00-015100
    SQL4-00-015200
    SQL4-00-015610
    SQL4-00-015620
 #>
[CmdletBinding()]
Param(
[Parameter()]
[System.String]$ComputerName = "localhost",
[Parameter()]
[System.String]$InstanceName = "MSSQLSERVER",
[Parameter(Mandatory=$true, Position=0, ParameterSetName="DB")]
[System.String]$DatabaseName,
[Parameter(Mandatory=$true, ParameterSetName="All")]
[switch]$AllDatabases,
[Parameter(Mandatory=$true)]
[System.String]$OperatorToEmail,
[Parameter()]
[System.String]$JobCategory = "STIG Audits",
[Parameter()]
[System.String]$AlterFunctionJobName = "Alter_Function_Audit",
[Parameter()]
[System.String]$AlterTriggerJobName = "Alter_Trigger_Audit",
[Parameter()]
[System.String]$AlterXPJobName = "Alter_XP_Audit",
[Parameter()]
[System.TimeSpan]$JobTime = (New-Object -TypeName System.TimeSpan(2, 0, 0)),
[Parameter(Mandatory=$true)]
[System.String]$MailProfile,
[Parameter()]
[switch]$CreateAuditTrigger,
[Parameter()] 
[System.Management.Automation.PSCredential]
[System.Management.Automation.Credential()]
$SqlCredential = [System.Management.Automation.PSCredential]::Empty,
[Parameter()]
[System.Int32]$Port = -1
)

Begin {
if ([System.String]::IsNullOrEmpty($AlterFunctionJobName)) {
$AlterFunctionJobName = "Alter_Function_Audit"
}

if ([System.String]::IsNullOrEmpty($AlterTriggerJobName)) {
$AlterTriggerJobName = "Alter_Trigger_Audit"
}

if ([System.String]::IsNullOrEmpty($AlterXPJobName)) {
$AlterXPJobName = "Alter_XP_Audit"
}

if ($JobTime -in @($null, [System.TimeSpan]::Zero, [System.TimeSpan]::MaxValue, [System.TimeSpan]::MinValue)) {
$JobTime = New-Object -TypeName System.TimeSpan(2, 0, 0)
}
}

Process {
$SqlServer = Get-SQLServer -ComputerName $ComputerName -InstanceName $InstanceName -Port $Port -Credential $SqlCredential

[Microsoft.SqlServer.Management.Smo.Database[]]$DBs = @()

if ($AllDatabases) {
$DBs += $SqlConnection.Databases
}
else {
$DBs += ($SqlConnection.Databases | Where-Object {$_.Name -ieq $DatabaseName} | Select-Object -First 1)
}

#region STIG ID: SQL4-00-014900

if (($SqlServer.JobServer.Jobs | Where-Object {$_.Name -ieq $AlterFunctionJobName }) -eq $null) {
Write-Verbose -Message "Creating function audit command text."
$FunctionAuditCommandText = Get-SQLInstanceAuditCommandText -DaysDiff 1 `
-JobName $AlterFunctionJobName `
-OperatorToEmail $OperatorToEmail `
-EmailProfile $MailProfile `
-EmailSubject " - *Alert* FUNCTION Modification Detected" `
-ObjectToAudit Function `

Write-Verbose -Message "Creating function audit job."
$FunctionCheckJob = New-SQLAgentJob -SqlServer $SqlServer `
-Name $AlterFunctionJobName `
-Description "Daily audit to make sure no modifications to functions have been made." `
-EmailLevel Always `
-EventLogLevel OnFailure `
-NetSendLevel Never `
-PageLevel Never `
-DeleteLevel Never `
-OperatorToEmail $OperatorToEmail `
-JobCategory $JobCategory 

Write-Verbose -Message "Creating function audit job step."
$FunctionCheckJobStep = New-SQLAgentJobStep -SqlServer $SqlServer `
-Name $AlterFunctionJobName `
-Job $FunctionCheckJob `
-DatabaseName "master" `
-OnFailAction QuitWithFailure `
-OnSuccessAction QuitWithSuccess `
-RetryAttempts 0 `
-RetryInterval 0 `
-OSRunPriority 0 `
-SubSystem TransactSql `
-Command $FunctionAuditCommandText

Write-Verbose -Message "Creating function audit job schedule."
$FunctionCheckSchedule = New-SQLAgentJobSchedule -SqlServer $SqlServer `
-Name "Daily" `
-Job $FunctionCheckJob `
-ActiveStartTimeOfDay $JobTime `
-FrequencyType Daily `
-FrequencyInterval 1 
}
else {
Write-Verbose -Message "$AlterFunctionJobName job already exists."
}

#endregion

#region STIG ID: SQL4-00-015100

if (($SqlServer.JobServer.Jobs | Where-Object {$_.Name -ieq $AlterTriggerJobName }) -eq $null) {
Write-Verbose -Message "Creating trigger audit command text."
$TriggerAuditCommandText = Get-SQLInstanceAuditCommandText -DaysDiff 1 `
-JobName "Alter_Trigger_Audit" `
-OperatorToEmail $OperatorToEmail `
-EmailProfile $MailProfile `
-EmailSubject " - *Alert* TRIGGER Modification Detected" `
-ObjectToAudit Trigger `

Write-Verbose -Message "Creating trigger audit job."
$TriggerCheckJob = New-SQLAgentJob -SqlServer $SqlServer `
-Name "Alter_Trigger_Audit" `
-Description "Daily audit to make sure no modifications to triggers have been made." `
-EmailLevel Always `
-EventLogLevel OnFailure `
-NetSendLevel Never `
-PageLevel Never `
-DeleteLevel Never `
-OperatorToEmail $OperatorToEmail `
-JobCategory $JobCategory 

Write-Verbose -Message "Creating trigger audit job step."
$TriggerCheckJobStep = New-SQLAgentJobStep -SqlServer $SqlServer `
-Name $AlterTriggerJobName `
-Job $TriggerCheckJob `
-DatabaseName "master" `
-OnFailAction QuitWithFailure `
-OnSuccessAction QuitWithSuccess `
-RetryAttempts 0 `
-RetryInterval 0 `
-OSRunPriority 0 `
-SubSystem TransactSql `
-Command $TriggerAuditCommandText

Write-Verbose -Message "Creating trigger audit job schedule."
$TriggerCheckSchedule = New-SQLAgentJobSchedule -SqlServer $SqlServer `
-Name "Daily" `
-Job $TriggerCheckJob `
-ActiveStartTimeOfDay $JobTime `
-FrequencyType Daily `
-FrequencyInterval 1 
}
else {
Write-Verbose -Message "$AlterTriggerJobName job already exists."
}

#endregion

#region STIG ID: SQL4-00-015200

if (($SqlServer.JobServer.Jobs | Where-Object {$_.Name -ieq $AlterXPJobName}) -eq $null) {

Write-Verbose -Message "Creating stored procedure audit command text."
$XPAuditCommandText = Get-SQLInstanceAuditCommandText -DaysDiff 1 `
-JobName "Alter_XP_Audit" `
-OperatorToEmail $OperatorToEmail `
-EmailProfile $MailProfile `
-EmailSubject " - *Alert* STORED PROCEDURE Modification Detected" `
-ObjectToAudit Trigger `

Write-Verbose -Message "Creating stored procedure audit job."
$XPCheckJob = New-SQLAgentJob -SqlServer $SqlServer `
-Name "Alter_XP_Audit" `
-Description "Daily audit to make sure no modifications to stored procedures have been made." `
-EmailLevel Always `
-EventLogLevel OnFailure `
-NetSendLevel Never `
-PageLevel Never `
-DeleteLevel Never `
-OperatorToEmail $OperatorToEmail `
-JobCategory $JobCategory 

Write-Verbose -Message "Creating stored procedure audit job step."
$XPCheckJobStep = New-SQLAgentJobStep -SqlServer $SqlServer `
-Name $AlterXPJobName `
-Job $XPCheckJob `
-DatabaseName "master" `
-OnFailAction QuitWithFailure `
-OnSuccessAction QuitWithSuccess `
-RetryAttempts 0 `
-RetryInterval 0 `
-OSRunPriority 0 `
-SubSystem TransactSql `
-Command $XPAuditCommandText

Write-Verbose -Message "Creating stored procedure audit job schedule."
$XPCheckSchedule = New-SQLAgentJobSchedule -SqlServer $SqlServer `
-Name "Daily" `
-Job $XPCheckJob `
-ActiveStartTimeOfDay $JobTime `
-FrequencyType Daily `
-FrequencyInterval 1 
}
else {
Write-Verbose -Message "$AlterXPJobName job already exists."
}

#endregion

#region STIG ID: SQL4-00-015610, SQL4-00-015620

foreach ($Database in ($DBs | Where-Object {$_.Name -ne "msdb"})) {
[Microsoft.SqlServer.Management.Smo.ServerRole[]]$Roles = Get-SQLInstanceServerRoleMembership -SqlServer $SqlConnection -PrincipalName $Database.Owner -OnlyFixedRoles

if ($Database.Trustworthy -eq $true -and $Roles.Count -gt 0) {
Write-Verbose -Message "Database $($Database.Name) is set to Trustworthy and has an owner, $($Database.Owner), that is a member of a fixed role: $($Roles -join `",`")."
Set-SQLDatabaseTrustworthy -SqlServer $SqlConnection -DatabaseName $Database.Name -Enabled $false
}
}

#endregion

if ($CreateAuditTrigger) {
[Microsoft.SqlServer.Management.Smo.DatabaseDdlTriggerEventSet]$EventSet = New-Object -TypeName Microsoft.SqlServer.Management.Smo.DatabaseDdlTriggerEventSet
$EventSet.CreateProcedure = $true
$EventSet.AlterProcedure = $true
$EventSet.DropProcedure = $true
$EventSet.CreateFunction = $true
$EventSet.AlterFunction = $true
$EventSet.DropFunction = $true
$EventSet.CreateTrigger = $true
$EventSet.AlterTrigger = $true
$EventSet.DropTrigger = $true

foreach ($Database in $DBs) {
$Command = Get-SQLDatabaseDdlTriggerCommandText -OperatorToEmail $OperatorToEmail -Subject " $($Database.Name) - *ALERT* Object Modification Detected" -EmailProfile $MailProfile
$NewTrigger = New-SQLDatabaseDDLTrigger -SqlServer $SqlConnection -Name "AuditModificationsTrigger" -DatabaseName $Database.Name -CommandText $Command -EventSet $EventSet -ImplementationType TransactSql
}
}
}

End {
Set-Location -Path $env:SystemDrive
Write-Host "Completed STIG implementation." -ForegroundColor Green
}
}

#endregion

Function Set-SQLInstanceForceEncryption {
<#
  .SYNOPSIS
   Sets the force encryption registry key.
 
  .DESCRIPTION
   The cmdlet sets the force encryption registry key for the SQL Instance. If the Instance does not have a certificate configured and the cmdlet is enabling encryption, the setting does not get applied.
 
  .PARAMETER ComputerName
   The server running the SQL instance to be configured or the virtual resource name of a clustered SQL instance. This defaults to localhost.
 
  .PARAMETER InstanceName
   The name of the instance to be configured, this defaults to the default instance name of MSSQLSERVER.
 
  .PARAMETER SqlServer
   An existing connection to a SQL Instance using a Microsoft.SqlServer.Management.Smo.Server object.
 
  .PARAMETER Enabled
   Specifies whether force encryption should be enabled or not. Defaults to true.
 
  .PARAMETER Credential
   The credentials to use to connect to the SQL host node.
 
  .PARAMTER PassThru
   Returns an object representing the item property. By default, this cmdlet does not generate any output.
 
  .INPUTS
   None
 
  .OUTPUTS
   None or System.Management.Automation.PSCustomObject
 
        .EXAMPLE
   Set-SQLInstanceForceEncryption -ComputerName "SQL2014" -InstanceName "MyInstance" -Enabled $true
 
   Sets the force encryption key to true.
 
  .NOTES
   AUTHOR: Michael Haken
   LAST UPDATE: 5/11/2016
 
  .FUNCTIONALITY
   STIG
    Microsoft SQL Server 2014 Instance V1R0
   STIG ID
    SQL4-00-018700
   Rule ID
    SQL4-00-018700_rule
   Vuln ID
    SQL4-00-018700
   Severity
    CAT I
 #>
[CmdletBinding()]
Param(
[Parameter(ParameterSetName="NewConnection")]
        [System.String]$ComputerName = "localhost",
        [Parameter(ParameterSetName="NewConnection")]
        [System.String]$InstanceName = "MSSQLSERVER",
        [Parameter(ParameterSetName="ExistingConnection",Mandatory=$true)]
        $SqlServer,
[Parameter()]
[bool]$Enable = $true,
[Parameter()] 
[System.Management.Automation.PSCredential]
[System.Management.Automation.Credential()]
$Credential = [System.Management.Automation.PSCredential]::Empty,
[Parameter()]
[switch]$PassThru 
)

Begin {
Import-SqlModule -LoadSMO

if ($Credential -eq $null) {
$Credential = [System.Management.Automation.PSCredential]::Empty
}

if ([System.String]::IsNullOrEmpty($InstanceName)) {
$InstanceName = "MSSQLSERVER"
}

if ($SqlServer -ne $null -and $SqlServer.GetType() -ne [Microsoft.SqlServer.Management.Smo.Server]) {
            throw "SqlServer parameter must be an existing Microsoft.SqlServer.Management.Smo.Server object."
        }

Write-Verbose -Message "Setting Force Encryption."
Write-Verbose -Message "STIG ID: SQL4-00-018700"
}

Process {
if ($PSCmdlet.ParameterSetName -eq "ExistingConnection") {
            [Microsoft.SqlServer.Management.Smo.Server]$SqlConnection = $SqlServer
        }
        else {
            [Microsoft.SqlServer.Management.Smo.Server]$SqlConnection = Get-SQLServer -ComputerName $ComputerName -InstanceName $InstanceName
        }

if ($SqlConnection.NetName -iin $script:LocalNames) {
Write-Verbose -Message "Running command locally."
if ($Enable -eq $true ) {
if (![System.String]::IsNullOrEmpty((Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\$($SqlConnection.ServiceInstanceId)\MSSQLServer\SuperSocketNetLib" -Name "Certificate" | Select-Object -ExpandProperty "Certificate"))) {
$Property = Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\$($SqlConnection.ServiceInstanceId)\MSSQLServer\SuperSocketNetLib" -Name "ForceEncryption" -Value $Enable -PassThru:$PassThru
}
else {
Write-Verbose -Message "A certificate is not defined, will not force encryption."
}
}
else {
$Property = Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\$($SqlConnection.ServiceInstanceId)\MSSQLServer\SuperSocketNetLib" -Name "ForceEncryption" -Value $Enable -PassThru:$PassThru
}
}
else {
Write-Verbose -Message "Running command remotely."
$Session = New-PSSession -ComputerName $SqlConnection.NetName -Credential $Credential

try {
$Property = Invoke-Command -Session $Session -ScriptBlock { 
if ($args[2] -eq $true) {
if (![System.String]::IsNullOrEmpty((Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\$($args[0])\MSSQLServer\SuperSocketNetLib" -Name "Certificate" | Select-Object -ExpandProperty "Certificate"))) {
Write-Verbose -Message "Certificate is present."
return (Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\$($args[0])\MSSQLServer\SuperSocketNetLib" -Name "ForceEncryption" -Value $args[1] -PassThru:$args[2])
}
else {
throw "A certificate is not defined, will not force encryption."
}
}
else {
Write-Verbose -Message "Disabling forced encryption."
return (Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\$($args[0])\MSSQLServer\SuperSocketNetLib" -Name "ForceEncryption" -Value $args[1] -PassThru:$args[2])
}
} -ArgumentList @($SqlConnection.ServiceInstanceId, $Enable, $PassThru) 
}
catch [System.Exception] {
Write-Verbose -Message $_.Exception.Message
}

Remove-PSSession -Session $Session
}
}

End {
if ($PassThru) {
Write-Output $Property
}
}
}

#region Smo Functions

Function Set-SQLInstanceDatabaseFilePermissions {
<#
  .SYNOPSIS
   Access to database files must be limited to relevant processes and to authorized, administrative users.
 
  .DESCRIPTION
   The Set-DatabaseFilePermissions cmdlet sets the required security permissions for the SQL database directories and files.
 
  .PARAMETER SQLAdministratorsName
   The user or group specified as the sysadmin for the SQL instance.
 
  PARAMETER ComputerName
   The server running the SQL instance to be configured or the virtual resource name of a clustered SQL instance. This defaults to localhost.
 
  .PARAMETER InstanceName
   The name of the instance to be configured, this defaults to the default instance name of MSSQLSERVER.
 
  .PARAMETER SqlServer
   An existing connection to a SQL Instance using a Microsoft.SqlServer.Management.Smo.Server object.
 
  .PARAMETER IncludeLocalAdministrators
   Specifies that the local administrators group of the server maintaining the database shared storage should receive full control permissions.
 
        .EXAMPLE
   Set-SQLInstanceDatabaseFilePermissions -SQLAdministratorsName "UG-SQL-Admins"
          
   Configures the required permissions for the database files and directories on the MSSQLSERVER instance on the localhost.
 
  .EXAMPLE
   Set-SQLInstanceDatabaseFilePermissions -SQLAdministratorsName "UG-SQL-Admins" -ComputerName "Server01" -InstanceName "MyInstance" -IncludeLocalAdministrators
 
   Configures the required permissions for the database files and directories on the MyInstance instance on Server01 and includes the local administrators group in those permissions.
 
  .INPUTS
   None
 
  .OUTPUTS
   None
 
  .NOTES
   AUTHOR: Michael Haken
   LAST UPDATE: 5/11/2016
 
  .FUNCTIONALITY
 
   STIG
    Microsoft SQL Server 2014 Instance V1R0
   STIG ID
    SQL4-00-031400
   Rule ID
    SQL4-00-031400_rule
   Vuln ID
    SQL4-00-031400
   Severity
    CAT II
 #>

[CmdletBinding()]
Param(
[Parameter(Position=0,Mandatory=$true)]
[string]$SQLAdministratorsName,
[Parameter(ParameterSetName="NewConnection")]
        [System.String]$ComputerName = "localhost",
        [Parameter(ParameterSetName="NewConnection")]
        [System.String]$InstanceName = "MSSQLSERVER",
        [Parameter(ParameterSetName="ExistingConnection",Mandatory=$true)]
        $SqlServer,
[Parameter()]
[switch]$IncludeLocalAdministrators
)

    Begin{
Import-SqlModule -LoadSMO

if ([System.String]::IsNullOrEmpty($InstanceName)) {
$InstanceName = "MSSQLSERVER"
}

if ($SqlServer -ne $null -and $SqlServer.GetType() -ne [Microsoft.SqlServer.Management.Smo.Server]) {
            throw "SqlServer parameter must be an existing Microsoft.SqlServer.Management.Smo.Server object."
        }

Write-Verbose -Message "Setting Database File and Directory Permissions."
Write-Verbose -Message "STIG ID: SQL4-00-031400"
}

Process {
if ($PSCmdlet.ParameterSetName -eq "ExistingConnection") {
            [Microsoft.SqlServer.Management.Smo.Server]$SqlConnection = $SqlServer
        }
        else {
            [Microsoft.SqlServer.Management.Smo.Server]$SqlConnection = Get-SQLServer -ComputerName $ComputerName -InstanceName $InstanceName
        }

$Offset = 0
Write-Verbose -Message "Getting service account SID."
$ServiceAccount = $SqlConnection.Logins | Where-Object {$_.Name -eq $SqlConnection.ServiceAccount} | Select-Object -First 1 
$ServiceAccountSid = New-Object System.Security.Principal.SecurityIdentifier($ServiceAccount.Sid, $Offset)

Write-Verbose -Message "Getting SQL Agent service account SID."
$SqlAgentAccount = $SqlConnection.Logins | Where-Object {$_.Name -eq $SqlConnection.JobServer.ServiceAccount} | Select-Object -First 1

if ($SqlAgentAccount -eq $null) {
Write-Verbose -Message "The SQL Agent service account returned null, getting the account through a query."
$SqlAgentAccount = ($SqlConnection.Databases | Where-Object {$_.Name -eq "master"} | Select-Object -First 1).ExecuteWithResults("SELECT Sid FROM master.sys.dm_server_services svc JOIN master.sys.server_principals prin ON svc.service_account = prin.name WHERE svc.servicename LIKE 'SQL Server Agent%'").Tables[0] 
}

$SqlAgentAccountSid = New-Object System.Security.Principal.SecurityIdentifier([System.Byte[]]$SqlAgentAccount.Sid, $Offset)

Write-Verbose -Message "Getting $SQLAdministratorsName SID."	
$SQLAdministratorsSid = Get-AccountSid -UserName $SQLAdministratorsName	

Write-Verbose -Message "Creating access rules."
$AccessRules = New-SQLInstanceDatabaseDirectoryAccessRuleSet -SqlServiceAccountSid $ServiceAccountSid -SqlAgentSid $SqlAgentAccountSid -AdministratorsSid $SQLAdministratorsSid -IncludeLocalAdministrators

Write-Verbose -Message "Getting data directories."
$DataDir = $SqlConnection.DefaultFile
$LogDir = $SqlConnection.DefaultLog
$BackupDir = $SqlConnection.BackupDirectory
$RootDir = $SqlConnection.RootDirectory
$TempDBDir = $SqlConnection.Databases | Where-Object {$_.Name -eq "tempdb"} | Select-Object -First 1 | Select-Object -ExpandProperty PrimaryFilePath

$DataDirectories = @($DataDir, $LogDir, $BackupDir, $RootDir, $TempDBDir)
$DataDirectories = $DataDirectories | Select-Object -Unique

Write-Verbose -Message "Removing child directories from the list of directories."
$FinalDirs = @()

foreach ($Dir in $DataDirectories) {
$ShouldAdd = $true
foreach ($OtherDir in ($DataDirectories | Where-Object {$_ -ne $Dir })) {
if ($Dir.StartsWith($OtherDir, [System.StringComparison]::OrdinalIgnoreCase)) {
$ShouldAdd = $false
break
}
}
if ($ShouldAdd) {
Write-Verbose -Message "Unique parent path $Dir."
$FinalDirs += $Dir
}
else {
Write-Verbose -Message "Removing $Dir, it is a child of another data directory."
}
}

#$DataDirectories = Get-SQLInstanceDataDirectories -InstanceName $InstanceName -ComputerName $ComputerName -EncryptConnection:$EncryptConnection -Credential $Credential

Write-Verbose -Message "Transforming directories."
$ComputerName = $SqlConnection.NetName
foreach ($Directory in $FinalDirs) {
if (!$Directory.StartsWith("\\") -and $ComputerName -notin $script:LocalNames) {
$Directory = $Directory.Replace(":","`$")
$Directory = "\\$ComputerName\$Directory"
}

Set-FilePermissions -Path $Directory -Rules $AccessRules -Replace -ForceInheritance
}

<#Get-Member -InputObject $DataDirectories -MemberType Properties | ForEach-Object {
   $Path = $DataDirectories."$($_.Name)"
 
   if (!$Path.StartsWith("\\") -and $ComputerName -notin $script:LocalNames) {
    $Path = $Path.Replace(":","`$")
    $Path = "\\$ComputerName\$Path"
   }
    
   Set-FilePermissions -Path $Path -Rules $AccessRules -Replace -ForceInheritance
  }#>
}

End {
Write-Verbose -Message "Completed setting database folder and file permissions."
}
}

Function Set-SQLInstanceInstallationFilesPermissionsAndAuditing{
<#
  .SYNOPSIS
   Software, applications, and configuration files that are part of, or related to, the SQL Server installation must be monitored to discover unauthorized changes.
 
  .DESCRIPTION
   The Set-SQLInstanceInstallationFilesPermissionsAndAudting cmdlet sets the required security permissions for the SQL installation and auditing.
 
  .PARAMETER ComputerName
   The server running the SQL instance to be configured or the virtual resource name of a clustered SQL instance. This defaults to localhost.
 
  .PARAMETER InstanceName
   The name of the instance to be configured, this defaults to the default instance name of MSSQLSERVER.
  
  .PARAMETER SqlServer
   An existing connection to a SQL Instance using a Microsoft.SqlServer.Management.Smo.Server object.
 
  .PARAMETER InheritDefault
   Alternatively reset inherited permissions from the parent directory, this is typically sufficient if the installation directory was set under $env:ProgramFiles
 
  .PARAMETER Replace
   Replace all permissions of the installation directory, subfolders, and files instead of re-inheriting default permissions.
 
        .EXAMPLE
   Set-SQLInstanceInstallationFilesPermissionsAndAuditing -ComputerName "SQL2014" -InstanceName "MyInstance"
          
   Configures the required permissions for the audit logs by forcing inheriting the default permissions.
 
  .EXAMPLE
   Set-SQLInstanceInstallationFilesPermissionsAndAuditing -ComputerName "SQL2014" -InstanceName "MyInstance" -Replace
          
   Configures the required permissions for the audit logs by replacing existing permissions with a new permission set.
 
  .INPUTS
   None
 
  .OUTPUTS
   None
 
  .NOTES
   AUTHOR: Michael Haken
   LAST UPDATE: 5/11/2016
 
  .FUNCTIONALITY
   STIG
    Microsoft SQL Server 2014 Instance V1R0
   STIG ID
    SQL4-00-015350
   Rule ID
    SQL4-00-015350_rule
   Vuln ID
    SQL4-00-015350
   Severity
    CAT I
 #>

[CmdletBinding(DefaultParameterSetName = "ExistingConnectionWithInherit")]
Param(
[Parameter(ParameterSetName="NewConnectionWithReplace")]
[Parameter(ParameterSetName="NewConnectionWithInherit")]
        [System.String]$ComputerName = "localhost",
        [Parameter(ParameterSetName="NewConnectionWithReplace")]
[Parameter(ParameterSetName="NewConnectionWithInherit")]
        [System.String]$InstanceName = "MSSQLSERVER",
        [Parameter(ParameterSetName="ExistingConnectionWithReplace",Mandatory=$true)]
[Parameter(ParameterSetName="ExistingConnectionWithInherit",Mandatory=$true)]
        $SqlServer,
[Parameter(ParameterSetName="NewConnectionWithReplace", Mandatory=$true)]
[Parameter(ParameterSetName="ExistingConnectionWithReplace",Mandatory=$true)]
[switch]$Replace,
[Parameter(ParameterSetName="NewConnectionWithInherit")]
[Parameter(ParameterSetName="ExistingConnectionWithInherit")]
[switch]$InheritDefault
)

Begin {
Import-SqlModule -LoadSMO

if ([System.String]::IsNullOrEmpty($InstanceName)) {
$InstanceName = "MSSQLSERVER"
}

if ($SqlServer -ne $null -and $SqlServer.GetType() -ne [Microsoft.SqlServer.Management.Smo.Server]) {
            throw "SqlServer parameter must be an existing Microsoft.SqlServer.Management.Smo.Server object."
        }

Write-Verbose -Message "Setting Installation Directory Permissions."
Write-Verbose -Message "STIG ID: SQL4-00-015350"       
    }

    Process
    {
if ($PSCmdlet.ParameterSetName -eq "ExistingConnection") {
            [Microsoft.SqlServer.Management.Smo.Server]$SqlConnection = $SqlServer
        }
        else {
            [Microsoft.SqlServer.Management.Smo.Server]$SqlConnection = Get-SQLServer -ComputerName $ComputerName -InstanceName $InstanceName
        }

#$Path = (Get-SQLInstanceDetails -ComputerName $ComputerName -InstanceName $InstanceName -EncryptConnection:$EncryptConnection -Credential $Credential).InstallationPath

Write-Verbose -Message "Getting installation directory."
$Path = [System.IO.Directory]::GetParent($SqlConnection.InstallDataDirectory) | Select-Object -ExpandProperty FullName

Write-Verbose -Message "Transforming path."
$ComputerName = $SqlConnection.NetName
if (!$Path.StartsWith("\\") -and $ComputerName -notin $script:LocalNames) {
$Path = $Path.Replace(":","`$")
$Path = "\\$ComputerName\$Path"
}

switch -wildcard ($PSCmdlet.ParameterSetName) {
"*Replace" {
Write-Verbose -Message "Replacing current file permissions on $Path and forcing inheritance."
$AccessRules = New-SQLInstanceInstallationDirectoryAccessRuleSet
Set-FilePermissions -Path $Path -Rules $AccessRules -Replace:$Replace -ForceInheritance
break
}
"*Inherit" {
Write-Verbose -Message "Resetting inheritance on $Path."
Reset-InheritedPermissions -Path $Path
break
}
default {
throw "Could not determine parameter set name."
}
}

Write-Verbose -Message "Creating audit rules."
$AuditRules = New-SQLInstanceInstallationDirectoryAuditRuleSet

Write-Verbose -Message "Setting audit rules on $Path."
Set-Auditing -Path $Path -AuditRules $AuditRules
}

End {
Write-Verbose -Message "Completed setting installation directory permissions."
}
}

Function Set-SQLInstanceAuditFilePermissions {
<#
  .SYNOPSIS
   The audit information produced by SQL Server must be protected from unauthorized read access.
 
  .DESCRIPTION
   The Set-SQLInstanceAuditFilePermissions cmdlet sets the required security permissions for the SQL audit log files.
 
  .PARAMETER ComputerName
   The server running the SQL instance to be configured or the virtual resource name of a clustered SQL instance. This defaults to localhost.
 
  .PARAMETER InstanceName
   The name of the instance to be configured, this defaults to the default instance name of MSSQLSERVER.
 
  .PARAMETER SqlServer
   An existing connection to a SQL Instance using a Microsoft.SqlServer.Management.Smo.Server object.
 
  .PARAMETER AuditorAdministratorsName
   The name of the user or group responsible for the audit administrator role.
 
  .PARAMETER AuditorsName
   The name of the user or group responsible for auditing the database, primarily accessing audit log files.
 
        .EXAMPLE
   Set-SQLInstanceAuditFilePermissions -AuditAdministratorsName "UG-SQL-Audit-Admins" -AuditorsName "UG-SQL-Auditors"
          
   Configures the required permissions for the audit logs on the localhost for the default MSSQLSERVER instance.
 
  .INPUTS
   None
 
  .OUTPUTS
   None
 
  .NOTES
   AUTHOR: Michael Haken
   LAST UPDATE: 5/11/2016
 
  .FUNCTIONALITY
 
   STIG
    Microsoft SQL Server 2014 Instance V1R0
   STIG ID
    SQL4-00-013600
    SQL4-00-013700
    SQL4-00-013800
   Rule ID
    SQL4-00-013600_rule
    SQL4-00-013700_rule
    SQL4-00-013800_rule
   Vuln ID
    SQL4-00-013600
    SQL4-00-013700
    SQL4-00-013800
   Severity
    CAT II
    CAT III
    CAT III
 #>

[CmdletBinding()]
Param(
[Parameter(Position=0,Mandatory=$true)]
[string]$AuditorAdministratorsName,
[Parameter(Position=1, Mandatory=$true)]
[string]$AuditorsName,
[Parameter(ParameterSetName="NewConnection")]
        [System.String]$ComputerName = "localhost",
        [Parameter(ParameterSetName="NewConnection")]
        [System.String]$InstanceName = "MSSQLSERVER",
        [Parameter(ParameterSetName="ExistingConnection",Mandatory=$true)]
        $SqlServer
)

    Begin
    {
Import-SqlModule -LoadSMO

if ([System.String]::IsNullOrEmpty($InstanceName)) {
$InstanceName = "MSSQLSERVER"
}

if ($SqlServer -ne $null -and $SqlServer.GetType() -ne [Microsoft.SqlServer.Management.Smo.Server]) {
            throw "SqlServer parameter must be an existing Microsoft.SqlServer.Management.Smo.Server object."
        }

Write-Verbose -Message "Setting Audit File Permissions."
Write-Verbose -Message "STIG IDs: SQL4-00-013600, SQL4-00-013700, SQL4-00-013800"       
    }

    Process
    {
if ($PSCmdlet.ParameterSetName -eq "ExistingConnection") {
            [Microsoft.SqlServer.Management.Smo.Server]$SqlConnection = $SqlServer
        }
        else {
            [Microsoft.SqlServer.Management.Smo.Server]$SqlConnection = Get-SQLServer -ComputerName $ComputerName -InstanceName $InstanceName
        }

<#if ($InstanceName -ieq "mssqlserver") {
   $InstanceServiceName = $InstanceName
   $SqlAgentService = "SQLSERVERAGENT"
  }
  else {
   $InstanceServiceName = "MSSQL`$$InstanceName"
   $SqlAgentService = "SQLAgent`$$InstanceName"
  }
 
  if ($ComputerName -iin $script:LocalNames) {
   $SqlServiceAccount = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$InstanceServiceName" -Name "ObjectName" | Select-Object -ExpandProperty ObjectName
   $SqlAgentServiceAccount = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$SqlAgentService" -Name "ObjectName" | Select-Object -ExpandProperty ObjectName
  }
  else {
   $Session = New-PSSession -ComputerName $ComputerName -Credential $Credential
   $SqlServiceAccount = Invoke-Command -Session $Session -ScriptBlock { Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$($args[0])" -Name "ObjectName" | Select-Object -ExpandProperty ObjectName } -ArgumentList @($InstanceServiceName)
   $SqlAgentServiceAccount = Invoke-Command -ComputerName $ComputerName -ScriptBlock { Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$($args[0])" -Name "ObjectName" | Select-Object -ExpandProperty ObjectName } -ArgumentList @($SqlAgentService)
   Remove-PSSession -Session $Session
  }
 
  $ServiceAccountSid = Get-AccountSid -UserName $SqlServiceAccount -ComputerName $ComputerName -Credential $Credential
  $SqlAgentAccountSid = Get-AccountSid -UserName $SqlAgentServiceAccount -ComputerName $ComputerName -Credential $Credential
  #>

$Offset = 0
Write-Verbose -Message "Getting service account SID."
$ServiceAccount = $SqlConnection.Logins | Where-Object {$_.Name -eq $SqlConnection.ServiceAccount} | Select-Object -First 1 
$ServiceAccountSid = New-Object System.Security.Principal.SecurityIdentifier($ServiceAccount.Sid, $Offset)

Write-Verbose -Message "Getting SQL Agent service account SID."
$SqlAgentAccount = $SqlConnection.Logins | Where-Object {$_.Name -eq $SqlConnection.JobServer.ServiceAccount} | Select-Object -First 1

if ($SqlAgentAccount -eq $null) {
Write-Verbose -Message "The SQL Agent service account returned null, getting the account through a query."
$SqlAgentAccount = ($SqlConnection.Databases | Where-Object {$_.Name -eq "master"} | Select-Object -First 1).ExecuteWithResults("SELECT Sid FROM master.sys.dm_server_services svc JOIN master.sys.server_principals prin ON svc.service_account = prin.name WHERE svc.servicename LIKE 'SQL Server Agent%'").Tables[0] 
}

$SqlAgentAccountSid = New-Object System.Security.Principal.SecurityIdentifier([System.Byte[]]$SqlAgentAccount.Sid, $Offset)

Write-Verbose -Message "Getting audit administrators SID."
$AuditAdministratorsSid = Get-AccountSid -UserName $AuditorAdministratorsName

Write-Verbose -Message "Getting auditors SID."
$AuditorsSid = Get-AccountSid -UserName $AuditorsName

Write-Verbose -Message "Building access rules."
$AccessRules = New-SQLInstanceAuditLogAccessRuleSet -SqlServiceAccountSid $ServiceAccountSid -SqlAgentSid $SqlAgentAccountSid -AuditAdministratorSid $AuditAdministratorsSid -AuditorsSid $AuditorsSid

Write-Verbose -Message "Getting error log path."
$Directory = Get-SQLInstanceErrorLogPath -ComputerName $ComputerName -InstanceName $InstanceName

Write-Verbose -Message "Transforming error log path."
$ComputerName = $SqlConnection.NetName
if (!$Directory.StartsWith("\\") -and $ComputerName -inotin $script:LocalNames) {
$Directory = $Directory.Replace(":\","`$\")
$Directory = "\\$ComputerName\$Directory"
}

Write-Verbose -Message "Setting file permissions on $Directory."
Set-FilePermissions -Path $Directory -Rules $AccessRules -Replace -ForceInheritance
}

    End{
Write-Verbose -Message "Completed setting audit file permissions."
}
}

Function Set-SQLInstanceAuditors {
<#
  .SYNOPSIS
   SQL Server must allow only the ISSM (or individuals or roles appointed by the ISSM) to select which auditable events are to be audited or traced.
 
  .DESCRIPTION
   The Set-SQLInstanceAuditors cmdlet creates logins for specified auditor Windows Groups, creates 2 roles, one for Server level auditing, and one for Database level auditing, grants them permissions
   and adds the new logins to the respective groups.
 
   Users or roles with existing ALTER ANY SERVER AUDIT or ALTER ANY DATABASE AUDIT permissions at the server or database level will have those privileges removed.
 
  .PARAMETER ComputerName
   The server running the SQL instance to be configured or the virtual resource name of a clustered SQL instance. This defaults to localhost.
 
  .PARAMETER InstanceName
   The name of the instance to be configured, this defaults to the default instance name of MSSQLSERVER.
  
  .PARAMETER SqlServer
   An existing connection to a SQL Instance using a Microsoft.SqlServer.Management.Smo.Server object.
 
  .PARAMETER ServerAuditorsRole
   The name of the role to be created for managing server level audits. Will be granted ALTER ANY SERVER AUDIT. Defaults to SERVER_AUDIT_MAINTAINERS.
 
  .PARAMETER DatabaseAuditorsRole
   The name of the role to be created for managing database level audits. Will be granted ALTER ANY DATABASE AUDIT on every existing database. Defaults to DATABASE_AUDIT_MAINTAINERS.
 
  .PARAMETER ServerAuditors
   The Windows user or Group that will have a login created and added to the new Server Auditors Role.
 
  .PARMETER DatabaseAuditors
   The Windows user or Group that will have a login created, then have a Database User created on every existing database, and added to the new Database Auditors Role.
 
        .EXAMPLE
   Set-SQLInstanceAuditors -ComputerName "SQL2014" -InstanceName "MyInstance" -ServerAuditors "Contoso\UG-SQL-Server-Auditors" -DatabaseAuditors "Contoso\UG-SQL-Database-Auditors"
          
   Creates logins for Contoso\UG-SQL-Server-Auditors and Contoso\UG-SQL-Database-Auditors. Creates the SERVER_AUDIT_MAINTAINERS and DATABASE_AUDIT_MAINTAINERS roles.
   Grants the required permissions to those roles. Adds a database user on each database for Contoso\UG-SQL-Database-Auditors. Remove existing privileges from other accounts and roles.
 
  .INPUTS
   None
 
  .OUTPUTS
   None
 
  .NOTES
   AUTHOR: Michael Haken
   LAST UPDATE: 5/11/2016
 
  .FUNCTIONALITY
   STIG
    Microsoft SQL Server 2014 Instance V1R0
   STIG ID
    SQL4-00-011300
   Rule ID
    SQL4-00-011300_rule
   Vuln ID
    SQL4-00-011300
   Severity
    CAT II
 #>
    [CmdletBinding()]
    Param(
        [Parameter(ParameterSetName="NewConnection")]
        [System.String]$ComputerName = "localhost",
        [Parameter(ParameterSetName="NewConnection")]
        [System.String]$InstanceName = "MSSQLSERVER",
        [Parameter(ParameterSetName="ExistingConnection",Mandatory=$true)]
        $SqlServer,
        [Parameter()]
        [System.String]$ServerAuditorsRole = "SERVER_AUDIT_MAINTAINERS",
        [Parameter()]
        [System.String]$DatabaseAuditorsRole = "DATABASE_AUDIT_MAINTAINERS",
        [Parameter(Mandatory=$true)]
        [System.String]$ServerAuditors,
        [Parameter(Mandatory=$true)]
        [System.String]$DatabaseAuditors
    )

    Begin {
        Import-SqlModule -LoadSMO

if ([System.String]::IsNullOrEmpty($InstanceName)) {
$InstanceName = "MSSQLSERVER"
}

        if ($SqlServer -ne $null -and $SqlServer.GetType() -ne [Microsoft.SqlServer.Management.Smo.Server]) {
            throw "SqlServer parameter must be an existing Microsoft.SqlServer.Management.Smo.Server object."
        }

if ([System.String]::IsNullOrEmpty($ServerAuditorsRole)) {
$ServerAuditorsRole = "SERVER_AUDIT_MAINTAINERS"
}

if ([System.String]::IsNullOrEmpty($DatabaseAuditorsRole)) {
$DatabaseAuditorsRole = "DATABASE_AUDIT_MAINTAINERS"
}

Write-Verbose -Message "Setting SQL Instance and Database Auditors."
Write-Verbose -Message "STIG ID: SQL4-00-015350"
    }

    Process {
        if ($PSCmdlet.ParameterSetName -eq "ExistingConnection") {
            [Microsoft.SqlServer.Management.Smo.Server]$SqlConnection = $SqlServer
        }
        else {
            [Microsoft.SqlServer.Management.Smo.Server]$SqlConnection = Get-SQLServer -ComputerName $ComputerName -InstanceName $InstanceName
        }

[System.String[]]$Roles = $SqlConnection.Roles | Where-Object {$_.IsFixedRole -eq $false } | Select-Object -ExpandProperty Name
[System.String[]]$Logins = $SqlConnection.Logins | Where-NotMatchIn -Matches $script:IgnoreNames -Property "Name" | Select-Object -ExpandProperty Name

        [System.String[]]$NewLogins = @($ServerAuditors, $DatabaseAuditors)
        [System.String[]]$NewRoles = @($ServerAuditorsRole, $DatabaseAuditorsRole)

        foreach ($Login in $NewLogins) {
if ($SqlConnection.Settings.LoginMode -eq [Microsoft.SqlServer.Management.Smo.ServerLoginMode]::Mixed -or $SqlConnection.Settings.LoginMode -eq [Microsoft.SqlServer.Management.Smo.ServerLoginMode]::Normal) {

if ($Login -like "*\*") {
Write-Verbose -Message "$Login matches domain account structure."
Add-SQLInstanceLogin -SqlServer $SqlConnection -Name $Login -LoginType WindowsUser
}
else {
Write-Verbose -Message "$Login will be created as a Sql user."
Add-SQLInstanceLogin -SqlServer $SqlConnection -Name $Login -LoginType SqlLogin
}
}
else {
Write-Verbose -Message "SQL Authentication is not enabled, $Login being created as a windows user."
Add-SQLInstanceLogin -SqlServer $SqlConnection -Name $Login -LoginType WindowsUser
}
        }

        [System.String]$Role = ""

Add-SQLInstanceServerRole -SqlServer $SqlConnection -Name $ServerAuditorsRole

        $Principals = @()
$Principals += $Logins
$Principals += $Roles

        foreach ($Principal in $Principals) {
Write-Verbose -Message "Reviewing ALTER ANY SERVER AUDIT permissions for $Principal."
            [Microsoft.SqlServer.Management.Smo.ServerPermissionInfo[]]$Permissions = $SqlConnection.EnumServerPermissions($Principal)
    
            #PermissionType is a ServerPermissionSet object. The ServerPermissionSet object has properties that
            #correspond to the different permissions
            foreach ($ServerPermissionSet in $Permissions | Select-Object -ExpandProperty PermissionType) {
                if ($ServerPermissionSet.AlterAnyServerAudit -eq $true) {
                    Write-Verbose -Message "Revoking ALTER ANY SERVER AUDIT from $Principal."
                    $SqlConnection.Revoke([Microsoft.SqlServer.Management.Smo.ServerPermission]::AlterAnyServerAudit, $Principal)
                }
            }
        }

        Write-Verbose -Message "Granting ALTER ANY SERVER AUDIT to $ServerAuditorsRole."
        $SqlConnection.Grant([Microsoft.SqlServer.Management.Smo.ServerPermission]::AlterAnyServerAudit, $ServerAuditorsRole)

        Write-Verbose -Message "Adding $ServerAuditors to $ServerAuditorsRole."
        [Microsoft.SqlServer.Management.Smo.ServerRole]$SrvAuditorRole = $SqlConnection.Roles | Where-Object {$_.Name -eq $ServerAuditorsRole} | Select-Object -First 1
        $SrvAuditorRole.AddMember($ServerAuditors)

        foreach ($Database in $SqlConnection.Databases) {
            $DatabaseRoles = $Database.Roles | Where-Object { $_.IsFixedRole -eq $false } | Select-Object -ExpandProperty Name 
            $DatabaseUsers = $Database.Users | Where-NotMatchIn -Matches $script:IgnoreNames -Property "Name" | Select-Object -ExpandProperty Name

            [System.String[]]$Principals = @()
            $Principals += $DatabaseRoles
            $Principals += $DatabaseUsers

            foreach ($Principal in ($Principals | Where-Object {$_ -inotin @($ServerAuditorsRole, $DatabaseAuditorsRole)} )) {

                [Microsoft.SqlServer.Management.Smo.DatabasePermissionInfo[]]$DatabasePermissions = $Database.EnumDatabasePermissions($Principal) 

                foreach ($DatabasePermissionSet in $DatabasePermissions | Select-Object -ExpandProperty PermissionType) {
                    if ($DatabasePermissionSet.AlterAnyDatabaseAudit -eq $true) {
                        Write-Verbose -Message "Revoking ALTER ANY DATABASE AUDIT from $Principal."
                        $Database.Revoke([Microsoft.SqlServer.Management.Smo.DatabasePermission]::AlterAnyDatabaseAudit, $Principal)
                    }
                }
            }

            if ($DatabaseUsers -inotcontains $DatabaseAuditors) {
                Write-Verbose -Message "Creating database user for $DatabaseAuditors."
                [Microsoft.SqlServer.Management.Smo.User]$NewUser = New-Object Microsoft.SqlServer.Management.Smo.User($Database, $DatabaseAuditors)

try {
$NewUser.Create()
}
catch [Exception] {
if ($_.Exception.InnerException -ne $null) {
$Exception = $_.Exception
while ($Exception.InnerException -ne $null) {                      
$Exception = $Exception.InnerException
}

throw $Exception
}
else {
throw $_.Exception
}
}
            }
            else {
                Write-Verbose -Message "Database $($Database.Name) already contains a user for $DatabaseAuditors."
            }
            
            if ($DatabaseRoles -inotcontains $DatabaseAuditorsRole) {
                Write-Verbose -Message "Creating role $DatabaseAuditorsRole in database $($Database.Name)."
                [Microsoft.SqlServer.Management.Smo.DatabaseRole]$NewRole = New-Object Microsoft.SqlServer.Management.Smo.DatabaseRole($Database, $DatabaseAuditorsRole)
                
try {
$NewRole.Create()
}
catch [Exception] {
if ($_.Exception.InnerException -ne $null) {
$Exception = $_.Exception
while ($Exception.InnerException -ne $null) {                      
$Exception = $Exception.InnerException
}

throw $Exception
}
else {
throw $_.Exception
}
}
            }
            else {
                Write-Verbose -Message "Database $($Database.Name) already contains the role $DatabaseAuditorsRole."
            }

            Write-Verbose -Message "Granting ALTER ANY DATABASE AUDIT to $DatabaseAuditorsRole on $($Database.Name)."
            $Database.Grant([Microsoft.SqlServer.Management.Smo.DatabasePermission]::AlterAnyDatabaseAudit, $DatabaseAuditorsRole)

            Write-Verbose -Message "Adding $DatabaseAuditors to $DatabaseAuditorsRole in database $($Database.Name)."
            [Microsoft.SqlServer.Management.Smo.DatabaseRole]$DdAuditorsRole = $Database.Roles | Where-Object {$_.Name -eq $DatabaseAuditorsRole} | Select-Object -First 1
            $DdAuditorsRole.AddMember($DatabaseAuditors)
        }
    }

    End {
    }
}

Function Set-SQLInstanceAuditing {
<#
  .SYNOPSIS
   SQL Server must generate trace or audit records on numerous actions.
 
  .DESCRIPTION
   The Set-SQLInstanceAuditing cmdlet creates an audit and an audit specification to audit all required events. It can optionally be set to include database level auditing, in which case it will also
   audit all SELECT, INSERT, UPDATE, DROP, and EXECUTE commands on every database. Use caution with this option as it will fill up logs quickly and is not required for all data per the STIG.
 
  .PARAMETER ComputerName
   The server running the SQL instance to be configured or the virtual resource name of a clustered SQL instance. This defaults to localhost.
 
  .PARAMETER InstanceName
   The name of the instance to be configured, this defaults to the default instance name of MSSQLSERVER.
  
  .PARAMETER SqlServer
   An existing connection to a SQL Instance using a Microsoft.SqlServer.Management.Smo.Server object.
 
  .PARAMETER AuditName
   The name of the audit to create. This defaults to STIG_Audit
 
  .PARAMETER AuditSpecificationName
   The name of the audit specification to create. This defaults to STIG_Audit_Specification.
 
  .PARAMETER AuditDestination
   The audit events can either be written to the Application Log, Security Log, or a Log File. Specify ApplicationLog, SecurityLog, or File. If the File option is selected, the FilePath parameter
   can also be used. The ApplicationLog is the default destination.
 
   Special considerations should be used when writing to the Security Log, see https://msdn.microsoft.com/en-us/library/cc645889.aspx for more details.
 
  .PARAMETER FilePath
   If the audit events are written to a file, you can specify the file they are written to. This defaults to "$env:SYSTEMROOT\Program Files\Microsoft SQL Server\Logs\AuditLog.trc".
 
   If ApplicationLog or SecurityLog are selected, this parameter is ignored.
 
  .PARMETER IncludeDatabaseLevelAudting
   This parameter specifies that all INSERT, UPDATE, SELECT, DELETE, and EXECUTE actions on every database except the master are audited. Use with caution since this will fill up the logs quickly.
 
  .PARAMTER PassThru
   Returns an object representing the item property. By default, this cmdlet does not generate any output.
 
        .EXAMPLE
   Set-SQLInstanceAuditing -ComputerName "SQL2014" -InstanceName "MyInstance"
          
   Configures the auditing on the SQL Instance and writes the audits to the Application Log.
 
  .INPUTS
   None
 
  .OUTPUTS
   None or Microsoft.SqlServer.Management.Smo.Audit
 
  .NOTES
   AUTHOR: Michael Haken
   LAST UPDATE: 5/11/2016
 
  .FUNCTIONALITY
   STIG
    Microsoft SQL Server 2014 Instance V1R0
   STIG ID
    SQL4-00-030400
    SQL4-00-011900
    SQL4-00-012000
    SQL4-00-012100
    SQL4-00-012200
    SQL4-00-012300
    SQL4-00-012400
    SQL4-00-030600
    SQL4-00-034000
    SQL4-00-035600
    SQL4-00-037500
    SQL4-00-037600
    SQL4-00-037700
    SQL4-00-037800
    SQL4-00-037900
    SQL4-00-038000
   Rule ID
    SQL4-00-030400_rule
    SQL4-00-011900_rule
    SQL4-00-012000_rule
    SQL4-00-012100_rule
    SQL4-00-012200_rule
    SQL4-00-012300_rule
    SQL4-00-012400_rule
    SQL4-00-030600_rule
    SQL4-00-034000_rule
    SQL4-00-035600_rule
    SQL4-00-037500_rule
    SQL4-00-037600_rule
    SQL4-00-037700_rule
    SQL4-00-037800_rule
    SQL4-00-037900_rule
    SQL4-00-038000_rule
   Vuln ID
    SQL4-00-030400
    SQL4-00-011900
    SQL4-00-012000
    SQL4-00-012100
    SQL4-00-012200
    SQL4-00-012300
    SQL4-00-012400
    SQL4-00-030600
    SQL4-00-034000
    SQL4-00-035600
    SQL4-00-037500
    SQL4-00-037600
    SQL4-00-037700
    SQL4-00-037800
    SQL4-00-037900
    SQL4-00-038000
   Severity
    CAT II
 #>
    [CmdletBinding()]
    Param(
        [Parameter(ParameterSetName="NewConnection")]
        [System.String]$ComputerName = "localhost",
        [Parameter(ParameterSetName="NewConnection")]
        [System.String]$InstanceName = "MSSQLSERVER",
        [Parameter(ParameterSetName="ExistingConnection",Mandatory=$true)]
        $SqlServer = $null,
        [Parameter()]
        [System.String]$AuditName = "STIG_Audit",
        [Parameter()]
        [System.String]$AuditSpecificationName = "STIG_Audit_Specification",
        [Parameter()]
        [ValidateSet("ApplicationLog", "SecurityLog", "File")]
        [System.String]$AuditDestination = "ApplicationLog",
        [Parameter()]
        [System.String]$FilePath = "$env:SYSTEMROOT\Program Files\Microsoft SQL Server\Logs\AuditLog.trc",
        [Parameter()]
[switch]$IncludeDatabaseLevelAudting,
        [Parameter()]
        [switch]$PassThru
    )

    Begin{
        Import-SqlModule -LoadSMO

if ([System.String]::IsNullOrEmpty($InstanceName)) {
$InstanceName = "MSSQLSERVER"
}

        if ($SqlServer -ne $null -and $SqlServer.GetType() -ne [Microsoft.SqlServer.Management.Smo.Server]) {
            throw "SqlServer parameter must be an existing Microsoft.SqlServer.Management.Smo.Server object."
        }

Write-Verbose -Message "Setting SQL Instance Auditing."
Write-Verbose -Message "STIG ID: SQL4-00-030400, SQL4-00-011900, SQL4-00-012000, SQL4-00-012100, SQL4-00-012200, SQL4-00-012300, SQL4-00-012400, SQL4-00-030600, SQL4-00-034000, SQL4-00-035600, SQL4-00-037500, SQL4-00-037600, SQL4-00-037700, SQL4-00-037800, SQL4-00-037900, SQL4-00-038000"
    }

    Process {
        if ($PSCmdlet.ParameterSetName -eq "ExistingConnection") {
            [Microsoft.SqlServer.Management.Smo.Server]$SqlConnection = $SqlServer
        }
        else {
            [Microsoft.SqlServer.Management.Smo.Server]$SqlConnection = Get-SQLServer -ComputerName $ComputerName -InstanceName $InstanceName
        }

        if (($SqlConnection.Audits | Where-Object {$_.Name -ieq $AuditName}) -eq $null) {
            Write-Verbose -Message "Creating audit $AuditName."

            [Microsoft.SqlServer.Management.Smo.Audit]$ServerAudit = New-Object Microsoft.SqlServer.Management.Smo.Audit($SqlConnection, $AuditName)
            $ServerAudit.OnFailure = [Microsoft.SqlServer.Management.Smo.OnFailureAction]::Continue
            switch ($AuditDestination) {
                "ApplicationLog" {
                    $ServerAudit.DestinationType = [Microsoft.SqlServer.Management.Smo.AuditDestinationType]::ApplicationLog
                    break
                }
                "SecurityLog" {
                    $ServerAudit.DestinationType = [Microsoft.SqlServer.Management.Smo.AuditDestinationType]::SecurityLog
                    break
                }
                "File" {
                    $ServerAudit.DestinationType = [Microsoft.SqlServer.Management.Smo.AuditDestinationType]::File
                    $ServerAudit.FilePath = $FilePath
                    break
                }
            }
            
            $ServerAudit.Enable()

try {
$ServerAudit.Create()
}
catch [Exception] {
if ($_.Exception.InnerException -ne $null) {
                    $Exception = $_.Exception
                    while ($Exception.InnerException -ne $null) {                      
                        $Exception = $Exception.InnerException
                    }

                    throw $Exception
                }
                else {
                    throw $_.Exception
                }
}
        }
        else {
            Write-Verbose -Message "Server already contains an audit named $AuditName."
            [Microsoft.SqlServer.Management.Smo.Audit]$ServerAudit = $SqlConnection.Audits | Where-Object {$_.Name -ieq $AuditName} | Select-Object -First 1
            $ServerAudit.Enable()
        }

        if (($SqlConnection.ServerAuditSpecifications | Where-Object {$_.Name -ieq $AuditSpecificationName}) -eq $null) {
            Write-Verbose -Message "Creating audit specification $AuditSpecificationName."
            [Microsoft.SqlServer.Management.Smo.AuditSpecification]$ServerAuditSpecification = [Microsoft.SqlServer.Management.Smo.AuditSpecification]$ServerAuditSpecification = New-Object -TypeName Microsoft.SqlServer.Management.Smo.AuditSpecification($SqlConnection, $AuditSpecificationName)
            $ServerAuditSpecification.AuditName = $AuditName

try {
$ServerAuditSpecification.Create()  
}
catch [Exception] {
if ($_.Exception.InnerException -ne $null) {
                    $Exception = $_.Exception
                    while ($Exception.InnerException -ne $null) {                      
                        $Exception = $Exception.InnerException
                    }

                    throw $Exception
                }
                else {
                    throw $_.Exception
                }
}
        }
        else {
            Write-Verbose -Message "Server already contains an audit specification named $AuditSpecificationName. Disabling the specification to modify it."
            [Microsoft.SqlServer.Management.Smo.AuditSpecification]$ServerAuditSpecification = $SqlConnection.ServerAuditSpecifications |  Where-Object {$_.Name -ieq $AuditSpecificationName} | Select-Object -First 1
            $ServerAuditSpecification.Disable()
        }

        foreach ($Action in ([Enum]::GetNames([Microsoft.SqlServer.Management.Smo.AuditActionType]) | Where-Object {$_ -like "*Group"})) {
            [Microsoft.SqlServer.Management.Smo.AuditSpecificationDetail]$SpecificationDetail = New-Object -TypeName Microsoft.SqlServer.Management.Smo.AuditSpecificationDetail($Action)
            $ServerAuditSpecification.AddAuditSpecificationDetail($SpecificationDetail)
        }

        if ($IncludeDatabaseLevelAudting) {
            foreach ($Database in ($SqlConnection.Databases | Where-Object {$_.Name -ine "master" })) {
                Set-SQLDatabaseAuditing -Database $Database -SqlServer $SqlConnection -AuditName $AuditName -DatabaseAuditSpecificationName $AuditSpecificationName -Audits $script:DatabaseAudits
            }
        }
        
        $ServerAuditSpecification.Enable()  
    }

    End {
        if ($PassThru) {
            Write-Output $ServerAudit
        }
    }
}

Function Set-SQLDatabaseAuditing {
<#
  .SYNOPSIS
   SQL Server must generate trace or audit records on numerous actions.
 
  .DESCRIPTION
   The Set-SQLDatabaseAuditing cmdlet creates a database audit specification to audit all selected events. This defaults to audit all SELECT, INSERT, UPDATE, DROP, and EXECUTE commands
  
   Use caution with this option as it will fill up logs quickly and is not required for all data per the STIG.
 
  .PARAMETER ComputerName
   The server running the SQL instance to be configured or the virtual resource name of a clustered SQL instance. This defaults to localhost.
 
  .PARAMETER InstanceName
   The name of the instance to be configured, this defaults to the default instance name of MSSQLSERVER.
  
  .PARAMETER SqlServer
   An existing connection to a SQL Instance using a Microsoft.SqlServer.Management.Smo.Server object.
 
  .PARAMETER Database
   An existing database of the type Microsoft.SqlServer.Management.Smo.Database to create the auditing on.
 
  .PARAMETER AuditName
   The name of the audit to use, this should be an existing audit that the new Audit Specification is added to.
 
  .PARAMETER DatabaseAuditSpecificationName
   The name of the database audit specification to create.
 
  .PARAMETER Audits
   The specific audits to include, choose any combination of SELECT, INSERT, UPDATE, DROP, and EXECUTE. This defaults to all.
 
  .PARAMETER Principal
   The principal to audit taking these actions. This parameter defaults to public, which audits actions from all users.
 
  .PARAMTER PassThru
   Returns an object representing the item property. By default, this cmdlet does not generate any output.
 
        .EXAMPLE
   Set-SQLInstanceAuditing -ComputerName "SQL2014" -InstanceName "MyInstance"
          
   Configures the auditing on the SQL Instance and writes the audits to the Application Log.
 
  .INPUTS
   None
 
  .OUTPUTS
   None or Microsoft.SqlServer.Management.Smo.DatabaseAuditSpecification
 
  .NOTES
   AUTHOR: Michael Haken
   LAST UPDATE: 5/11/2016
 
  .FUNCTIONALITY
   STIG
    Microsoft SQL Server 2014 Instance V1R0
   STIG ID
 #>
    [CmdletBinding()]
    Param(
        [Parameter(ParameterSetName="NewConnection")]
        [System.String]$ComputerName = "localhost",
        [Parameter(ParameterSetName="NewConnection")]
        [System.String]$InstanceName = "MSSQLSERVER",
        [Parameter(ParameterSetName="ExistingConnection",Mandatory=$true)]
        $SqlServer,
        [Parameter(Mandatory=$true)]
        $Database,
        [Parameter(Mandatory=$true)]
        [System.String]$AuditName,
        [Parameter(Mandatory=$true)]
        [System.String]$DatabaseAuditSpecificationName,
        [Parameter()]
        [ValidateSet("SELECT", "INSERT", "UPDATE", "DELETE", "EXECUTE", IgnoreCase = $true)]
        [ValidateScript({$_.Count -ge 1})]
        [System.String[]]$Audits = $script:DatabaseAudits,
        [Parameter()]
        [System.String]$Principal = "public",
        [Parameter()]
        [switch]$PassThru
    )

    Begin {
        Import-SqlModule -LoadSMO

if ([System.String]::IsNullOrEmpty($InstanceName)) {
$InstanceName = "MSSQLSERVER"
}

        if ($SqlServer -ne $null -and $SqlServer.GetType() -ne [Microsoft.SqlServer.Management.Smo.Server]) {
            throw "SqlServer parameter must be an existing Microsoft.SqlServer.Management.Smo.Server object."
        }

        if ($Database.GetType() -ne [Microsoft.SqlServer.Management.Smo.Database] -and $Database.GetType() -ne [System.String]) {
            throw "Database parameter must be of type Microsoft.SqlServer.Management.Smo.Database or System.String."
        }

Write-Verbose -Message "Setting Database Level Auditing."
Write-Verbose -Message "STIG ID: "
    }

    Process {
        if ($PSCmdlet.ParameterSetName -eq "ExistingConnection") {
            [Microsoft.SqlServer.Management.Smo.Server]$SqlConnection = $SqlServer
        }
        else {
            [Microsoft.SqlServer.Management.Smo.Server]$SqlConnection = Get-SQLServer -ComputerName $ComputerName -InstanceName $InstanceName
        }

        if ($Database.GetType().Equals([System.String])) {
            [Microsoft.SqlServer.Management.Smo.Database]$Database = $SqlConnection.Databases | Where-Object {$_.Name -eq $Database.Name } | Select-Object -First 1
        }

        if ($Database -ne $null) {

            if (($Database.DatabaseAuditSpecifications | Where-Object { $_.Name -ieq $DatabaseAuditSpecificationName }) -eq $null) {
                Write-Verbose -Message "Creating database audit specification $DatabaseAuditSpecificationName on $($Database.Name)."
                [Microsoft.SqlServer.Management.Smo.DatabaseAuditSpecification]$DatabaseAuditSpecification = New-Object -TypeName Microsoft.SqlServer.Management.Smo.DatabaseAuditSpecification($Database, $DatabaseAuditSpecificationName)
                $DatabaseAuditSpecification.AuditName = $AuditName

try {
$DatabaseAuditSpecification.Create()
Write-Verbose -Message "Specification enabled $($DatabaseAuditSpecification.Enabled)"
}
catch [Exception] {
if ($_.Exception.InnerException -ne $null) {
$Exception = $_.Exception
while ($Exception.InnerException -ne $null) {                      
$Exception = $Exception.InnerException
}

throw $Exception
}
else {
throw $_.Exception
}
}
            }
            else {
                Write-Verbose -Message "Database $($Database.Name) already contains a database audit specification named $DatabaseAuditSpecificationName. Disabling the specification to modify it."
                [Microsoft.SqlServer.Management.Smo.DatabaseAuditSpecification]$DatabaseAuditSpecification = $Database.DatabaseAuditSpecifications | Where-Object { $_.Name -ieq $DatabaseAuditSpecificationName} | Select-Object -First 1
                $DatabaseAuditSpecification.Disable()
            }
         
            foreach($Action in ([Enum]::GetNames([Microsoft.SqlServer.Management.Smo.AuditActionType]) | Where-Object {$_ -iin $Audits } )) {
                $ObjectClass = "Database"
                $ObjectSchema = [System.String]::Empty
                [Microsoft.SqlServer.Management.Smo.AuditSpecificationDetail]$SpecificationDetail = New-Object -TypeName Microsoft.SqlServer.Management.Smo.AuditSpecificationDetail($Action, $ObjectClass, $ObjectSchema, $Database.Name, $Principal)
                $DatabaseAuditSpecification.AddAuditSpecificationDetail($SpecificationDetail)
            }

            $DatabaseAuditSpecification.Enable()
        }
        else {
            throw "Could not find a database named $Database."
        }
    }

    End {
        if ($PassThru) {
            Write-Output $DatabaseAuditSpecification
        }
    }
}

Function Set-SQLInstanceManagementRoles {
<#
  .SYNOPSIS
   SQL Server must be configured to separate user functionality (including user interface services) from database management functionality.
 
   SQL Server must prevent non-privileged users from executing privileged functionality, to include disabling, circumventing, or altering implemented security safeguards/countermeasures.
 
   SQL Server and Windows must enforce access restrictions associated with changes to the configuration of the SQL Server instance or database(s).
 
  .DESCRIPTION
   The Set-SQLInstanceManagementRoles cmdlet creates new roles with the same permissions as the key built in roles: sysadmin, serveradmin, and dbcreator. It also creates a role granted CONNECT SQL.
 
   Then, identified Windows Users, Groups, or SQL Logins are created if they do not already exist and added to these roles.
 
   Any other logins or roles explicitly granted these permissions will have them revoked and will be added to the new roles. Any members of the built in roles will be removed and added to the new
   roles, except for system accounts in the sysadmin role like NT SERVICE, NT AUTHORITY, sys, INFORMATION_SCHEMA or ##*## accounts.
 
  .PARAMETER ComputerName
   The server running the SQL instance to be configured or the virtual resource name of a clustered SQL instance. This defaults to localhost.
 
  .PARAMETER InstanceName
   The name of the instance to be configured, this defaults to the default instance name of MSSQLSERVER.
  
  .PARAMETER SqlServer
   An existing connection to a SQL Instance using a Microsoft.SqlServer.Management.Smo.Server object.
 
  .PARAMETER ConnectSqlRoleName
   The name of the role being granted CONNECT SQL to create. This defaults to CONNECT_SQL_ROLE.
 
  .PARAMETER SysAdminRoleName
   The name of the role being granted CONTROL SERVER to create. This defaults to SYSADMIN_ROLE.
 
  .PARAMETER ServerAdminRoleName
   The name of the role being granted the server admin permissions to create. This defaults to SERVERADMIN_ROLE.
 
  .PARAMETER DBCreatorRoleName
   The name of the role being granted CREATE ANY DATABASE to create. This defaults to DBCREATOR_ROLE.
 
  .PARAMETER SysAdminRoleMembers
   The Server Logins that should belong to the new Server Role. Logins will be created if they don't already exist.
 
  .PARAMETER ServerAdminRoleMembers
   The Server Logins that should belong to the new Server Role. Logins will be created if they don't already exist.
 
  .PARAMETER DBCreatorRoleMembers
   The Server Logins that should belong to the new Server Role. Logins will be created if they don't already exist.
 
  .PARAMETER ConnectSqlRoleMembers
   The Server Logins that should belong to the new Server Role. Logins will be created if they don't already exist.
 
  .PARAMETER DefaultSysAdmins
   The Server Logins in this list will not be removed from the sysadmin role during the execution of this cmdlet to preserve the capability to perform functions that explicitly check for membership in sysadmin.
 
        .EXAMPLE
   Set-SQLInstanceManagementRoles -ComputerName "SQL2014" `
           -InstanceName "MyInstance" `
           -SysAdminRoleMembers @("Contoso\UG-SQL-DEV_001-SysAdmins") `
           -ServerAdminRoleMembers @("Contoso\UG-SQL-DEV_001-ServerAdmins") `
           -DBCreatorRoleMembers @("Contoso\UG-SQL-DEV_001-DBCreators")
            
   Creates the 4 roles with their default names and creates 3 new logins and adds those logins to the corresponding role. Existing privileges are transferred to the new roles.
 
  .INPUTS
   None
 
  .OUTPUTS
   None
 
  .NOTES
   AUTHOR: Michael Haken
   LAST UPDATE: 5/11/2016
 
  .FUNCTIONALITY
   STIG
    Microsoft SQL Server 2014 Instance V1R0
   STIG ID
    SQL4-00-020500
    SQL4-00-032500
    SQL4-00-033900
   Rule ID
    SQL4-00-020500_rule
    SQL4-00-032500_rule
    SQL4-00-033900_rule
   Vuln ID
    SQL4-00-020500
    SQL4-00-032500
    SQL4-00-033900
   Severity
    CAT II
 #>
[CmdletBinding()]
    Param(
        [Parameter(ParameterSetName="NewConnection")]
        [System.String]$ComputerName = "localhost",
        [Parameter(ParameterSetName="NewConnection")]
        [System.String]$InstanceName = "MSSQLSERVER",
        [Parameter(ParameterSetName="ExistingConnection",Mandatory=$true)]
        $SqlServer,
[Parameter()]
[System.String]$ConnectSqlRoleName = "CONNECT_SQL_ROLE",
[Parameter()]
[System.String]$SysAdminRoleName = "SYSADMIN_ROLE",
[Parameter()]
[System.String]$ServerAdminRoleName = "SERVERADMIN_ROLE",
[Parameter()]
[System.String]$DBCreatorRoleName = "DBCREATOR_ROLE",
[Parameter()]
[System.String[]]$SysAdminRoleMembers,
[Parameter()]
[System.String[]]$ServerAdminRoleMembers,
[Parameter()]
[System.String[]]$DBCreatorRoleMembers,
[Parameter()]
[System.String[]]$ConnectSqlRoleMembers,
[Parameter()]
[System.String[]]$DefaultSysAdmins
)

Begin {
Import-SqlModule -LoadSMO

if ([System.String]::IsNullOrEmpty($InstanceName)) {
$InstanceName = "MSSQLSERVER"
}

        if ($SqlServer -ne $null -and $SqlServer.GetType() -ne [Microsoft.SqlServer.Management.Smo.Server]) {
            throw "SqlServer parameter must be an existing Microsoft.SqlServer.Management.Smo.Server object."
        }

Write-Verbose -Message "Creating SQL Instance Management Roles."
Write-Verbose -Message "STIG ID: SQL4-00-020500, SQL4-00-032500, SQL4-00-033900"
}

Process {
if ($PSCmdlet.ParameterSetName -eq "ExistingConnection") {
            [Microsoft.SqlServer.Management.Smo.Server]$SqlConnection = $SqlServer
        }
        else {
            [Microsoft.SqlServer.Management.Smo.Server]$SqlConnection = Get-SQLServer -ComputerName $ComputerName -InstanceName $InstanceName
        }

#Create logins for specified new role members
$NewLogins = @()
$NewLogins += $SysAdminRoleMembers
$NewLogins += $ServerAdminRoleMembers
$NewLogins += $DBCreatorRoleMembers
$NewLogins += $ConnectSqlRoleMembers

foreach ($Login in ($NewLogins | Where-Object {![System.String]::IsNullOrEmpty($_) })) {
if ($SqlConnection.Settings.LoginMode -eq [Microsoft.SqlServer.Management.Smo.ServerLoginMode]::Mixed -or $SqlConnection.Settings.LoginMode -eq [Microsoft.SqlServer.Management.Smo.ServerLoginMode]::Normal) {

if ($Login -like "*\*") {
Write-Verbose -Message "$Login matches domain account structure."
Add-SQLInstanceLogin -SqlServer $SqlConnection -Name $Login -LoginType WindowsUser
}
else {
Write-Verbose -Message "$Login will be created as a Sql user."
Add-SQLInstanceLogin -SqlServer $SqlConnection -Name $Login -LoginType SqlLogin
}
}
else {
Write-Verbose -Message "SQL Authentication is not enabled, $Login being created as a windows user."
Add-SQLInstanceLogin -SqlServer $SqlConnection -Name $Login -LoginType WindowsUser
}
}

#Create new roles
[Microsoft.SqlServer.Management.Smo.ServerRole]$SysAdminRole = Add-SQLInstanceServerRole -SqlServer $SqlConnection -Name $SysAdminRoleName -PassThru
[Microsoft.SqlServer.Management.Smo.ServerRole]$ServerAdminRole = Add-SQLInstanceServerRole -SqlServer $SqlConnection -Name $ServerAdminRoleName -PassThru
[Microsoft.SqlServer.Management.Smo.ServerRole]$DBCreatorRole = Add-SQLInstanceServerRole -SqlServer $SqlConnection -Name $DBCreatorRoleName -PassThru
[Microsoft.SqlServer.Management.Smo.ServerRole]$ConnectSqlRole = Add-SQLInstanceServerRole -SqlServer $SqlConnection -Name $ConnectSqlRoleName -PassThru

[Microsoft.SqlServer.Management.Smo.ServerPermissionSet]$ServerAdminPermissionSet = New-Object -TypeName Microsoft.SqlServer.Management.Smo.ServerPermissionSet
        $ServerAdminPermissionSet.AlterAnyEndpoint = $true
$ServerAdminPermissionSet.AlterResources = $true
$ServerAdminPermissionSet.AlterServerState = $true
$ServerAdminPermissionSet.AlterSettings = $true
$ServerAdminPermissionSet.Shutdown = $true
$ServerAdminPermissionSet.ViewServerState = $true

#Assign permissions to roles
        $SqlConnection.Grant([Microsoft.SqlServer.Management.Smo.ServerPermission]::ControlServer, $SysAdminRole.Name, $true)
$SqlConnection.Grant($ServerAdminPermissionSet, $ServerAdminRole.Name)
$SqlConnection.Grant([Microsoft.SqlServer.Management.Smo.ServerPermission]::CreateAnyDatabase, $DBCreatorRole.Name)
$SqlConnection.Grant([Microsoft.SqlServer.Management.Smo.ServerPermission]::ConnectSql, $ConnectSqlRole.Name)

#Assign new logins as members to the new roles
if ($SysAdminRoleMembers.Count -gt 0) {
Write-Verbose -Message "Adding $($SysAdminRoleMembers -join `",`") to $SysAdminRoleName."
$SysAdminRoleMembers | ForEach-Object { $SysAdminRole.AddMember($_) }
}
else {
Write-Verbose -Message "No members in SysAdminRoleMembers."
}

if ($ServerAdminRoleMembers.Count -gt 0) {
Write-Verbose -Message "Adding $($ServerAdminRoleMembers -join `",`") to $ServerAdminRoleName."
$ServerAdminRoleMembers | ForEach-Object { $ServerAdminRole.AddMember($_) }
}
else {
Write-Verbose -Message "No members in ServerAdminRoleMembers."
}

if ($DBCreatorRoleMembers.Count -gt 0) {
Write-Verbose -Message "Adding $($DBCreatorRoleMembers -join `",`") to $DBCreatorRoleName."
$DBCreatorRoleMembers | ForEach-Object { $DBCreatorRole.AddMember($_) }
}
else {
Write-Verbose -Message "No members in DBCreatorRoleMembers."
}

if ($ConnectSqlRoleMembers.Count -gt 0) {
Write-Verbose -Message "Adding $($ConnectSqlRoleMembers -join `",`") to $ConnectSqlRoleName."
$ConnectSqlRoleMembers | ForEach-Object { $ConnectSqlRole.AddMember($_) }
}
else {
Write-Verbose -Message "No members in ConnectSqlRoleMembers."
}

Write-Verbose -Message "Reviewing existing principals and altering permissions."

[System.String[]]$Logins = $SqlConnection.Logins | Where-Object {$_.Sid -ne 0x01} | Where-NotMatchIn -Matches $script:IgnoreNames -Property "Name" | Select-Object -ExpandProperty Name
[System.String[]]$Roles = $SqlConnection.Roles  | Where-Object {$_.IsFixedRole -eq $false -and $_.Name -inotin @($SysAdminRoleName, $ServerAdminRoleName, $ConnectSqlRoleName, $DBCreatorRoleName) } | Select-Object -ExpandProperty Name

[System.String[]]$Principals = @()
$Principals += $Logins
$Principals += $Roles

Write-Verbose -Message "Reviewing principals $($Principals -join `",`")"

#Check explicit permissions on each principal
foreach ($Principal in $Principals) {
            [Microsoft.SqlServer.Management.Smo.ServerPermissionInfo[]]$Permissions = $SqlConnection.EnumServerPermissions($Principal)
Write-Verbose -Message "Reviewing explicit permissions for $Principal."

            #PermissionType is a ServerPermissionSet object. The ServerPermissionSet object has properties that
            #correspond to the different permissions
            foreach ($ServerPermissionSet in $Permissions | Select-Object -ExpandProperty PermissionType) {
                
if ($ServerPermissionSet.ControlServer -eq $true) {
Write-Verbose -Message "Adding $Principal to $SysAdminRoleName."
$SysAdminRole.AddMember($Principal)

                    Write-Verbose -Message "Revoking CONTROL SERVER from $Principal."
                    $SqlConnection.Revoke([Microsoft.SqlServer.Management.Smo.ServerPermission]::ControlServer, $Principal)
                }

if ($ServerPermissionSet.AlterAnyEndpoint -eq $true -and $ServerPermissionSet.AlterResources -eq $true -and $ServerPermissionSet.AlterServerState -eq $true -and
$ServerPermissionSet.AlterSettings -eq $true -and $ServerPermissionSet.Shutdown -eq $true -and $ServerPermissionSet.ViewServerState -eq $true) {
Write-Verbose -Message "Adding $Principal to $ServerAdminRoleName."
$ServerAdminRole.AddMember($Principal)

Write-Verbose -Message "Revoking Server Admin permissions from $Principal."
$SqlConnection.Revoke($ServerAdminPermissionSet, $Principal)
}

if ($ServerPermissionSet.CreateAnyDatabase -eq $true) {
Write-Verbose -Message "Adding $Principal to $DBCreatorRoleName."
$DBCreatorRole.AddMember($Principal)

Write-Verbose -Message "Revoking CREATE ANY DATABASE from $Principal"
                    $SqlConnection.Revoke([Microsoft.SqlServer.Management.Smo.ServerPermission]::CreateAnyDatabase, $Principal)
}

if ($ServerPermissionSet.ConnectSql -eq $true) {
Write-Verbose -Message "Adding $Principal to $ConnectSqlRoleName."
$ConnectSqlRole.AddMember($Principal)

Write-Verbose -Message "Revoking CONNECT SQL from $Principal"
                    $SqlConnection.Revoke([Microsoft.SqlServer.Management.Smo.ServerPermission]::ConnectSql, $Principal)
}	
            }
        }

#Review fixed roles

Write-Verbose -Message "Reviewing fixed server roles and moving members."

#Sysadmin SID = 0x03
[Microsoft.SqlServer.Management.Smo.ServerRole]$SysAdminFixedRole = $SqlConnection.Roles | Where-Object {$_.IsFixedRole -eq $true -and $_.ID -eq 0x03} | Select-Object -First 1

#Don't modify sa or builtin NT SERVICE logins like SQLSERVERAGENT or MSSQLSERVER
foreach ($Member in ($SysAdminFixedRole.EnumMemberNames() | Where-NotMatchIn -Matches $script:IgnoreNames | Where-Object {$_ -inotin $DefaultSysAdmins})) {	
if (($SqlConnection.Logins | Where-Object {$_.Name -eq $Member -and $_.Sid -ne 0x01} ) -ne $null) {
Write-Verbose -Message "Adding $Member to $SysAdminRoleName."
$SysAdminRole.AddMember($Member)

Write-Verbose -Message "Removing $Member from $($SysAdminFixedRole.Name)."
$SysAdminFixedRole.DropMember($Member)
}
}

#ServerAdmin SID = 0x05
[Microsoft.SqlServer.Management.Smo.ServerRole]$ServerAdminFixedRole = $SqlConnection.Roles | Where-Object {$_.IsFixedRole -eq $true -and $_.ID -eq 0x05} | Select-Object -First 1

foreach ($Member in $ServerAdminFixedRole.EnumMemberNames()) {
Write-Verbose -Message "Adding $Member to $ServerAdminRoleName."
$ServerAdminRole.AddMember($Member)

Write-Verbose -Message "Removing $Member from $($ServerAdminFixedRole.Name)."
$ServerAdminFixedRole.DropMember($Member)
}

#DBCreator SID = 0x09
[Microsoft.SqlServer.Management.Smo.ServerRole]$DBCreatorFixedRole =  $SqlConnection.Roles | Where-Object {$_.IsFixedRole -eq $true -and $_.ID -eq 0x09} | Select-Object -First 1

foreach ($Member in $DBCreatorFixedRole.EnumMemberNames()) {
Write-Verbose -Message "Adding $Member to $DBCreatorRoleName."
$DBCreatorRole.AddMember($Member)

Write-Verbose -Message "Removing $Member from $($DBCreatorFixedRole.Name)."
$DBCreatorFixedRole.DropMember($Member)
}
}

End {

}
}

Function Rename-SQLInstanceAccount {
<#
  .SYNOPSIS
   Renames a SQL Login.
 
  .DESCRIPTION
   The Rename-SQLInstanceAccount cmdlet renames a provided login.
 
  .PARAMETER ComputerName
   The server running the SQL instance to be configured or the virtual resource name of a clustered SQL instance. This defaults to localhost.
 
  .PARAMETER InstanceName
   The name of the instance to be configured, this defaults to the default instance name of MSSQLSERVER.
  
  .PARAMETER SqlServer
   An existing connection to a SQL Instance using a Microsoft.SqlServer.Management.Smo.Server object.
 
  .PARAMETER Name
   The current name of the account to rename.
 
  .PARAMETER Sid
   The SID of the login principal to rename.
 
  .PARAMETER NewName
   The new name of the login.
 
  .PARAMTER PassThru
   Returns an object representing the item property. By default, this cmdlet does not generate any output.
 
        .EXAMPLE
   Rename-SQLInstanceAccount -ComputerName "SQL2014" -Instance "MyInstance" -Name "sa" -NewName "xsa"
          
   Renames the sa account to xsa.
 
  .EXAMPLE
   Rename-SQLInstanceAccount -ComputerName "SQL2014" -Instance "MyInstance" -Sid 0x01 -NewName "xsa"
    
   Renames the account with the SID 0x01 (the sa account) to xsa.
 
  .INPUTS
   None
 
  .OUTPUTS
   None or Microsoft.SqlServer.Management.Smo.Login
 
  .NOTES
   AUTHOR: Michael Haken
   LAST UPDATE: 5/11/2016
 
  .FUNCTIONALITY
   STIG
    Microsoft SQL Server 2014 Instance V1R0
   STIG ID
    SQL4-00-010200
   Rule ID
    SQL4-00-010200_rule
   Vuln ID
    SQL4-00-010200
   Severity
    CAT III
 #>
    [CmdletBinding()]
    Param(
        [Parameter(ParameterSetName="NewConnectionWithName")]
        [Parameter(ParameterSetName="NewConnectionWithSid")]
        [System.String]$ComputerName = "localhost",
        
        [Parameter(ParameterSetName="NewConnectionWithName")]
        [Parameter(ParameterSetName="NewConnectionWithSid")]
        [System.String]$InstanceName = "MSSQLSERVER",

        [Parameter(ParameterSetName="ExistingConnectionWithName",Mandatory=$true,Position=0)]
        [Parameter(ParameterSetName="ExistingConnectionWithSid",Mandatory=$true,Position=0)]
        $SqlServer,

        [Parameter(Position=1,Mandatory=$true,ParameterSetName="ExistingConnectionWithName")]
        [Parameter(Position=0,Mandatory=$true,ParameterSetName="NewConnectionWithName")]
        [System.String]$Name,

        [Parameter(Position=1,Mandatory=$true,ParameterSetName="ExistingConnectionWithSid")]
        [Parameter(Position=0,Mandatory=$true,ParameterSetName="NewConnectionWithSid")]
        $Sid,

        [Parameter(Position=1,Mandatory=$true,ParameterSetName="NewConnectionWithName")]
        [Parameter(Position=1,Mandatory=$true,ParameterSetName="NewConnectionWithSid")]
        [Parameter(Position=2,Mandatory=$true,ParameterSetName="ExistingConnectionWithSid")]
        [Parameter(Position=2,Mandatory=$true,ParameterSetName="ExistingConnectionWithName")]
        [System.String]$NewName,

        [Parameter()]
        [switch]$PassThru
    )

    Begin {
        Import-SqlModule -LoadSMO

if ([System.String]::IsNullOrEmpty($InstanceName)) {
$InstanceName = "MSSQLSERVER"
}

        if ($SqlServer -ne $null -and $SqlServer.GetType() -ne [Microsoft.SqlServer.Management.Smo.Server]) {
            throw "SqlServer parameter must be an existing Microsoft.SqlServer.Management.Smo.Server object."
        }

Write-Verbose -Message "Renaming SQL Login."
Write-Verbose -Message "STIG ID: SQL4-00-010200"
    }

    Process {
        if ($PSCmdlet.ParameterSetName -ilike "ExistingConnection*") {
            [Microsoft.SqlServer.Management.Smo.Server]$SqlConnection = $SqlServer
        }
        else {
            [Microsoft.SqlServer.Management.Smo.Server]$SqlConnection = Get-SQLServer -ComputerName $ComputerName -InstanceName $InstanceName
        }

        switch -wildcard ($PSCmdlet.ParameterSetName) {
            "*Name" {
Write-Verbose -Message "Matching login by name, $Name."

                [Microsoft.SqlServer.Management.Smo.Login]$Login = $SqlConnection.Logins | Where-Object {$_.Name -ieq $Name } | Select-Object -First 1
Write-Verbose -Message "Found login is null: $($Login -eq $null)"
                break
            }
            "*Sid" {
Write-Verbose -Message "Matching login by sid, $Sid."

                if ($Sid.GetType() -eq [System.Byte[]]) {
                    [System.Byte[]]$Value = $Sid
                }
                if ($Sid.GetType() -eq [System.String]) {
                    [System.Security.Principal.SecurityIdentifier]$Temp = New-Object System.Security.Principal.SecurityIdentifier($Sid)                   
                    [System.Byte[]]$Value = New-Object System.Byte[]($Temp.BinaryLength)
                    $Temp.GetBinaryForm($Value, 0)
                }
                if ($Sid.GetType() -eq [System.Int32]) {
                    
                    [System.Byte[]]$Value = [System.BitConverter]::GetBytes($Sid)
                }

                [Microsoft.SqlServer.Management.Smo.Login]$Login = $SqlConnection.Logins | Where-Object {
                    
                    if ($_.Sid.Length -lt 4) {
                        [System.Byte[]]$TempArr = New-Object System.Byte[](4)
                        $_.Sid.CopyTo($TempArr, 0)
                    }
                    else {
                        [System.Byte[]]$TempArr = New-Object System.Byte[]($_.Sid.Length)
                        $TempArr = $_.Sid
                    }

                    [System.BitConverter]::ToInt32($Value, 0) -eq [BitConverter]::ToInt32($TempArr, 0)
                    
                } | Select-Object -First 1

                break
            }
        }

if ($Login -ne $null) {
$Login.Rename($NewName)
}
else {
Write-Warning "Could not find a login matching the provided information."
}
    }

    End {
        if ($PassThru) {
            Write-Output $Login
        }
    }
}

Function Disable-SQLInstanceAccount {
<#
  .SYNOPSIS
   Disables a SQL Login.
 
  .DESCRIPTION
   The Disable-SQLInstanceAccount cmdlet disables a provided login.
 
  .PARAMETER ComputerName
   The server running the SQL instance to be configured or the virtual resource name of a clustered SQL instance. This defaults to localhost.
 
  .PARAMETER InstanceName
   The name of the instance to be configured, this defaults to the default instance name of MSSQLSERVER.
  
  .PARAMETER SqlServer
   An existing connection to a SQL Instance using a Microsoft.SqlServer.Management.Smo.Server object.
 
  .PARAMETER Name
   The current name of the account to disable.
 
  .PARAMETER Sid
   The SID of the login principal to disable.
 
  .PARAMTER PassThru
   Returns an object representing the item property. By default, this cmdlet does not generate any output.
 
        .EXAMPLE
   Disable-SQLInstanceAccount -ComputerName "SQL2014" -InstanceName "MyInstance" -Name "sa"
          
   Disables the sa account
 
  .EXAMPLE
   Rename-SQLInstanceAccount -ComputerName "SQL2014" -InstanceName "MyInstance" -Sid 0x01
    
   Disables the account with the SID 0x01 (the sa account).
 
  .INPUTS
   None
 
  .OUTPUTS
   None or Microsoft.SqlServer.Management.Smo.Login
 
  .NOTES
   AUTHOR: Michael Haken
   LAST UPDATE: 5/11/2016
 
  .FUNCTIONALITY
   STIG
    Microsoft SQL Server 2014 Instance V1R0
   STIG ID
    SQL4-00-017100
   Rule ID
    SQL4-00-017100_rule
   Vuln ID
    SQL4-00-017100
   Severity
    CAT II
 #>
    [CmdletBinding()]
    Param(
        [Parameter(ParameterSetName="NewConnectionWithName")]
        [Parameter(ParameterSetName="NewConnectionWithSid")]
        [System.String]$ComputerName = "localhost",
        
        [Parameter(ParameterSetName="NewConnectionWithName")]
        [Parameter(ParameterSetName="NewConnectionWithSid")]
        [System.String]$InstanceName = "MSSQLSERVER",

        [Parameter(ParameterSetName="ExistingConnectionWithName",Mandatory=$true,Position=0)]
        [Parameter(ParameterSetName="ExistingConnectionWithSid",Mandatory=$true,Position=0)]
        $SqlServer,

        [Parameter(Position=1,Mandatory=$true,ParameterSetName="ExistingConnectionWithName")]
        [Parameter(Position=0,Mandatory=$true,ParameterSetName="NewConnectionWithName")]
        [System.String]$Name,

        [Parameter(Position=1,Mandatory=$true,ParameterSetName="ExistingConnectionWithSid")]
        [Parameter(Position=0,Mandatory=$true,ParameterSetName="NewConnectionWithSid")]
        $Sid,

        [Parameter()]
        [switch]$PassThru
    )

    Begin {
        Import-SqlModule -LoadSMO

if ([System.String]::IsNullOrEmpty($InstanceName)) {
$InstanceName = "MSSQLSERVER"
}

        if ($SqlServer -ne $null -and $SqlServer.GetType() -ne [Microsoft.SqlServer.Management.Smo.Server]) {
            throw "SqlServer parameter must be an existing Microsoft.SqlServer.Management.Smo.Server object."
        }

Write-Verbose -Message "Disabling SQL Login."
Write-Verbose -Message "STIG ID: SQL4-00-017100"
    }

    Process {
        if ($PSCmdlet.ParameterSetName -ilike "ExistingConnection*") {
            [Microsoft.SqlServer.Management.Smo.Server]$SqlConnection = $SqlServer
        }
        else {
            [Microsoft.SqlServer.Management.Smo.Server]$SqlConnection = Get-SQLServer -ComputerName $ComputerName -InstanceName $InstanceName
        }

        switch -wildcard ($PSCmdlet.ParameterSetName) {
            "*Name" {
Write-Verbose -Message "Matching login by name, $Name."

                [Microsoft.SqlServer.Management.Smo.Login]$Login = $SqlConnection.Logins | Where-Object {$_.Name -ieq $Name } | Select-Object -First 1
Write-Verbose -Message "Found login is null: $($Login -eq $null)"
                break
            }
            "*Sid" {
Write-Verbose -Message "Matching login by sid, $Sid."

                if ($Sid.GetType() -eq [System.Byte[]]) {
                    [System.Byte[]]$Value = $Sid
                }
                if ($Sid.GetType() -eq [System.String]) {
                    [System.Security.Principal.SecurityIdentifier]$Temp = New-Object System.Security.Principal.SecurityIdentifier($Sid)                   
                    [System.Byte[]]$Value = New-Object System.Byte[]($Temp.BinaryLength)
                    $Temp.GetBinaryForm($Value, 0)
                }
                if ($Sid.GetType() -eq [System.Int32]) {
                    
                    [System.Byte[]]$Value = [System.BitConverter]::GetBytes($Sid)
                }

                [Microsoft.SqlServer.Management.Smo.Login]$Login = $SqlConnection.Logins | Where-Object {
                    
                    if ($_.Sid.Length -lt 4) {
                        [System.Byte[]]$TempArr = New-Object System.Byte[](4)
                        $_.Sid.CopyTo($TempArr, 0)
                    }
                    else {
                        [System.Byte[]]$TempArr = New-Object System.Byte[]($_.Sid.Length)
                        $TempArr = $_.Sid
                    }

                    [System.BitConverter]::ToInt32($Value, 0) -eq [BitConverter]::ToInt32($TempArr, 0)
                    
                } | Select-Object -First 1

                break
            }
        }

if ($Login -ne $null) {
$Login.Disable()
}
else {
Write-Warning "Could not find a login matching the provided information."
}
    }

    End {
        if ($PassThru) {
            Write-Output $Login
        }
    }
}

Function Set-SQLInstanceXPCmdShell{
<#
  .SYNOPSIS
   Access to xp_cmdshell must be disabled, unless specifically required and approved.
 
  .DESCRIPTION
   The Set-SQLInstanceXPCmdShell cmdlet enables or disables xp_cmdshell.
 
  .PARAMETER ComputerName
   The server running the SQL instance to be configured or the virtual resource name of a clustered SQL instance. This defaults to localhost.
 
  .PARAMETER InstanceName
   The name of the instance to be configured, this defaults to the default instance name of MSSQLSERVER.
  
  .PARAMETER SqlServer
   An existing connection to a SQL Instance using a Microsoft.SqlServer.Management.Smo.Server object.
 
  .PARAMETER Enabled
   Specifies whether xp_cmdshell should be enabled or disabled. Defaults to false.
 
  .PARAMTER PassThru
   Returns an object representing the item property. By default, this cmdlet does not generate any output.
 
        .EXAMPLE
   Set-SQLInstanceXPCmdShell -ComputerName "SQL2014" -InstanceName "MyInstance" -Enabled $false
          
   Disables xp_cmdshell on the specified instance.
 
  .INPUTS
   None
 
  .OUTPUTS
   None or System.Boolean
 
  .NOTES
   AUTHOR: Michael Haken
   LAST UPDATE: 5/11/2016
 
  .FUNCTIONALITY
   STIG
    Microsoft SQL Server 2014 Instance V1R0
   STIG ID
    SQL4-00-017200
   Rule ID
    SQL4-00-017200_rule
   Vuln ID
    SQL4-00-017200
   Severity
    CAT II
 #>
[CmdletBinding()]
Param(
[Parameter(ParameterSetName="NewConnection")]
        [System.String]$ComputerName = "localhost",
        [Parameter(ParameterSetName="NewConnection")]
        [System.String]$InstanceName = "MSSQLSERVER",
        [Parameter(ParameterSetName="ExistingConnection",Mandatory=$true,Position=0)]
        $SqlServer,
[Parameter()]
[System.Boolean]$Enabled = $false,
        [Parameter()]
        [switch]$PassThru
)

Begin {
Import-SqlModule -LoadSMO

if ([System.String]::IsNullOrEmpty($InstanceName)) {
$InstanceName = "MSSQLSERVER"
}

if ($SqlServer -ne $null -and $SqlServer.GetType() -ne [Microsoft.SqlServer.Management.Smo.Server]) {
            throw "SqlServer parameter must be an existing Microsoft.SqlServer.Management.Smo.Server object."
        }

Write-Verbose -Message "Disabling XP_Cmdshell."
Write-Verbose -Message "STIG ID: SQL4-00-017200"
}

Process {
if ($PSCmdlet.ParameterSetName -eq "ExistingConnection") {
            [Microsoft.SqlServer.Management.Smo.Server]$SqlConnection = $SqlServer
        }
        else {
            [Microsoft.SqlServer.Management.Smo.Server]$SqlConnection = Get-SQLServer -ComputerName $ComputerName -InstanceName $InstanceName
        }

        Write-Verbose -Message "Enabling Show Advanced Options."
        $Max = $SqlConnection.Configuration.ShowAdvancedOptions.Maximum
        $Min = $SqlConnection.Configuration.ShowAdvancedOptions.Minimum
        Write-Verbose -Message "ShowAdvancedOptions mininum: $Min maximum: $Max"
        $SqlConnection.Configuration.ShowAdvancedOptions.ConfigValue = $Max
        $SqlConnection.Configuration.Alter()
        Write-Verbose -Message "Setting xp_cmdshell enabled to $Enabled."
$SqlConnection.Configuration.XPCmdShellEnabled.ConfigValue = $Enabled
        $SqlConnection.Configuration.Alter()
        Write-Verbose -Message "Disabling Show Advanced Options."
        $SqlConnection.Configuration.ShowAdvancedOptions.ConfigValue = $Min
        $SqlConnection.Configuration.Alter()
}

End {
        if ($PassThru) {
            Write-Output $SqlConnection.Configuration.XPCmdShellEnabled
        }
}
}

Function Set-SQLInstanceLoginPasswordPolicies {
<#
  .SYNOPSIS
   If SQL Server authentication, using passwords, is employed, SQL Server must enforce the DoD standards for password complexity and lifetime.
 
  .DESCRIPTION
   The Set-SQLInstanceLoginPasswordPolicies cmdlet enables the password policy and password expiration options on every SQL Login.
 
  .PARAMETER ComputerName
   The server running the SQL instance to be configured or the virtual resource name of a clustered SQL instance. This defaults to localhost.
 
  .PARAMETER InstanceName
   The name of the instance to be configured, this defaults to the default instance name of MSSQLSERVER.
  
  .PARAMETER SqlServer
   An existing connection to a SQL Instance using a Microsoft.SqlServer.Management.Smo.Server object.
 
  .PARAMETER IncludeSA
   Specifies whether the built in SA account should also have these properties set.
 
        .EXAMPLE
   Set-SQLInstanceLoginPasswordPolicies -ComputerName "SQL2014" -InstanceName "MyInstance"
          
   Enables the password policy and expiration on every SQL login on the specified instance.
 
  .INPUTS
   None
 
  .OUTPUTS
   None
 
  .NOTES
   AUTHOR: Michael Haken
   LAST UPDATE: 5/11/2016
 
  .FUNCTIONALITY
   STIG
    Microsoft SQL Server 2014 Instance V1R0
   STIG ID
    SQL4-00-038900
   Rule ID
    SQL4-00-038900_rule
   Vuln ID
    SQL4-00-038900
   Severity
    CAT II
 #>
    [CmdletBinding()]
    Param(
[Parameter(ParameterSetName="NewConnection")]
        [System.String]$ComputerName = "localhost",
        [Parameter(ParameterSetName="NewConnection")]
        [System.String]$InstanceName = "MSSQLSERVER",
        [Parameter(ParameterSetName="ExistingConnection",Mandatory=$true,Position=0)]
        $SqlServer,
        [Parameter()]
        [switch]$IncludeSA,
        [Parameter()]
        [switch]$PassThru
)

Begin {
Import-SqlModule -LoadSMO

if ([System.String]::IsNullOrEmpty($InstanceName)) {
$InstanceName = "MSSQLSERVER"
}

        if ($SqlServer -ne $null -and $SqlServer.GetType() -ne [Microsoft.SqlServer.Management.Smo.Server]) {
            throw "SqlServer parameter must be an existing Microsoft.SqlServer.Management.Smo.Server object."
        }

Write-Verbose -Message "Setting SQL Login Password Policy and Expiration."
Write-Verbose -Message "STIG ID: SQL4-00-038900"
}

Process {
        if ($PSCmdlet.ParameterSetName -eq "ExistingConnection") {
            [Microsoft.SqlServer.Management.Smo.Server]$SqlConnection = $SqlServer
        }
        else {
            [Microsoft.SqlServer.Management.Smo.Server]$SqlConnection = Get-SQLServer -ComputerName $ComputerName -InstanceName $InstanceName
        }

        if ($IncludeSA) {
            $SqlConnection.Logins | Where-Object {$_.LoginType -eq [Microsoft.SqlServer.Management.Smo.LoginType]::SqlLogin } | ForEach-Object {
                Write-Verbose -Message "Configuring password policy for $($_.Name)."
                $_.PasswordPolicyEnforced = $true
                $_.PasswordExpirationEnabled = $true
                $_.Alter()
            }
        }
        else {           
            $SqlConnection.Logins | Where-Object {$_.LoginType -eq [Microsoft.SqlServer.Management.Smo.LoginType]::SqlLogin -and $_.Sid -ne 0x01 } | ForEach-Object {
                Write-Verbose -Message "Configuring password policy for $($_.Name)."
                $_.PasswordPolicyEnforced = $true
                $_.PasswordExpirationEnabled = $true
                $_.Alter()
            }
        }       
    }

    End {

    }
}

Function Set-SQLInstanceProtocols {
<#
 
 
 .FUNCTIONALITY
  STIG ID SQL4-00-034200 Rule ID SQL4-00-034200_rule Vuln ID SQL4-00-034200
  Severity
   CAT II
 #>
[CmdletBinding()]
Param(

)
}

Function Set-SQLInstanceDefaultTrace{
<#
  .SYNOPSIS
   Enables or disables the default trace.
 
  .DESCRIPTION
   The Set-SQLInstanceDefaultTrace cmdlet enables or disables the default trace on the instance.
 
  .PARAMETER ComputerName
   The server running the SQL instance to be configured or the virtual resource name of a clustered SQL instance. This defaults to localhost.
 
  .PARAMETER InstanceName
   The name of the instance to be configured, this defaults to the default instance name of MSSQLSERVER.
 
  .PARAMETER SqlServer
   An existing connection to a SQL Instance using a Microsoft.SqlServer.Management.Smo.Server object.
 
  .PARAMETER Enabled
   Specifies whether to enable or disable the default trace. This defaults to true.
 
  .PARAMTER PassThru
   Returns an object representing the item property. By default, this cmdlet does not generate any output.
 
        .EXAMPLE
   Set-SQLInstanceDefaultTrace -ComputerName "SQL2014" -InstanceName "MyInstance" -Enabled $true
          
   Enables the default trace on the specified instance.
 
  .INPUTS
   None
 
  .OUTPUTS
   System.Boolean
 
  .NOTES
   AUTHOR: Michael Haken
   LAST UPDATE: 5/11/2016
 #>
[CmdletBinding()]
Param(
[Parameter(ParameterSetName="NewConnection")]
        [System.String]$ComputerName = "localhost",
        [Parameter(ParameterSetName="NewConnection")]
        [System.String]$InstanceName = "MSSQLSERVER",
        [Parameter(ParameterSetName="ExistingConnection",Mandatory=$true,Position=0)]
        $SqlServer,
[Parameter()]
[bool]$Enabled = $true,
        [Parameter()]
        [switch]$PassThru
)

Begin {
Import-SqlModule -LoadSMO

if ([System.String]::IsNullOrEmpty($InstanceName)) {
$InstanceName = "MSSQLSERVER"
}

if ($SqlServer -ne $null -and $SqlServer.GetType() -ne [Microsoft.SqlServer.Management.Smo.Server]) {
            throw "SqlServer parameter must be an existing Microsoft.SqlServer.Management.Smo.Server object."
        }
}

Process {
if ($PSCmdlet.ParameterSetName -eq "ExistingConnection") {
            [Microsoft.SqlServer.Management.Smo.Server]$SqlConnection = $SqlServer
        }
        else {
            [Microsoft.SqlServer.Management.Smo.Server]$SqlConnection = Get-SQLServer -ComputerName $ComputerName -InstanceName $InstanceName
        }

        Write-Verbose -Message "Enabling Show Advanced Options."
        $Max = $SqlConnection.Configuration.ShowAdvancedOptions.Maximum
        $Min = $SqlConnection.Configuration.ShowAdvancedOptions.Minimum
        Write-Verbose -Message "ShowAdvancedOptions mininum: $Min maximum: $Max"
        $SqlConnection.Configuration.ShowAdvancedOptions.ConfigValue = $Max
        $SqlConnection.Configuration.Alter()
        Write-Verbose -Message "Setting default trace enabled to $Enabled."
$SqlConnection.Configuration.DefaultTraceEnabled.ConfigValue = $Enabled
        $SqlConnection.Configuration.Alter()
        Write-Verbose -Message "Disabling Show Advanced Options."
        $SqlConnection.Configuration.ShowAdvancedOptions.ConfigValue = $Min
        $SqlConnection.Configuration.Alter()
}

End {
        if ($PassThru) {
            Write-Output $SqlConnection.Configuration.DefaultTraceEnabled
        }
}
}

Function Add-SQLInstanceLogin {
<#
  .SYNOPSIS
   Adds a new login to the SQL Instance.
 
  .DESCRIPTION
   The Add-SQLInstanceLogin cmdlet creates a new Windows User, Group, or SQL Login.
 
  .PARAMETER ComputerName
   The server running the SQL instance to be configured or the virtual resource name of a clustered SQL instance. This defaults to localhost.
 
  .PARAMETER InstanceName
   The name of the instance to be configured, this defaults to the default instance name of MSSQLSERVER.
 
  .PARAMETER SqlServer
   An existing connection to a SQL Instance using a Microsoft.SqlServer.Management.Smo.Server object.
 
  .PARAMETER Name
   The name of the login to create.
 
  .PARAMETER LoginType
   The type of login to create, either WindowsUser (also used for groups) or SqlLogin. This defaults to WindowsUser.
 
  .PARAMTER PassThru
   Returns an object representing the item property. By default, this cmdlet does not generate any output.
 
        .EXAMPLE
   Add-SQLInstanceLogin -ComputerName "SQL2014" -InstanceName "MyInstance" -Name "Contoso\UG-SQL-Users" -LoginType WindowsUser
          
   Creates a new login for the UG-SQL-Users group on the instance.
 
  .INPUTS
   None
 
  .OUTPUTS
   Microsoft.SqlServer.Management.Smo.Login
 
  .NOTES
   AUTHOR: Michael Haken
   LAST UPDATE: 5/11/2016
 #>
[CmdletBinding()]
Param(
[Parameter(ParameterSetName="NewConnection")]
        [System.String]$ComputerName = "localhost",
        [Parameter(ParameterSetName="NewConnection")]
        [System.String]$InstanceName = "MSSQLSERVER",
        [Parameter(ParameterSetName="ExistingConnection",Mandatory=$true,Position=0)]
        $SqlServer,
[Parameter(Position=0,Mandatory=$true)]
[System.String]$Name,
[Parameter(Position=1)]
[ValidateSet("WindowsUser", "SqlLogin")]
[System.String]$LoginType = "WindowsUser",
        [Parameter()]
        [switch]$PassThru
)

Begin {
Import-SqlModule -LoadSMO

if ([System.String]::IsNullOrEmpty($InstanceName)) {
$InstanceName = "MSSQLSERVER"
}

if ($SqlServer -ne $null -and $SqlServer.GetType() -ne [Microsoft.SqlServer.Management.Smo.Server]) {
            throw "SqlServer parameter must be an existing Microsoft.SqlServer.Management.Smo.Server object."
        }
}

Process {
if ($PSCmdlet.ParameterSetName -eq "ExistingConnection") {
            [Microsoft.SqlServer.Management.Smo.Server]$SqlConnection = $SqlServer
        }
        else {
            [Microsoft.SqlServer.Management.Smo.Server]$SqlConnection = Get-SQLServer -ComputerName $ComputerName -InstanceName $InstanceName
        }

[System.String[]]$Logins = $SqlConnection.Logins | Where-NotMatchIn -Matches $script:IgnoreNames -Property "Name" | Select-Object -ExpandProperty Name

if ($Name -inotin $Logins) {
Write-Verbose -Message "Creating login $Name."
[Microsoft.SqlServer.Management.Smo.Login]$NewLogin = New-Object Microsoft.SqlServer.Management.Smo.Login($SqlConnection, $Name)
$NewLogin.DefaultDatabase = "master";

switch ($LoginType.ToLower()) {
"windowsuser" {
$NewLogin.LoginType = [Microsoft.SqlServer.Management.Smo.LoginType]::WindowsUser
break
}
"sqllogin" {
$NewLogin.LoginType = [Microsoft.SqlServer.Management.Smo.LoginType]::SqlLogin
break
}
default {
throw "Could not determine login type $LoginType."
}
}

try {
$NewLogin.Create()
}
catch [Exception] {
if ($_.Exception.InnerException -ne $null) {
                    $Exception = $_.Exception
                    while ($Exception.InnerException -ne $null) {                      
                        $Exception = $Exception.InnerException
                    }

                    throw $Exception
                }
                else {
                    throw $_.Exception
                }
}
}
else {
Write-Verbose -Message "$Name login already exists."
[Microsoft.SqlServer.Management.Smo.Login]$NewLogin = $SqlConnection.Logins | Where-Object { $_.Name -ieq $Name } | Select-Object -First 1
}
}

End {
if ($PassThru) {
Write-Output $NewLogin
}
}
}

Function Add-SQLInstanceServerRole {
<#
  .SYNOPSIS
   Adds a new role to the SQL Instance.
 
  .DESCRIPTION
   The Add-SQLInstanceRole cmdlet creates a Server Role.
 
  .PARAMETER ComputerName
   The server running the SQL instance to be configured or the virtual resource name of a clustered SQL instance. This defaults to localhost.
 
  .PARAMETER InstanceName
   The name of the instance to be configured, this defaults to the default instance name of MSSQLSERVER.
 
  .PARAMETER SqlServer
   An existing connection to a SQL Instance using a Microsoft.SqlServer.Management.Smo.Server object.
 
  .PARAMETER Name
   The name of the role to create.
 
  .PARAMTER PassThru
   Returns an object representing the item property. By default, this cmdlet does not generate any output.
 
        .EXAMPLE
   Add-SQLInstanceRole -ComputerName "SQL2014" -InstanceName "MyInstance" -Name "NEW_ROLE"
          
   Creates a new role named NEW_ROLE.
 
  .INPUTS
   None
 
  .OUTPUTS
   Microsoft.SqlServer.Management.Smo.ServerRole
 
  .NOTES
   AUTHOR: Michael Haken
   LAST UPDATE: 5/11/2016
 #>
[CmdletBinding()]
Param(
[Parameter(ParameterSetName="NewConnection")]
        [System.String]$ComputerName = "localhost",
        [Parameter(ParameterSetName="NewConnection")]
        [System.String]$InstanceName = "MSSQLSERVER",
        [Parameter(ParameterSetName="ExistingConnection",Mandatory=$true,Position=0)]
        $SqlServer,
[Parameter(Position=0,Mandatory=$true)]
[System.String]$Name,
        [Parameter()]
        [switch]$PassThru
)

Begin {
Import-SqlModule -LoadSMO

if ([System.String]::IsNullOrEmpty($InstanceName)) {
$InstanceName = "MSSQLSERVER"
}

if ($SqlServer -ne $null -and $SqlServer.GetType() -ne [Microsoft.SqlServer.Management.Smo.Server]) {
            throw "SqlServer parameter must be an existing Microsoft.SqlServer.Management.Smo.Server object."
        }
}

Process {
if ($PSCmdlet.ParameterSetName -eq "ExistingConnection") {
            [Microsoft.SqlServer.Management.Smo.Server]$SqlConnection = $SqlServer
        }
        else {
            [Microsoft.SqlServer.Management.Smo.Server]$SqlConnection = Get-SQLServer -ComputerName $ComputerName -InstanceName $InstanceName
        }

[System.String[]]$Roles = $SqlConnection.Roles | Where-Object {$_.IsFixedRole -eq $false } | Select-Object -ExpandProperty Name

 if ($Name -inotin $Roles) {
            Write-Verbose -Message "Creating role $Name"
            [Microsoft.SqlServer.Management.Smo.ServerRole]$NewRole = New-Object Microsoft.SqlServer.Management.Smo.ServerRole($SqlConnection, $Name)
            
try {
$NewRole.Create()
}
catch [Exception] {
if ($_.Exception.InnerException -ne $null) {
                    $Exception = $_.Exception
                    while ($Exception.InnerException -ne $null) {                      
                        $Exception = $Exception.InnerException
                    }

                    throw $Exception
                }
                else {
                    throw $_.Exception
                }
}
        }
        else {
            Write-Verbose -Message "$Name role already exists."
[Microsoft.SqlServer.Management.Smo.ServerRole]$NewRole = $SqlConnection.Roles | Where-Object {$_.Name -ieq $Name } | Select-Object -First 1
        }
}

End {
if ($PassThru) {
Write-Output $NewRole
}
}
}

Function New-SQLInstanceJobCategory {
<#
  .SYNOPSIS
   Adds a new job category to the SQL Instance.
 
  .DESCRIPTION
   The Add-SQLInstanceJobCategory cmdlet creates a new job category of use with SQL Agent jobs.
 
  .PARAMETER ComputerName
   The server running the SQL instance to be configured or the virtual resource name of a clustered SQL instance. This defaults to localhost.
 
  .PARAMETER InstanceName
   The name of the instance to be configured, this defaults to the default instance name of MSSQLSERVER.
 
  .PARAMETER SqlServer
   An existing connection to a SQL Instance using a Microsoft.SqlServer.Management.Smo.Server object.
 
  .PARAMETER Name
   The name of the job category to create.
 
  .PARAMTER PassThru
   Returns an object representing the item property. By default, this cmdlet does not generate any output.
 
        .EXAMPLE
   New-SQLInstanceJobCategory -ComputerName "SQL2014" -InstanceName "MyInstance" -Name "STIG Audits"
          
   Creates a new job category named STIG Audits.
 
  .INPUTS
   None
 
  .OUTPUTS
   Microsoft.SqlServer.Management.Smo.Agent.JobCategory
 
  .NOTES
   AUTHOR: Michael Haken
   LAST UPDATE: 5/11/2016
 #>
[CmdletBinding()]
Param(
[Parameter(ParameterSetName="NewConnection")]
        [System.String]$ComputerName = "localhost",
        [Parameter(ParameterSetName="NewConnection")]
        [System.String]$InstanceName = "MSSQLSERVER",
        [Parameter(ParameterSetName="ExistingConnection",Mandatory=$true,Position=0)]
        $SqlServer,
[Parameter(Position=0,Mandatory=$true)]
[System.String]$Name,
        [Parameter()]
        [switch]$PassThru
)

Begin {
Import-SqlModule -LoadSMO

if ([System.String]::IsNullOrEmpty($InstanceName)) {
$InstanceName = "MSSQLSERVER"
}

if ($SqlServer -ne $null -and $SqlServer.GetType() -ne [Microsoft.SqlServer.Management.Smo.Server]) {
            throw "SqlServer parameter must be an existing Microsoft.SqlServer.Management.Smo.Server object."
        }
}

Process {
if ($PSCmdlet.ParameterSetName -eq "ExistingConnection") {
            [Microsoft.SqlServer.Management.Smo.Server]$SqlConnection = $SqlServer
        }
        else {
            [Microsoft.SqlServer.Management.Smo.Server]$SqlConnection = Get-SQLServer -ComputerName $ComputerName -InstanceName $InstanceName
        }


if (($SqlConnection.JobServer.JobCategories | Where-Object {$_.Name -ieq $Name}) -eq $null) {
Write-Verbose -Message "Job category does not already exist, creating it."
[Microsoft.SqlServer.Management.Smo.Agent.JobCategory]$Category = New-Object -TypeName Microsoft.SqlServer.Management.Smo.Agent.JobCategory($SqlConnection.JobServer, $Name)
$Category.CategoryType = [Microsoft.SqlServer.Management.Smo.Agent.CategoryType]::LocalJob

try {
$Category.Create()
}
catch [Exception] {
if ($_.Exception.InnerException -ne $null) {
$Exception = $_.Exception
while ($Exception.InnerException -ne $null) {                      
$Exception = $Exception.InnerException
}

throw $Exception
}
else {
throw $_.Exception
}
}
}
else {
Write-Verbose -Message "Job category already exists, returning it."
[Microsoft.SqlServer.Management.Smo.Agent.JobCategory]$Category = $SqlConnection.JobServer.JobCategories | Where-Object {$_.Name -ieq $Name} | Select-Object -First 1
}
}

End {
if ($PassThru) {
Write-Output $Category
}
}
}

Function New-SQLAgentJob {
<#
  .SYNOPSIS
   Adds a new SQL Agent Job.
 
  .DESCRIPTION
   The New-SQLAgentJob cmdlet creates a new job.
 
  .PARAMETER ComputerName
   The server running the SQL instance to be configured or the virtual resource name of a clustered SQL instance. This defaults to localhost.
 
  .PARAMETER InstanceName
   The name of the instance to be configured, this defaults to the default instance name of MSSQLSERVER.
 
  .PARAMETER SqlServer
   An existing connection to a SQL Instance using a Microsoft.SqlServer.Management.Smo.Server object.
 
  .PARAMETER Name
   The name of the job to create.
 
  .PARAMETER Description
   The description of the new job.
 
  .PARAMETER EmailLevel
   Defines when an operator is notified by email, the options are: Always, Never, OnFailure, OnSuccess. This defaults to Never.
 
  .PARAMETER EventLogLevel
   Defines when an event is written to the event log, the options are: Always, Never, OnFailure, OnSuccess. This defaults to Never.
 
  .PARAMETER NetSendLevel
   Defines when an operator is notified by NetSend, the options are: Always, Never, OnFailure, OnSuccess. This defaults to Never.
 
  .PARAMETER PageLevel
   Defines when an operator is notified by page, the options are: Always, Never, OnFailure, OnSuccess. This defaults to Never.
 
  .PARAMETER DeleteLevel
   Defines is the job is deleted after it runs, the options are: Always, Never, OnFailure, OnSuccess. This defaults to Never.
 
  .PARAMETER OperatorToEmail
   The name of the operator to send emails to.
 
  .PARAMETER OperatorToPage
   The name of the operator to page.
   
  .PARAMETER OperatorToNetSend
   The name of the operator to NetSend.
 
  .PARAMETER Owner
   The name of the SQL Login that should be the owner of the job. This defaults to the sa account.
 
  .PARAMETER JobCategory
   The name of the job category the job should be a part of. This defaults to the job category with ID 0.
 
        .EXAMPLE
   $FunctionCheckJob = New-SQLAgentJob -ComputerName "SQL2014 -InstanceName "MyInstance" `
    -Name "Alter_Function_Audit" `
    -Description "Daily audit to make sure no modifications to functions have been made." `
    -EmailLevel Always `
    -EventLogLevel OnFailure `
    -NetSendLevel Never `
    -PageLevel Never `
    -DeleteLevel Never `
    -OperatorToEmail "Database Administrators" `
    -JobCategory "STIG Audits"
 
   Creates a new job that will be used to check function modifications. This job still requires a job step and schedule to be created.
 
  .INPUTS
   None
 
  .OUTPUTS
   Microsoft.SqlServer.Management.Smo.Agent.Job
 
  .NOTES
   AUTHOR: Michael Haken
   LAST UPDATE: 5/11/2016
 #>
[CmdletBinding()]
Param(
[Parameter(ParameterSetName="NewConnection")]
        [System.String]$ComputerName = "localhost",
        [Parameter(ParameterSetName="NewConnection")]
        [System.String]$InstanceName = "MSSQLSERVER",
        [Parameter(ParameterSetName="ExistingConnection",Mandatory=$true,Position=0)]
        $SqlServer,
[Parameter(Position=0,Mandatory=$true)]
[System.String]$Name,
[Parameter(Position=1)]
[System.String]$Description = [System.String]::Empty,
[Parameter()]
[ValidateSet("Always", "Never", "OnFailure", "OnSuccess")]
[System.String]$EmailLevel = "Never",
[Parameter()]
[ValidateSet("Always", "Never", "OnFailure", "OnSuccess")]
[System.String]$EventLogLevel = "Never",
[Parameter()]
[ValidateSet("Always", "Never", "OnFailure", "OnSuccess")]
[System.String]$NetSendLevel = "Never",
[Parameter()]
[ValidateSet("Always", "Never", "OnFailure", "OnSuccess")]
[System.String]$PageLevel = "Never",
[Parameter()]
[ValidateSet("Always", "Never", "OnFailure", "OnSuccess")]
[System.String]$DeleteLevel = "Never",
[Parameter()]
[System.String]$OperatorToEmail = [System.String]::Empty,
[Parameter()]
[System.String]$OperatorToPage = [System.String]::Empty,
[Parameter()]
[System.String]$OperatorToNetSend = [System.String]::Empty,
[Parameter()]
[System.String]$Owner = [System.String]::Empty,
[Parameter()]
[System.String]$JobCategory = [System.String]::Empty
)

Begin {
Import-SqlModule -LoadSMO

if ([System.String]::IsNullOrEmpty($InstanceName)) {
$InstanceName = "MSSQLSERVER"
}

if ($SqlServer -ne $null -and $SqlServer.GetType() -ne [Microsoft.SqlServer.Management.Smo.Server]) {
            throw "SqlServer parameter must be an existing Microsoft.SqlServer.Management.Smo.Server object."
        }
}

Process {
if ($PSCmdlet.ParameterSetName -eq "ExistingConnection") {
            [Microsoft.SqlServer.Management.Smo.Server]$SqlConnection = $SqlServer
        }
        else {
            [Microsoft.SqlServer.Management.Smo.Server]$SqlConnection = Get-SQLServer -ComputerName $ComputerName -InstanceName $InstanceName
        }

if (($SqlConnection.JobServer.Jobs | Where-Object {$_.Name -ieq $Name}) -eq $null) {

[Microsoft.SqlServer.Management.Smo.Agent.Job]$Job = New-Object -TypeName Microsoft.SqlServer.Management.Smo.Agent.Job($SqlConnection.JobServer, $Name)

if (![System.String]::IsNullOrEmpty($Description)) {
$Job.Description = $Description
}

[bool]$IgnoreCase = $true

if (![System.String]::IsNullOrEmpty($OperatorToEmail)) {
[Microsoft.SqlServer.Management.Smo.Agent.CompletionAction]$Action = [Microsoft.SqlServer.Management.Smo.Agent.CompletionAction]::Never

if ([System.Enum]::TryParse($EmailLevel, $IgnoreCase, [ref]$Action)) {
$Job.EmailLevel = $Action
$Job.OperatorToEmail = $OperatorToEmail
}
else {
$Job.EmailLevel = [Microsoft.SqlServer.Management.Smo.Agent.CompletionAction]::Never
}
}
else {
$Job.EmailLevel = [Microsoft.SqlServer.Management.Smo.Agent.CompletionAction]::Never
}

if (![System.String]::IsNullOrEmpty($OperatorToPage)) {

if ([System.Enum]::TryParse($PageLevel, $IgnoreCase, [ref]$Action)) {
$Job.PageLevel = $Action
$Job.OperatorToPage = $OperatorToPage
}
else {
$Job.PageLevel = [Microsoft.SqlServer.Management.Smo.Agent.CompletionAction]::Never
}
}
else {
$Job.PageLevel = [Microsoft.SqlServer.Management.Smo.Agent.CompletionAction]::Never
}

if (![System.String]::IsNullOrEmpty($OperatorToNetSend)) {

if ([System.Enum]::TryParse($NetSendLevel, $IgnoreCase, [ref]$Action)) {
$Job.NetSendLevel = $Action
$Job.OperatorToNetSend = $OperatorToNetSend
}
else {
$Job.NetSendLevel = [Microsoft.SqlServer.Management.Smo.Agent.CompletionAction]::Never
}
}
else {
$Job.NetSendLevel = [Microsoft.SqlServer.Management.Smo.Agent.CompletionAction]::Never
}

if ([System.Enum]::TryParse($EventLogLevel, $IgnoreCase, [ref]$Action)) {
$Job.EventLogLevel = $Action
}
else {
$Job.EventLogLevel = [Microsoft.SqlServer.Management.Smo.Agent.CompletionAction]::OnFailure
}

if ([System.Enum]::TryParse($DeleteLevel, $IgnoreCase, [ref]$Action)) {
$Job.DeleteLevel = $Action
}
else {
$Job.DeleteLevel = [Microsoft.SqlServer.Management.Smo.Agent.CompletionAction]::Never
}	

if (![System.String]::IsNullOrEmpty($JobCategory)) {
[Microsoft.SqlServer.Management.Smo.Agent.JobCategory]$Category = $SqlConnection.JobServer.JobCategories | Where-Object {$_.Name -ieq $JobCategory} | Select-Object -First 1
}

if ($Category -eq $null -or [System.String]::IsNullOrEmpty($JobCategory)) {
[Microsoft.SqlServer.Management.Smo.Agent.JobCategory]$Category = $SqlConnection.JobServer.JobCategories | Where-Object {$_.ID -eq 0} | Select-Object -First 1
}

$Job.Category = $Category.Name

if (![System.String]::IsNullOrEmpty($Owner)) {
$Job.OwnerLoginName = $Owner
}
else {
#Sets the owner to the built in sa account
$Job.OwnerLoginName = $SqlConnection.Logins | Where-Object {$_.Sid -eq 0x01} | Select-Object -First 1 -ExpandProperty Name
}

try {
$Job.Create()
}
catch [Exception] {
if ($_.Exception.InnerException -ne $null) {
                    $Exception = $_.Exception
                    while ($Exception.InnerException -ne $null) {                      
                        $Exception = $Exception.InnerException
                    }

                    throw $Exception
                }
                else {
                    throw $_.Exception
                }
}
}
else {
[Microsoft.SqlServer.Management.Smo.Agent.Job]$Job = $SqlConnection.JobServer | Where-Object {$_.Name -ieq $Name} | Select-Object -First 1
}
}

End {
Write-Output $Job
}
}

Function New-SQLAgentJobStep {
<#
  .SYNOPSIS
   Adds a new job step to a specified job.
 
  .DESCRIPTION
   The Add-SQLAgentJobStep cmdlet creates a new job step as part of an existing job.
 
  .PARAMETER ComputerName
   The server running the SQL instance to be configured or the virtual resource name of a clustered SQL instance. This defaults to localhost.
 
  .PARAMETER InstanceName
   The name of the instance to be configured, this defaults to the default instance name of MSSQLSERVER.
 
  .PARAMETER SqlServer
   An existing connection to a SQL Instance using a Microsoft.SqlServer.Management.Smo.Server object.
 
  .PARAMETER Job
   The Job this step is being created for.
 
  .PARAMETER Name
   The name of the job step to create.
 
  .PARAMETER SubSystem
   The subsystem that will be used to run the step, the options are: "ActiveScripting", "AnalysisCommand", "AnalysisQuery", "CmdExec", "Distribution", "LogReader", "Merge", "PowerShell", "QueueReader", "Snapshot", "Ssis", "TransactSql".
 
   This defaults to TransactSql.
 
  .PARAMETER RetryAttempts
   The maximum number of times a job step is retried before it is returned with a completion status of failure. This defaults to 0.
 
  .PARAMETER RetryInterval
   The number of minutes that Microsoft SQL Server Agent waits before trying to execute a job step that has previously failed. This defaults to 0.
 
  .PARAMETER OSRunPriority
   The execution thread scheduling for job steps executing operating system tasks. This defaults to 0.
 
  .PARAMETER DatabaseName
   The name of the database to which the job step command execution is confined. This defaults to master.
 
  .PARAMETER DatabaseUser
   The database user account that the job step assumes when executing the command string.
  
  .PARAMETER OnFailAction
   The action to take when the job step finishes execution with failure. The options are "GoToNextStep", "GoToStep", "QuitWithFailure", "QuitWithSuccess". This defaults to QuitWithFailure.
 
  .PARAMETER OnSuccessAction
   The action to take when the job step finishes execution with success. The options are "GoToNextStep", "GoToStep", "QuitWithFailure", "QuitWithSuccess". This defaults to QuitWithSuccess.
 
  .PARAMETER Command
   The command execution string for the job step.
 
        .EXAMPLE
   $FunctionCheckJobStep = New-SQLAgentJobStep -ComputerName "SQL2014" -InstanceName "MyInstance" `
    -Name "Alter_Function_Audit_Step" `
    -Job $FunctionCheckJob `
    -DatabaseName "master" `
    -OnFailAction QuitWithFailure `
    -OnSuccessAction QuitWithSuccess `
    -RetryAttempts 0 `
    -RetryInterval 0 `
    -OSRunPriority 0 `
    -SubSystem TransactSql `
    -Command "PRINT('Ran job');"
          
   Creates a job step that prints the text "Ran job".
 
  .INPUTS
   None
 
  .OUTPUTS
   Microsoft.SqlServer.Management.Smo.Agent.JobStep
 
  .NOTES
   AUTHOR: Michael Haken
   LAST UPDATE: 5/11/2016
 #>
[CmdletBinding()]
Param(
[Parameter(ParameterSetName="NewConnectionWithName")]
[Parameter(ParameterSetName="NewConnectionWithJob")]
        [System.String]$ComputerName = "localhost",
[Parameter(ParameterSetName="NewConnectionWithName")]
        [Parameter(ParameterSetName="NewConnectionWithJob")]
        [System.String]$InstanceName = "MSSQLSERVER",
        [Parameter(ParameterSetName="ExistingConnectionWithName",Mandatory=$true,Position=0)]
[Parameter(ParameterSetName="ExistingConnectionWithJob",Mandatory=$true,Position=0)]
        $SqlServer,
[Parameter(ParameterSetName="ExistingConnectionWithName",Mandatory=$true,Position=1)]
[Parameter(ParameterSetName="NewConnectionWithName",Mandatory=$true,Position=1)]
[System.String]$JobName,
[Parameter(ParameterSetName="NewConnectionWithJob",Mandatory=$true,Position=1)]
[Parameter(ParameterSetName="ExistingConnectionWithJob",Mandatory=$true,Position=1)]
$Job,
[Parameter()]
[System.String]$Name,
[Parameter()]
[ValidateSet("ActiveScripting", "AnalysisCommand", "AnalysisQuery", "CmdExec", "Distribution", "LogReader", "Merge", "PowerShell", "QueueReader", "Snapshot", "Ssis", "TransactSql")]
[System.String]$SubSystem = "TransactSql",
[Parameter()]
[ValidateScript({$_ -ge 0})]
[System.Int32]$RetryAttempts = 0,
[Parameter()]
[ValidateScript({$_ -ge 0})]
[System.Int32]$RetryInterval = 0,
[Parameter()]
[ValidateScript({$_ -ge 0})]
[System.Int32]$OSRunPriority = 0,
[Parameter()]
[ValidateScript({![System.String]::IsNullOrEmpty($_)})]
[System.String]$DatabaseName = "master",
[Parameter()]
[System.String]$DatabaseUser,
[Parameter()]
[ValidateSet("GoToNextStep", "GoToStep", "QuitWithFailure", "QuitWithSuccess")]
[System.String]$OnFailAction = "QuitWithFailure",
[Parameter()]
[ValidateSet("GoToNextStep", "GoToStep", "QuitWithFailure", "QuitWithSuccess")]
[System.String]$OnSuccessAction = "QuitWithSuccess",
[Parameter(Mandatory=$true)]
[System.String]$Command
)

Begin {
Import-SqlModule -LoadSMO

if ([System.String]::IsNullOrEmpty($InstanceName)) {
$InstanceName = "MSSQLSERVER"
}

if ($SqlServer -ne $null -and $SqlServer.GetType() -ne [Microsoft.SqlServer.Management.Smo.Server]) {
            throw "SqlServer parameter must be an existing Microsoft.SqlServer.Management.Smo.Server object."
        }

if ($Job -ne $null -and $Job.GetType() -ne [Microsoft.SqlServer.Management.Smo.Agent.Job]) {
throw "Job parameter must be an existing Microsoft.SqlServer.Management.Smo.Agent.Job object."
}
}

Process {
if ($PSCmdlet.ParameterSetName -like "ExistingConnection*") {
            [Microsoft.SqlServer.Management.Smo.Server]$SqlConnection = $SqlServer
        }
        else {
            [Microsoft.SqlServer.Management.Smo.Server]$SqlConnection = Get-SQLServer -ComputerName $ComputerName -InstanceName $InstanceName
        }

if ($PSCmdlet.ParameterSetName -like "*WithName") {
[Microsoft.SqlServer.Management.Smo.Job]$Job = $SqlConnection.JobServer.Jobs | Where-Object {$_.Name -ieq $JobName} | Select-Object -First 1

if ($Job -eq $null) {
throw "$JobName does not match any existing jobs."
}
}

[Microsoft.SqlServer.Management.Smo.Agent.JobStep]$JobStep = New-Object -TypeName Microsoft.SqlServer.Management.Smo.Agent.JobStep($Job, $Name)

[Microsoft.SqlServer.Management.Smo.Agent.AgentSubSystem]$SubSystemObject = [Microsoft.SqlServer.Management.Smo.Agent.AgentSubSystem]::TransactSql

if ([System.Enum]::TryParse($SubSystem, [ref]$SubSystemObject)) {
$JobStep.SubSystem = $SubSystemObject
}
else {
$JobStep.SubSystem = [Microsoft.SqlServer.Management.Smo.Agent.AgentSubSystem]::TransactSql
}

[Microsoft.SqlServer.Management.Smo.Agent.StepCompletionAction]$Action = [Microsoft.SqlServer.Management.Smo.Agent.StepCompletionAction]::QuitWithFailure

if ([System.Enum]::TryParse($OnFailAction, [ref]$Action)) {
$JobStep.OnFailAction = $Action
}
else {
$JobStep.OnFailAction = [Microsoft.SqlServer.Management.Smo.Agent.StepCompletionAction]::QuitWithFailure
}

if ([System.Enum]::TryParse($OnSuccessAction, [ref]$Action)) {
$JobStep.OnSuccessAction = $Action
}
else {
$JobStep.OnSuccessAction = [Microsoft.SqlServer.Management.Smo.Agent.StepCompletionAction]::QuitWithSuccess
}

$JobStep.DatabaseName = $DatabaseName

if (![System.String]::IsNullOrEmpty($DatabaseUser)) {
$JobStep.DatabaseUser = $DatabaseUser
}

$JobStep.OSRunPriority = $OSRunPriority
$JobStep.RetryAttempts = $RetryAttempts
$JobStep.RetryInterval = $RetryInterval
$JobStep.Command = $Command

try {
$JobStep.Create()
}
catch [Exception] {
if ($_.Exception.InnerException -ne $null) {
                $Exception = $_.Exception
                while ($Exception.InnerException -ne $null) {                      
                    $Exception = $Exception.InnerException
                }

                throw $Exception
            }
            else {
                throw $_.Exception
            }
}
}

End {
Write-Output $JobStep
}

}

<#
 WeekDays.Sunday = 1
 WeekDays.Monday = 2
 WeekDays.Tuesday = 4
 WeekDays.Wednesday = 8
 WeekDays.Thursday = 16
 WeekDays.Friday = 32
 WeekDays.Saturday = 64
 WeekDays.WeekDays = 62
 WeekDays.WeekEnds = 65
 WeekDays.EveryDay = 127
#>

Function New-SQLAgentJobSchedule {
<#
  .SYNOPSIS
   Adds a new schedule to a specified job.
 
  .DESCRIPTION
   The Add-SQLAgentJobSchedule cmdlet creates a new schedule to run a specified job.
 
  .PARAMETER ComputerName
   The server running the SQL instance to be configured or the virtual resource name of a clustered SQL instance. This defaults to localhost.
 
  .PARAMETER InstanceName
   The name of the instance to be configured, this defaults to the default instance name of MSSQLSERVER.
 
  .PARAMETER SqlServer
   An existing connection to a SQL Instance using a Microsoft.SqlServer.Management.Smo.Server object.
 
  .PARAMETER Job
   The Job this schedule is being created for.
 
  .PARAMETER JobName
   The name of the job this schedule is being created for.
 
  .PARAMETER Name
   The name of the schedule to be created.
 
  .PARAMETER ActiveEndDate
   The date and time when the schedule ends.
 
  .PARAMETER ActiveEndTimeOfDay
   The time when the job schedule stops for the day.
 
  .PARAMETER ActiveStartDate
   The date and time when the schedule starts. This defaults to now.
 
  .PARAMETER ActiveStartTimeOfDay
   The time when the job schedule starts for the day.
 
  .PARAMETER FrequencyInterval
   The frequency interval, which determines how often the job is scheduled to run. https://msdn.microsoft.com/en-us/library/microsoft.sqlserver.management.smo.agent.jobschedule.frequencyinterval.aspx
 
  .PARAMETER FreqeuncyType
   The way in which frequency is evaluated for the job schedule, whether it's one time only, or weekly, or when the processor is idle, for example. The options are: "AutoStart", "Daily", "Monthly", "MonthlyRelative", "OneTime", "OnIdle", "Unknown", "Weekly".
 
   This defaults to Unknown.
    
        .EXAMPLE
   $FunctionCheckSchedule = New-SQLAgentJobSchedule -ComputerName "SQL2014" -InstanceName "MyInstance" `
    -Name "Daily" `
    -Job $FunctionCheckJob `
    -ActiveStartTimeOfDay (New-Object System.TimeSpan(2, 0, 0)) `
    -FrequencyType Daily `
    -FrequencyInterval 1
          
   Creates a schedule that runs daily at 2AM.
 
  .INPUTS
   None
 
  .OUTPUTS
   Microsoft.SqlServer.Management.Smo.Agent.JobSchedule
 
  .NOTES
   AUTHOR: Michael Haken
   LAST UPDATE: 5/11/2016
 #>
[CmdletBinding()]
Param(
[Parameter(ParameterSetName="NewConnectionWithName")]
[Parameter(ParameterSetName="NewConnectionWithJob")]
        [System.String]$ComputerName = "localhost",
[Parameter(ParameterSetName="NewConnectionWithName")]
        [Parameter(ParameterSetName="NewConnectionWithJob")]
        [System.String]$InstanceName = "MSSQLSERVER",
        [Parameter(ParameterSetName="ExistingConnectionWithName",Mandatory=$true,Position=0)]
[Parameter(ParameterSetName="ExistingConnectionWithJob",Mandatory=$true,Position=0)]
        $SqlServer,
[Parameter(Position=2,Mandatory=$true)]
[System.String]$Name,
[Parameter(ParameterSetName="ExistingConnectionWithName",Mandatory=$true,Position=1)]
[Parameter(ParameterSetName="NewConnectionWithName",Mandatory=$true,Position=1)]
[System.String]$JobName,
[Parameter(ParameterSetName="NewConnectionWithJob",Mandatory=$true,Position=1)]
[Parameter(ParameterSetName="ExistingConnectionWithJob",Mandatory=$true,Position=1)]
$Job,
[Parameter()]
[System.DateTime]$ActiveEndDate = [System.DateTime]::MinValue,
[Parameter()]
[System.TimeSpan]$ActiveEndTimeOfDay = [System.TimeSpan]::Zero,
[Parameter()]
[System.DateTime]$ActiveStartDate = [System.DateTime]::Now,
[Parameter(Mandatory=$true)]
[System.TimeSpan]$ActiveStartTimeOfDay,
[Parameter()]
[System.Int32]$FrequencyInterval,
[Parameter()]
[ValidateSet("AutoStart", "Daily", "Monthly", "MonthlyRelative", "OneTime", "OnIdle", "Unknown", "Weekly")]
[System.String]$FrequencyType = "Unknown"

)

Begin {
Import-SqlModule -LoadSMO

if ([System.String]::IsNullOrEmpty($InstanceName)) {
$InstanceName = "MSSQLSERVER"
}

if ($SqlServer -ne $null -and $SqlServer.GetType() -ne [Microsoft.SqlServer.Management.Smo.Server]) {
            throw "SqlServer parameter must be an existing Microsoft.SqlServer.Management.Smo.Server object."
        }

if ($Job -ne $null -and $Job.GetType() -ne [Microsoft.SqlServer.Management.Smo.Agent.Job]) {
throw "Job parameter must be an existing Microsoft.SqlServer.Management.Smo.Agent.Job object."
}
}

Process {
if ($PSCmdlet.ParameterSetName -like "ExistingConnection*") {
            [Microsoft.SqlServer.Management.Smo.Server]$SqlConnection = $SqlServer
        }
        else {
            [Microsoft.SqlServer.Management.Smo.Server]$SqlConnection = Get-SQLServer -ComputerName $ComputerName -InstanceName $InstanceName
        }

if ($PSCmdlet.ParameterSetName -like "*WithName") {
[Microsoft.SqlServer.Management.Smo.Agent.Job]$Job = $SqlConnection.JobServer.Jobs | Where-Object {$_.Name -ieq $JobName} | Select-Object -First 1

if ($Job -eq $null) {
throw "$JobName does not match any existing jobs."
}
}

[Microsoft.SqlServer.Management.Smo.Agent.JobSchedule]$Schedule = New-Object -TypeName Microsoft.SqlServer.Management.Smo.Agent.JobSchedule($Job, $Name)

[Microsoft.SqlServer.Management.Smo.Agent.FrequencyTypes]$Freq = [Microsoft.SqlServer.Management.Smo.Agent.FrequencyTypes]::Unknown

if ([System.Enum]::TryParse($FrequencyType, [ref]$Freq)) {
$Schedule.FrequencyTypes = $Freq
}
else {
throw "Could not determine the frequency type given by $FrequencyType."
}

$Schedule.ActiveStartDate = $ActiveStartDate
$Schedule.ActiveStartTimeOfDay = $ActiveStartTimeOfDay
if ($ActiveEndDate -gt [System.DateTime]::MinValue -and $ActiveEndTimeOfDay -ne $null) {
$Schedule.ActiveEndDate = $ActiveEndDate
$Schedule.ActiveEndTimeOfDay = $ActiveEndTimeOfDay
}

$Schedule.FrequencyInterval = $FrequencyInterval

try {
$Schedule.Create()
}
catch [Exception] {
if ($_.Exception.InnerException -ne $null) {
$Exception = $_.Exception
                while ($Exception.InnerException -ne $null) {                      
                    $Exception = $Exception.InnerException
                }

                throw $Exception
            }
            else {
                throw $_.Exception
            }
}
}

End {
Write-Output $Schedule
}
}

Function Set-SQLDatabaseTrustworthy {
<#
  .SYNOPSIS
   Sets the trustworthy setting on a database.
 
  .DESCRIPTION
   The Set-SQLDatabaseTrustworthy cmdlet modifies the trustworthy setting. The SQL Server instance uses each database's TRUSTWORTHY property to guard against tampering that could enable
   unwarranted privilege escalation. When TRUSTWORTHY is 0/False/Off, SQL Server prevents the database from accessing resources in other databases.
   When TRUSTWORTHY is 1/True/On, SQL Server permits access to other databases (subject to other protections). SQL Server sets TRUSTWORTHY OFF when it creates a new database.
   SQL Server forces TRUSTWORTHY OFF, irrespective of its prior value, when an existing database is attached to it, to address the possibility that an adversary may have tampered with the database, introducing malicious code.
 
  .PARAMETER ComputerName
   The server running the SQL instance to be configured or the virtual resource name of a clustered SQL instance. This defaults to localhost.
 
  .PARAMETER InstanceName
   The name of the instance to be configured, this defaults to the default instance name of MSSQLSERVER.
  
  .PARAMETER SqlServer
   An existing connection to a SQL Instance using a Microsoft.SqlServer.Management.Smo.Server object.
 
  .PARAMETER DatabaseName
   The name of the database to modify.
 
  .PARAMETER Enabled
   Specifies whether this setting should be enabled or disabled.
 
  .PARAMTER PassThru
   Returns an object representing the item property. By default, this cmdlet does not generate any output.
 
        .EXAMPLE
   Set-SQLDatabaseTrustworthy -ComputerName "SQL2014" -InstanceName "MyInstance" -DatabaseName "master" -Enabled $false
          
   Sets the trustworthy setting on the master database to disabled.
 
  .INPUTS
   None
 
  .OUTPUTS
   None or System.Boolean
 
  .NOTES
   AUTHOR: Michael Haken
   LAST UPDATE: 5/11/2016
 
  .FUNCTIONALITY
   STIG
    Microsoft SQL Server 2014 Datavase V1R0
   STIG ID
    SQL4-00-015610
   Rule ID
    SQL4-00-015610_rule
   Vuln ID
    SQL4-00-015610
   Severity
    CAT II
 
 #>
[CmdletBinding()]
Param(
[Parameter(ParameterSetName="NewConnection")]
        [System.String]$ComputerName = "localhost",
        [Parameter(ParameterSetName="NewConnection")]
        [System.String]$InstanceName = "MSSQLSERVER",
        [Parameter(ParameterSetName="ExistingConnection",Mandatory=$true,Position=0)]
        $SqlServer,
[Parameter(Mandatory=$true)]
[System.String]$DatabaseName,
[Parameter()]
[System.Boolean]$Enabled = $false,
[Parameter()]
[switch]$PassThru
)

Begin {
Import-SqlModule -LoadSMO

if ([System.String]::IsNullOrEmpty($InstanceName)) {
$InstanceName = "MSSQLSERVER"
}

if ($SqlServer -ne $null -and $SqlServer.GetType() -ne [Microsoft.SqlServer.Management.Smo.Server]) {
            throw "SqlServer parameter must be an existing Microsoft.SqlServer.Management.Smo.Server object."
        }

Write-Verbose -Message "Setting Database Trustworthy."
Write-Verbose -Message "STIG ID: SQL4-00-015610"
}

Process {
if ($DB.Name -eq "msdb" -and $Enabled -eq $false) {
Write-Warning -Message "msdb database is required to be set to trustworthy, this cmdlet will not modify this setting."
}
else {
if ($PSCmdlet.ParameterSetName -eq "ExistingConnection") {
[Microsoft.SqlServer.Management.Smo.Server]$SqlConnection = $SqlServer
}
else {
[Microsoft.SqlServer.Management.Smo.Server]$SqlConnection = Get-SQLServer -ComputerName $ComputerName -InstanceName $InstanceName
}

[Microsoft.SqlServer.Management.Smo.Database]$DB = $SqlConnection.Databases | Where-Object {$_.Name -eq $DatabaseName} | Select-Object -First 1
$DB.Trustworthy = $Enabled
}
}

End {
if ($PassThru) {
Write-Output $DB.Trustworthy
}
}
}

Function Get-SQLInstanceServerRoleMembership {
<#
  .SYNOPSIS
   Gets the Server Role membership of a specified principal.
 
  .DESCRIPTION
   The Get-SQLInstanceServerRoleMembership cmdlet gets all of the Server Roles that a principal is a member of.
 
  .PARAMETER ComputerName
   The server running the SQL instance to be configured or the virtual resource name of a clustered SQL instance. This defaults to localhost.
 
  .PARAMETER InstanceName
   The name of the instance to be configured, this defaults to the default instance name of MSSQLSERVER.
  
  .PARAMETER SqlServer
   An existing connection to a SQL Instance using a Microsoft.SqlServer.Management.Smo.Server object.
 
  .PARAMETER PrincipalName
   The name of the principal to get role membership of.
 
  .PARAMETER OnlyFixedRoles
   Specifies is only the membership in fixed roles should be returned as a result.
 
        .EXAMPLE
   Get-SQLInstanceServerRoleMembership -ComputerName "SQL2014" -InstanceName "MyInstance" -PrincipalName "sa"
          
   Gets all of the server role membership for the sa account.
 
  .INPUTS
   None
 
  .OUTPUTS
   Microsoft.SqlServer.Management.Smo.ServerRole[]
 
  .NOTES
   AUTHOR: Michael Haken
   LAST UPDATE: 5/11/2016
 #>
[CmdletBinding()]
Param(
[Parameter(ParameterSetName="NewConnection")]
        [System.String]$ComputerName = "localhost",
        [Parameter(ParameterSetName="NewConnection")]
        [System.String]$InstanceName = "MSSQLSERVER",
        [Parameter(ParameterSetName="ExistingConnection",Mandatory=$true,Position=0)]
        $SqlServer,
[Parameter(Mandatory=$true)]
[System.String]$PrincipalName,
        [Parameter()]
        [switch]$OnlyFixedRoles
    
)

Begin {
Import-SqlModule -LoadSMO

if ([System.String]::IsNullOrEmpty($InstanceName)) {
$InstanceName = "MSSQLSERVER"
}

if ($SqlServer -ne $null -and $SqlServer.GetType() -ne [Microsoft.SqlServer.Management.Smo.Server]) {
            throw "SqlServer parameter must be an existing Microsoft.SqlServer.Management.Smo.Server object."
        }

Write-Verbose -Message "Getting roles for $PrincipalName."
}

Process {
if ($PSCmdlet.ParameterSetName -eq "ExistingConnection") {
            [Microsoft.SqlServer.Management.Smo.Server]$SqlConnection = $SqlServer
        }
        else {
            [Microsoft.SqlServer.Management.Smo.Server]$SqlConnection = Get-SQLServer -ComputerName $ComputerName -InstanceName $InstanceName
        }

        [Microsoft.SqlServer.Management.Smo.ServerRole[]]$Roles = @()

        if ($OnlyFixedRoles) {
    foreach($Role in ($SqlConnection.Roles | Where-Object { $_.IsFixedRole -eq $true } )) {
Write-Verbose "Checking role $($Role.Name)."
                if ($Role.EnumMemberNames() -icontains $PrincipalName) {
                    $Roles += $Role
                }
            }
        }
        else {
            foreach($Role in ($SqlConnection.Roles | Where-Object { $_.IsFixedRole -eq $true } )) {
Write-Verbose -Message "Checking role $($Role.Name)."
                if ($Role.EnumMemberNames() -icontains $PrincipalName) {
                    $Roles += $Role
                }
            }
        }
}

End {
        Write-Output $Roles
}
}

Function New-SQLDatabaseDDLTrigger {
<#
  .SYNOPSIS
   Creates a new database DDL trigger.
 
  .DESCRIPTION
   The New-SQLDatabaseDDLTrigger cmdlet creates a new DDL trigger on a specified database.
 
  .PARAMETER ComputerName
   The server running the SQL instance to be configured or the virtual resource name of a clustered SQL instance. This defaults to localhost.
 
  .PARAMETER InstanceName
   The name of the instance to be configured, this defaults to the default instance name of MSSQLSERVER.
  
  .PARAMETER SqlServer
   An existing connection to a SQL Instance using a Microsoft.SqlServer.Management.Smo.Server object.
 
  .PARAMETER Name
    Specifies the name of the DDL trigger
 
  .PARAMETER DatabaseName
   Specifies the database on which the database DDL trigger is created.
 
  .PARAMETER CommandText
   Specifies the text body that is used to define the DDL trigger.
 
  .PARAMETER EventSet
   A Microsoft.SqlServer.Management.Smo.DatabaseDdlTriggerEventSet object specifying the events that should be triggered on.
 
  .PARAMETER ImplementationType
   The implementation type for the database data definition language (DDL) trigger. The options are SqlClr or TransactSql. This defaults to TransactSql.
 
  .PARAMETER Owner
   The database user that is the context used when the database DDL trigger executes. This defaults to the Sql Agent service account.
 
        .EXAMPLE
   [Microsoft.SqlServer.Management.Smo.DatabaseDdlTriggerEventSet]$EventSet = New-Object -TypeName Microsoft.SqlServer.Management.Smo.DatabaseDdlTriggerEventSet
   $EventSet.CreateProcedure = $true
 
   New-SQLDatabaseDDLTrigger -ComputerName "SQL2014" -InstanceName "MyInstance" `
         -Name "AuditModificationsTrigger" `
         -DatabaseName "master" `
         -CommandText "PRINT('Procedure created.')" `
         -EventSet $EventSet `
         -ImplementationType TransactSql
          
   Creates a DDL trigger on the master database that fires anytime a stored procedure is created on that database.
 
  .INPUTS
   None
 
  .OUTPUTS
   Microsoft.SqlServer.Management.Smo.DatabaseDdlTrigger
 
  .NOTES
   AUTHOR: Michael Haken
   LAST UPDATE: 5/11/2016
 #>
[CmdletBinding()]
Param(
[Parameter(ParameterSetName="NewConnection")]
        [System.String]$ComputerName = "localhost",
        [Parameter(ParameterSetName="NewConnection")]
        [System.String]$InstanceName = "MSSQLSERVER",
        [Parameter(ParameterSetName="ExistingConnection",Mandatory=$true,Position=0)]
        $SqlServer,
        [Parameter(Mandatory=$true)]
        [System.String]$Name,
[Parameter(Mandatory=$true)]
[System.String]$DatabaseName,
        [Parameter(Mandatory=$true)]
        [System.String]$CommandText,
        [Parameter(Mandatory=$true)]
        $EventSet,
        [Parameter()]
        [Validateset("SqlClr", "TransactSql")]
        [System.String]$ImplementationType = "TransactSql",
        [Parameter()]
        [System.String]$Owner
)

Begin {
Import-SqlModule -LoadSMO

if ([System.String]::IsNullOrEmpty($InstanceName)) {
$InstanceName = "MSSQLSERVER"
}

if ($SqlServer -ne $null -and $SqlServer.GetType() -ne [Microsoft.SqlServer.Management.Smo.Server]) {
            throw "SqlServer parameter must be an existing Microsoft.SqlServer.Management.Smo.Server object."
        }

        if ($EventSet -ne $null -and $EventSet.GetType() -ne [Microsoft.SqlServer.Management.Smo.DatabaseDdlTriggerEventSet]) {
            throw "EventSet parameter must be an existing Microsoft.SqlServer.Management.Smo.DatabaseDdlTriggerEventSet object."
        }
}

Process {
if ($PSCmdlet.ParameterSetName -eq "ExistingConnection") {
            [Microsoft.SqlServer.Management.Smo.Server]$SqlConnection = $SqlServer
        }
        else {
            [Microsoft.SqlServer.Management.Smo.Server]$SqlConnection = Get-SQLServer -ComputerName $ComputerName -InstanceName $InstanceName
        }

[Microsoft.SqlServer.Management.Smo.Database]$DB = $SqlConnection.Databases | Where-Object {$_.Name -ieq $DatabaseName} | Select-Object -First 1
        if ($DB -ne $null) {
if (($DB.Triggers | Where-Object {$_.Name -ieq $Name}) -eq $null) {
Write-Verbose -Message "Trigger does not already exist, creating it."

[Microsoft.SqlServer.Management.Smo.DatabaseDdlTrigger]$Trigger = New-Object -TypeName Microsoft.SqlServer.Management.Smo.DatabaseDdlTrigger($DB, $Name, $EventSet, $CommandText)
[Microsoft.SqlServer.Management.Smo.ImplementationType]$Impl = [Microsoft.SqlServer.Management.Smo.ImplementationType]::TransactSql

if([System.Enum]::TryParse($ImplementationType, [ref]$Impl)) {
$Trigger.ImplementationType = $Impl
}
else {
$Trigger.ImplementationType = [Microsoft.SqlServer.Management.Smo.ImplementationType]::TransactSql
}

if ([System.String]::IsNullOrEmpty($Owner)) {
$Owner = $SqlConnection.JobServer.ServiceAccount
}

$Trigger.TextMode = $false
$Trigger.ExecutionContext = [Microsoft.SqlServer.Management.Smo.ExecutionContext]::Owner
$Trigger.ExecutionContextUser = $Owner

try {
$Trigger.Create()
}
catch [Exception] {
if ($_.Exception.InnerException -ne $null) {
$Exception = $_.Exception
while ($Exception.InnerException -ne $null) {                      
$Exception = $Exception.InnerException
}

throw $Exception
}
else {
throw $_.Exception
}
}
}
else {
Write-Verbose -Message "Trigger already exists in $($DB.Name), returning it."
$Trigger = $DB.Triggers | Where-Object {$_.Name -ieq $Name} | Select-Object -First 1
}
        }
        else {
            Write-Error -Message "Database $DatabaseName could not be found."
        }
}

End {
        if ($Trigger -ne $null) {
            Write-Output $Trigger
        }
}
}

Function Get-SQLInstanceErrorLogPath {
<#
  .SYNOPSIS
   Gets the SQL Instance error log path.
 
  .DESCRIPTION
   The Get-SQLInstanceErrorLogPath cmdlet gets the default error log path for the instance.
 
  .PARAMETER ComputerName
   The server running the SQL instance to be configured or the virtual resource name of a clustered SQL instance. This defaults to localhost.
 
  .PARAMETER InstanceName
   The name of the instance to be configured, this defaults to the default instance name of MSSQLSERVER.
  
  .PARAMETER SqlServer
   An existing connection to a SQL Instance using a Microsoft.SqlServer.Management.Smo.Server object.
 
        .EXAMPLE
   Get-SQLInstanceErrorLogPath -ComputerName "SQL2014" -InstanceName "MyInstance"
          
   Gets the error log path for the MyInstance SQL Instance.
 
  .INPUTS
   None
 
  .OUTPUTS
   System.String
 
  .NOTES
   AUTHOR: Michael Haken
   LAST UPDATE: 5/11/2016
 #>
[CmdletBinding()]
Param(
[Parameter(ParameterSetName="NewConnection")]
        [System.String]$ComputerName = "localhost",
        [Parameter(ParameterSetName="NewConnection")]
        [System.String]$InstanceName = "MSSQLSERVER",
        [Parameter(ParameterSetName="ExistingConnection",Mandatory=$true,Position=0)]
        $SqlServer
)

Begin {
Import-SqlModule -LoadSMO

if ([System.String]::IsNullOrEmpty($InstanceName)) {
$InstanceName = "MSSQLSERVER"
}

if ($SqlServer -ne $null -and $SqlServer.GetType() -ne [Microsoft.SqlServer.Management.Smo.Server]) {
            throw "SqlServer parameter must be an existing Microsoft.SqlServer.Management.Smo.Server object."
        }
}

Process {
if ($PSCmdlet.ParameterSetName -eq "ExistingConnection") {
            [Microsoft.SqlServer.Management.Smo.Server]$SqlConnection = $SqlServer
        }
        else {
            [Microsoft.SqlServer.Management.Smo.Server]$SqlConnection = Get-SQLServer -ComputerName $ComputerName -InstanceName $InstanceName
        }
}

End {
Write-Output $SqlConnection.ErrorLogPath
}
}

#endregion

#region Utility Functions

Function Get-SQLServer {
<#
  .SYNOPSIS
   Connects to a provided SQL instance with SMO.
 
  .DESCRIPTION
   The Get-SQLServer cmdlet connects to the specified SQL Server and Instance and provides a Microsoft.SqlServer.Management.Smo.Server object back to use for futher actions.
 
  .PARAMETER ComputerName
   The server running the SQL instance to be configured or the virtual resource name of a clustered SQL instance. This defaults to localhost.
 
  .PARAMETER InstanceName
   The name of the instance to be configured, this defaults to the default instance name of MSSQLSERVER.
 
  .PARAMETER Port
   The port the instance is running on. If this parameter is not defined, the cmdlet uses the SQL Browser service to identify the correct port.
 
  .PARAMETER InitialCatalog
   The initial database to connect to. This defaults to master.
 
  .PARAMETER Credential
   The credential to use to connect to the database if SQL Authentication is being used. Otherwise Windows Integrated Authentication with SSPI is used.
  
        .EXAMPLE
   $Server = Get-SQLServer -ComputerName "SQL2014" -InstanceName "MyInstance"
          
   Connects to the specified SQL Instance and provides back a server object.
 
  .INPUTS
   None
 
  .OUTPUTS
   Microsoft.SqlServer.Management.Smo.Server
 
  .NOTES
   AUTHOR: Michael Haken
   LAST UPDATE: 5/11/2016
 #>
    [CmdletBinding()]
    Param(
        [Parameter(Position=0)]
        [System.String]$ComputerName = "localhost",
        [Parameter(Position=1)]
        [System.String]$InstanceName = "MSSQLSERVER",
[Parameter(Position=2)]
[System.Int32]$Port = -1,
[Parameter(Position=3)]
[System.String]$InitialCatalog = "master",
[Parameter(Position=4)]
[System.Management.Automation.PSCredential]$Credential = [System.Management.Automation.PSCredential]::Empty
    )

    Begin {
        Import-SqlModule -LoadSMO

if([System.String]::IsNullOrEmpty($InstanceName)) {
$InstanceName = "MSSQLSERVER"
}

if ($Credential -eq $null) {
$Credential = [System.Management.Automation.PSCredential]::Empty
}

        if([System.String]::IsNullOrEmpty($InitialCatalog)) {
            $InitialCatalog = "master"
        }
    }

    Process {
        [Microsoft.SqlServer.Management.Common.ServerConnection]$Connection = New-Object Microsoft.SqlServer.Management.Common.ServerConnection

        if ($InstanceName -ieq "MSSQLSERVER") {
            Write-Verbose -Message "Using the default SQL Instance."
            $Connection.ServerInstance = $ComputerName
            $ConnectionString = "Data Source = $ComputerName"
        }
        else {
            Write-Verbose -Message "Using a named SQL Instance, $InstanceName."
            $Connection.ServerInstance = "$ComputerName\$InstanceName"
            $ConnectionString = "Data Source = $ComputerName\$InstanceName"
        }

if ($Port -gt 0) {
            Write-Verbose -Message "Using a defined port, $Port."
            $Connection.ServerInstance += ",$Port"
$ConnectionString += ",$Port;"
}
else {
            Write-Verbose -Message "Using the SQL Browser service to determine the port."
$ConnectionString += ";"
}
        
        $Connection.DatabaseName = $InitialCatalog
$ConnectionString += " Initial Catalog=$InitialCatalog;"

if ($Credential -eq [System.Management.Automation.PSCredential]::Empty) {
            Write-Verbose -Message "Using SSPI Integrated Security."
$ConnectionString += " Integrated Security=SSPI;"
            $Connection.LoginSecure = $true
}
else {
            Write-Verbose -Message "Using UserName and Password to connect."
            $Connection.LoginSecure = $false
$Connection.Login = $Credential.UserName
            $Connection.SecurePassword = $Credential.Password

$ConnectionString += " Integrated Security = false; User ID = $($Credential.UserName); Password=$(New-Object -TypeName System.String('*',$Credential.Password.Length));"
}
        
        Write-Verbose -Message "Connection String:`n $ConnectionString"

        [Microsoft.SqlServer.Management.Smo.Server]$SqlConnection = New-Object Microsoft.SqlServer.Management.Smo.Server($Connection)
    }

    End {
        Write-Output $SqlConnection
    }
}

Function Get-SQLInstanceVersion {
<#
  .SYNOPSIS
   Gets version information about the provided SQL instance.
 
  .DESCRIPTION
   The cmdlet gets version information about the provided SQL instance including version number, edition, and patch level.
 
  .PARAMETER ComputerName
   The server running the SQL instance to be configured or the virtual resource name of a clustered SQL instance. This defaults to localhost.
 
  .PARAMETER InstanceName
   The name of the instance to be configured, this defaults to the default instance name of MSSQLSERVER.
 
  .PARAMETER SqlServer
   An existing connection to a SQL Instance using a Microsoft.SqlServer.Management.Smo.Server object.
 
  .PARAMETER ShortVersionOnly
   Just returns the 2 digit number corresponding to the major SQL version.
    
  .INPUTS
   None
 
  .OUTPUTS
   System.Int
 
   System.Management.Automation.PSCustomObject
 
        .EXAMPLE
   Get-SQLInstanceVersion
 
   Gets the instance version for the MSSQLSERVER instance on localhost.
 
  .NOTES
   AUTHOR: Michael Haken
   LAST UPDATE: 4/20/2016
 #>
[CmdletBinding()]
Param(
[Parameter(ParameterSetName="NewConnection")]
        [System.String]$ComputerName = "localhost",
        [Parameter(ParameterSetName="NewConnection")]
        [System.String]$InstanceName = "MSSQLSERVER",
        [Parameter(ParameterSetName="ExistingConnection",Mandatory=$true)]
        $SqlServer,
[Parameter()]
[switch]$ShortVersionOnly
)

Begin {
Import-SqlModule -LoadSMO

if ([System.String]::IsNullOrEmpty($InstanceName)) {
$InstanceName = "MSSQLSERVER"
}

if ($SqlServer -ne $null -and $SqlServer.GetType() -ne [Microsoft.SqlServer.Management.Smo.Server]) {
            throw "SqlServer parameter must be an existing Microsoft.SqlServer.Management.Smo.Server object."
        }
}

Process {
if ($PSCmdlet.ParameterSetName -eq "ExistingConnection") {
            [Microsoft.SqlServer.Management.Smo.Server]$SqlConnection = $SqlServer
        }
        else {
            [Microsoft.SqlServer.Management.Smo.Server]$SqlConnection = Get-SQLServer -ComputerName $ComputerName -InstanceName $InstanceName
        }

if ($ShortVersionOnly) {
$Result = $SqlConnection.VersionMajor
}
else {	
$Result = [PSCustomObject]@{
Version = $SqlConnection.VersionString;
ShortVersion = $SqlConnection.VersionMajor;
Edition = $SqlConnection.Edition;
ProductLevel = $SqlConnection.ProductLevel;
OSVersion = $SqlConnection.OSVersion;
}
}
}

End {
Write-Output $Result
}
}

Function Get-SQLInstanceDetails {
<#
  .SYNOPSIS
   Gets a core set of details about the provided SQL instance.
 
  .DESCRIPTION
   The cmdlet gets details about data directories, the instance version, the db enginer and sql agent service accounts and SIDs, and the installation path.
 
  .PARAMETER ComputerName
   The server running the SQL instance to be configured or the virtual resource name of a clustered SQL instance. This defaults to localhost.
 
  .PARAMETER InstanceName
   The name of the instance to be configured, this defaults to the default instance name of MSSQLSERVER.
 
  .PARAMETER SqlServer
   An existing connection to a SQL Instance using a Microsoft.SqlServer.Management.Smo.Server object.
    
  .INPUTS
   None
 
  .OUTPUTS
   System.Management.Automation.PSCustomObject
 
        .EXAMPLE
   Get-SQLInstanceDetails
 
   Gets the instance details for the MSSQLSERVER instance on localhost.
 
  .NOTES
   AUTHOR: Michael Haken
   LAST UPDATE: 5/11/2016
 #>
[CmdletBinding()]
Param(
[Parameter(ParameterSetName="NewConnection")]
        [System.String]$ComputerName = "localhost",
        [Parameter(ParameterSetName="NewConnection")]
        [System.String]$InstanceName = "MSSQLSERVER",
        [Parameter(ParameterSetName="ExistingConnection",Mandatory=$true)]
        $SqlServer
)

Begin {
Import-SqlModule -LoadSMO

if ([System.String]::IsNullOrEmpty($InstanceName)) {
$InstanceName = "MSSQLSERVER"
}

if ($SqlServer -ne $null -and $SqlServer.GetType() -ne [Microsoft.SqlServer.Management.Smo.Server]) {
            throw "SqlServer parameter must be an existing Microsoft.SqlServer.Management.Smo.Server object."
        }
}

Process {
if ($PSCmdlet.ParameterSetName -eq "ExistingConnection") {
            [Microsoft.SqlServer.Management.Smo.Server]$SqlConnection = $SqlServer
        }
        else {
            [Microsoft.SqlServer.Management.Smo.Server]$SqlConnection = Get-SQLServer -ComputerName $ComputerName -InstanceName $InstanceName
        }

$Version = Get-SQLInstanceVersion -ShortVersionOnly -SqlServer $SqlConnection
$SqlServiceAccount = $SqlConnection.ServiceAccount
$SqlAgentServiceAccount = $SqlConnection.JobServer.ServiceAccount
$ServiceAccountSid = Get-AccountSid -UserName $SqlServiceAccount -SqlServer $SqlConnection	
$SqlAgentAccountSid = Get-AccountSid -UserName $SqlAgentServiceAccount -SqlServer $SqlConnection

$Directories = Get-SQLInstanceDataDirectories -SqlServer $SqlConnection

$Result = [PSCustomObject]@{
Version = $Version;
DBEngineServiceAccount = $SqlServiceAccount;
DBEngineServiceAccountSid = $ServiceAccountSid;
SqlAgentServiceAccount = $SqlAgentServiceAccount;
SqlAgentServiceAccountSid = $SqlAgentAccountSid;
}

$DataDirectories = @()
foreach ($Directory in $Directories) {
Add-Member -InputObject $Result -MemberType NoteProperty -Name $Directory -Value $Directories.$Directory
$DataDirectories += $Directories.$Directory
}

Add-Member -InputObject $Result -MemberType NoteProperty -Name "DataDirectories" -Value $DataDirectories
}

End {
Write-Output $Result
}
}

Function Get-SQLInstanceDataDirectories {
<#
  .SYNOPSIS
   Gets the data directories used by the SQL instance.
 
  .DESCRIPTION
   The cmdlet gets the default data path, default log path, the tempDB path (if different than the default data path), the backup directory, and the SQL root directory.
 
  .PARAMETER ComputerName
   The server running the SQL instance to be configured or the virtual resource name of a clustered SQL instance. This defaults to localhost.
 
  .PARAMETER InstanceName
   The name of the instance to be configured, this defaults to the default instance name of MSSQLSERVER.
 
  .PARAMETER SqlServer
   An existing connection to a SQL Instance using a Microsoft.SqlServer.Management.Smo.Server object.
    
  .INPUTS
   None
 
  .OUTPUTS
   System.Management.Automation.PSCustomObject
 
        .EXAMPLE
   Set-SQLInstanceDataDirectories
 
   Gets the data directories for the MSSQLSERVER instance on localhost.
 
  .NOTES
   AUTHOR: Michael Haken
   LAST UPDATE: 5/11/2016
 #>
[CmdletBinding()]
Param(
[Parameter(ParameterSetName="NewConnection")]
        [System.String]$ComputerName = "localhost",
        [Parameter(ParameterSetName="NewConnection")]
        [System.String]$InstanceName = "MSSQLSERVER",
        [Parameter(ParameterSetName="ExistingConnection",Mandatory=$true)]
        $SqlServer
)

Begin {
Import-SqlModule -LoadSMO

if ([System.String]::IsNullOrEmpty($InstanceName)) {
$InstanceName = "MSSQLSERVER"
}

if ($SqlServer -ne $null -and $SqlServer.GetType() -ne [Microsoft.SqlServer.Management.Smo.Server]) {
            throw "SqlServer parameter must be an existing Microsoft.SqlServer.Management.Smo.Server object."
        }
}

Process {
if ($PSCmdlet.ParameterSetName -eq "ExistingConnection") {
            [Microsoft.SqlServer.Management.Smo.Server]$SqlConnection = $SqlServer
        }
        else {
            [Microsoft.SqlServer.Management.Smo.Server]$SqlConnection = Get-SQLServer -ComputerName $ComputerName -InstanceName $InstanceName
        }

$DataRoot = $SqlConnection.RootDirectory
$DefaultData = $SqlConnection.DefaultFile
$DefaultLog = $SqlConnection.DefaultLog
$BackupDirectory = $SqlConnection.BackupDirectory
$InstallationDirectory = $SqlConnection.InstallDataDirectory
$TempDBPath = $SqlConnection.Databases | Where-Object {$_.Name -eq "tempdb" } | Select-Object -ExpandProperty PrimaryFilePath
$MasterDBPath = $SqlConnection.MasterDBPath
$MasterDBLogPath = $SqlConnection.MasterDBLogPath
$SqlProgramDir = [System.IO.Directory]::GetParent([System.IO.Directory]::GetParent($SqlConnection.InstallDataDirectory)).FullName

$Directories = [PSCustomObject]@{SqlProgramDir = $SqlProgramDir; DefaultDataPath = $DefaultData; DefaultLogPath = $DefaultLog; BackupDirectory = $BackupDirectory; DataRootPath = $DataRoot; TempDBPath = $TempDBPath; MasterDBPath = $MasterDBPath; MasterDBLogPath = $MasterDBLogPath;}
}

End {
Write-Output $Directories
}
}

Function Get-SQLInstanceDefaultTraceFile {
<#
  .SYNOPSIS
   Gets the most recent default trace file for the SQL Instance.
 
  .DESCRIPTION
   The Get-SQLInstanceDefaultTraceFile cmdlet gets the most recent default trace file path for the instance.
 
  .PARAMETER ComputerName
   The server running the SQL instance to be configured or the virtual resource name of a clustered SQL instance. This defaults to localhost.
 
  .PARAMETER InstanceName
   The name of the instance to be configured, this defaults to the default instance name of MSSQLSERVER.
  
  .PARAMETER SqlServer
   An existing connection to a SQL Instance using a Microsoft.SqlServer.Management.Smo.Server object.
 
        .EXAMPLE
   Get-SQLInstanceDefaultTraceFile -ComputerName "SQL2014" -InstanceName "MyInstance"
          
   Gets the default trace file path for the MyInstance SQL Instance.
 
  .INPUTS
   None
 
  .OUTPUTS
   System.String
 
  .NOTES
   AUTHOR: Michael Haken
   LAST UPDATE: 5/11/2016
 #>
[CmdletBinding()]
    Param(
        [Parameter(ParameterSetName="NewConnection")]
        [System.String]$ComputerName = "localhost",
        [Parameter(ParameterSetName="NewConnection")]
        [System.String]$InstanceName = "MSSQLSERVER",
        [Parameter(ParameterSetName="ExistingConnection",Mandatory=$true)]
        $SqlServer
    )

    Begin {
        Import-SqlModule -LoadSMO

if ([System.String]::IsNullOrEmpty($InstanceName)) {
$InstanceName = "MSSQLSERVER"
}

        if ($SqlServer -ne $null -and $SqlServer.GetType() -ne [Microsoft.SqlServer.Management.Smo.Server]) {
            throw "SqlServer parameter must be an existing Microsoft.SqlServer.Management.Smo.Server object."
        }
    }

    Process {
        if ($PSCmdlet.ParameterSetName -eq "ExistingConnection") {
            [Microsoft.SqlServer.Management.Smo.Server]$SqlConnection = $SqlServer
        }
        else {
            [Microsoft.SqlServer.Management.Smo.Server]$SqlConnection = Get-SQLServer -ComputerName $ComputerName -InstanceName $InstanceName
        }

[Microsoft.SqlServer.Management.Smo.Database]$Master = $SqlConnection.Databases | Where-Object {$_.Name -eq "master"} | Select-Object -First 1
$Data = $Master.ExecuteWithResults("SELECT TOP 1 path FROM sys.traces WHERE is_default = 1 ORDER BY last_event_time DESC")
$TraceFilePath = $Data.Tables[0] | Select-Object -ExpandProperty Path
}

End {
Write-Output $TraceFilePath
}
}

Function Get-SQLInstanceAuditCommandText {
<#
  .SYNOPSIS
   Gets the command text to be used with creating Agent jobs to audit modifications to Functions, Triggers, and Stored Procedures.
 
  .DESCRIPTION
   The Get-SQLInstanceAuditCommandText cmdlet creates the T-SQL commands run by a job to audit CREATE, ALTER, and DROP commands issued against Functions, Triggers, and Stored Procedures.
 
   The text reviews the default trace log reviewing specific event Ids for these actions. It collects the information and sends an HTML formatted email to the email addresses in the specified Operator name.
 
  .PARAMETER DaysDiff
   The number of days in the trace file to be reviewed. This defaults to 1.
 
  .PARAMETER JobName
   The name of the job that will be running the command. This is only used as information in the HTML body.
 
  .PARAMETER OperatorToEmail
   The name of the Operator whose email addresses will be used with sp_send_dbmail for notifications.
  
  .PARAMETER EmailProfile
   The database mail profile used to send emails.
 
  .PARAMETER EmailSubject
   The subject line of the email. The SQL Instance name will be prepended to the subject for easy identification.
 
  .PARAMETER ObjectToAudit
   Specifies which audit the command text is being generated for. The options are Function, StoredProcedure, and Trigger.
 
        .EXAMPLE
   Get-SQLInstanceAuditCommandText -DaysDiff 1 -JobName "Alter_Function_Audit" -OperatorToEmail "Database Administrators" -EmailProfile "MSSQLSERVER Profile" -EmailSubject " - *Alert* Function Modification" -ObjectToAudit Function
          
   Creates the command text to be run by a job to audit CREATE, ALTER, and DROP actions on functions in the SQL Instance.
 
  .INPUTS
   None
 
  .OUTPUTS
   System.String
 
  .NOTES
   AUTHOR: Michael Haken
   LAST UPDATE: 5/11/2016
 #>
[CmdletBinding()]
Param(
[Parameter()]
[System.Int32]$DaysDiff = 1,
[Parameter(Mandatory=$true)]
[System.String]$JobName,
[Parameter(Mandatory=$true)]
[System.String]$OperatorToEmail,
[Parameter(Mandatory=$true)]
[System.String]$EmailProfile,
[Parameter(Mandatory=$true)]
[System.String]$EmailSubject,
[Parameter(Mandatory=$true)]
[ValidateSet("Function", "StoredProcedure", "Trigger")]
[System.String]$ObjectToAudit
)

Begin {

}

Process {
[System.String]$ObjectTypes = ""
[System.String]$ObjectName = ""
[System.String]$Events = "(46, 47, 164)" #ALTER, CREATE, DROP

switch ($ObjectToAudit) {
"Function" {
$ObjectName = "FunctionName"
$ObjectTypes = "(17985, 17993, 18000, 18002, 18004, 20038, 21318, 21321, 21574)"
}
"StoredProcedure" {
$ObjectName = "StoredProcedureName"
$ObjectTypes = "(8276, 16724, 21076)"
}
"Trigger" {
$ObjectName = "TriggerName"
$ObjectTypes = "(8272, 8280, 17232)"
}
}

[System.String]$Command = @"
USE [master];
 
DECLARE @filename varchar(255) = (SELECT TOP 1 path FROM master.sys.traces WHERE is_default = 1 ORDER BY last_event_time DESC);
 
CREATE TABLE #temp
 (
 DatabaseName varchar(255),
 $ObjectName varchar(255),
 ObjectId varchar(255),
 StartTime datetime,
 NTUserName varchar(255),
 LoginName varchar(255),
 HostName varchar(255),
 ApplicationName varchar(255),
 DBUserName varchar(255),
 SPID int,
 EventClass int,
 EventName varchar(255),
 EndTime datetime,
 MethodName varchar(255),
 TransactionID int,
 FileName varchar(255),
 IsSystem tinyint,
 ObjectType int
 )
 
INSERT INTO #temp
SELECT DISTINCT
 gt.DatabaseName,
 gt.ObjectName AS $ObjectName,
 gt.ObjectID,
 gt.StartTime,
 gt.HostName,
 gt.NTUserName,
 gt.LoginName,
 gt.ApplicationName,
 gt.DBUserName,
 gt.SPID,
 gt.EventClass,
 te.name AS EventName,
 gt.EndTime,
 gt.MethodName,
 gt.TransactionID,
 gt.FileName,
 gt.IsSystem,
 gt.ObjectType
FROM [fn_trace_gettable](@filename, DEFAULT) gt
 JOIN sys.trace_events te
 ON gt.EventClass = te.trace_event_id
WHERE
 gt.EventClass in $Events AND
 gt.ObjectType in $ObjectTypes AND
 DATEDIFF(dd, gt.StartTime, GETDATE()) < '$DaysDiff'
ORDER BY gt.StartTime DESC;
 
IF (SELECT count(*) FROM #temp) > 1
BEGIN
DECLARE @Html varchar(max) = '';
DECLARE @HtmlHeaders varchar(max) = '';
DECLARE @HtmlRows varchar(max) = '';
 
--get header, columns name
SELECT @HtmlHeaders = @HtmlHeaders + '<th>' + name + '</th>' FROM tempdb.sys.columns WHERE object_id = object_id('tempdb.dbo.#temp');
 
--convert table to XML PATH, ELEMENTS XSINIL is used to include NULL values
SET @HtmlRows = (SELECT * FROM #temp FOR XML PATH('tr'), ELEMENTS XSINIL)
 
--convert the way ELEMENTS XSINIL display NULL to display word NULL
SET @HtmlRows = REPLACE(@HtmlRows, 'xsi:nil="true"/>', '>NULL</td>');
SET @HtmlRows = REPLACE(@HtmlRows, '<tr xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">', '<tr>')
 
--FOR XML PATH will set tags for each column name, <columnName1>abc</columnName1><columnName2>def</columnName2>
--this will replace all the column names with TD (html table data tag)
SELECT @HtmlRows = REPLACE(REPLACE(@HtmlRows, '<' + name + '>', '<td>'), '</' + name + '>', '</td>')
FROM tempdb.sys.columns WHERE object_id = object_id('tempdb.dbo.#temp')
 
SET @Html = '<!DOCTYPE html>
<html>
 <head>
  <meta name="viewport" content="width=device-width" />
  <title>$JobName</title>
 </head>
    <style>
        .table {
            width:100%;
            table-layout:fixed;
            border:1px solid black;
        }
         
        .table td {
            word-break:break-all;
            word-wrap:break-word;
            vertical-align:top;
   text-align:left;
        }
 
        .table th {
            text-align:center;
        }
    </style>
  <body style="width:1200px;margin-left:auto;margin-right:auto;">
   <h1 style="text-align:center;">$JobName</h1>
    <div>
     <table class="table"><thead>'
     + '<tr>' + @HtmlHeaders + '</tr>'
     + '</thead><tbody>'
     + @HtmlRows
     + '</tbody></table></div></body></html>';
 
DECLARE @Recipients varchar(max) = (SELECT email_address FROM msdb.dbo.sysoperators WHERE name ='$OperatorToEmail');
DECLARE @Subject varchar(255) = @@ServiceName + '$EmailSubject';
 
EXEC msdb.dbo.sp_send_dbmail
@profile_name = '$EmailProfile',
@body_format = 'HTML',
@body = @Html,
@recipients = @Recipients,
@subject = @Subject
 
END
 
DROP TABLE #temp;
"@
}

End {
        Write-Output $Command
}
}

Function Get-SQLDatabaseDdlTriggerCommandText {
<#
  .SYNOPSIS
   Gets the command text to be used with creating Database DDL triggers to audit modifications to Functions, Triggers, and Stored Procedures.
 
  .DESCRIPTION
   The Get-SQLDatabaseDdlTriggerCommandText cmdlet creates the T-SQL commands run by a trigger to audit CREATE, ALTER, and DROP commands issued against Functions, Triggers, and Stored Procedures.
 
   The gets the event notification of the action. It collects the information and sends an HTML formatted email to the email addresses in the specified Operator name.
 
  .PARAMETER Subject
   The subject line of the email. The SQL Instance name will be prepended to the subject for easy identification.
 
  .PARAMETER OperatorToEmail
   The name of the Operator whose email addresses will be used with sp_send_dbmail for notifications.
  
  .PARAMETER EmailProfile
   The database mail profile used to send emails.
 
        .EXAMPLE
   Get-SQLDatabaseDdlTriggerCommandText -OperatorToEmail "Database Administrators" -EmailProfile "MSSQLSERVER Profile" -Subject " $DBName - *Alert* SQL Modification"
          
   Creates the command text to be run by a trigger to audit CREATE, ALTER, and DROP actions on functions on a specific SQL database. The database name that the trigger is being created for is also included as part of the subject line.
 
  .INPUTS
   None
 
  .OUTPUTS
   System.String
 
  .NOTES
   AUTHOR: Michael Haken
   LAST UPDATE: 5/11/2016
 #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [System.String]$OperatorToEmail,
        [Parameter(Mandatory=$true)]
        [System.String]$Subject,
        [Parameter(Mandatory=$true)]
        [System.String]$EmailProfile
    )

    Begin {
        <#
   Event Data Object
 
   <EVENT_INSTANCE>
    <EventType>event </EventType>
 
    <PostTime>date-time</PostTime>
    <SPID>spid</SPID>
    <ServerName>name </ServerName>
 
    <LoginName>login </LoginName>
    <UserName>name</UserName>
    <DatabaseName>name</DatabaseName>
 
    <SchemaName>name</SchemaName>
    <ObjectName>name</ObjectName>
    <ObjectType>type</ObjectType>
 
    <TSQLCommand>command</TSQLCommand>
   </EVENT_INSTANCE>
  #>
    }

    Process {
        $Command = @"
SET NOCOUNT ON;
     
DECLARE @EventData XML = EVENTDATA()
DECLARE @IpAddress varchar(32) = (SELECT client_net_address FROM master.sys.dm_exec_connections WHERE session_id = @@SPID);
   
CREATE TABLE #temp (
 EventDate datetime,
 EventType varchar(255),
 UserName varchar(255),
 EventDDL varchar(max),
 DatabaseName varchar(255),
 SchemaName varchar(255),
 ObjectName varchar(255),
 HostName varchar(255),
 IPAddress varchar(32),
 ProgramName varchar(255)
);
 
INSERT INTO #temp
SELECT
 @EventData.value('(/EVENT_INSTANCE/PostTime)[1]', 'datetime'),
 @EventData.value('(/EVENT_INSTANCE/EventType)[1]', 'varchar(255)'),
 @EventData.value('(/EVENT_INSTANCE/LoginName)[1]', 'varchar(255)'),
 @EventData.value('(/EVENT_INSTANCE/TSQLCommand)[1]', 'varchar(max)'),
 @EventData.value('(/EVENT_INSTANCE/DatabaseName)[1]', 'varchar(255)'),
 @EventData.value('(/EVENT_INSTANCE/SchemaName)[1]', 'varchar(255)'),
 @EventData.value('(/EVENT_INSTANCE/ObjectName)[1]', 'varchar(255)'),
 HOST_NAME(),
 @IpAddress,
 PROGRAM_NAME()
 
DECLARE @Html varchar(max) = '';
DECLARE @HtmlHeaders varchar(max) = '';
DECLARE @HtmlRows varchar(max) = '';
 
--get header, columns name
SELECT @HtmlHeaders = @HtmlHeaders + '<th>' + name + '</th>' FROM tempdb.sys.columns WHERE object_id = object_id('tempdb.dbo.#temp');
 
--convert table to XML PATH, ELEMENTS XSINIL is used to include NULL values
SET @HtmlRows = (SELECT * FROM #temp FOR XML PATH('tr'), ELEMENTS XSINIL)
 
--convert the way ELEMENTS XSINIL display NULL to display word NULL
SET @HtmlRows = REPLACE(@HtmlRows, 'xsi:nil="true"/>', '>NULL</td>');
SET @HtmlRows = REPLACE(@HtmlRows, '<tr xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">', '<tr>')
 
--FOR XML PATH will set tags for each column name, <columnName1>abc</columnName1><columnName2>def</columnName2>
--this will replace all the column names with TD (html table data tag)
SELECT @HtmlRows = REPLACE(REPLACE(@HtmlRows, '<' + name + '>', '<td>'), '</' + name + '>', '</td>')
FROM tempdb.sys.columns WHERE object_id = object_id('tempdb.dbo.#temp')
 
SET @Html = '<!DOCTYPE html>
    <html>
     <head>
      <meta name="viewport" content="width=device-width" />
      <title>Modified Stored Procedure/Function/Trigger</title>
     </head>
     <style>
      .table {
       width:100%;
       table-layout:fixed;
       border:1px solid black;
      }
         
      .table td {
       word-break:break-all;
       word-wrap:break-word;
       vertical-align:top;
       text-align:left;
      }
 
      .table th {
       text-align:center;
      }
     </style>
      <body style="width:1200px;margin-left:auto;margin-right:auto;">
       <h1 style="text-align:center;">Modified Stored Procedure/Function/Trigger</h1>
        <div>
         <table class="table"><thead>'
         + '<tr>' + @HtmlHeaders + '</tr>'
         + '</thead><tbody>'
         + @HtmlRows
         + '</tbody></table></div></body></html>';
     
DECLARE @Recipients varchar(max) = (SELECT email_address FROM msdb.dbo.sysoperators WHERE name = '$OperatorToEmail');
DECLARE @Subject varchar(255) = @@ServiceName + '$Subject'
 
EXEC msdb.dbo.sp_send_dbmail
 @profile_name = '$EmailProfile',
 @body_format = 'HTML',
 @body = @Html,
 @recipients = @Recipients,
 @subject = @Subject
     
 
DROP TABLE #temp;
"@
    }

    End {
        Write-Output $Command
    }
}

Function New-SQLInstanceDatabaseDirectoryAccessRuleSet {
<#
  .SYNOPSIS
   Creates the access rule set for the SQL Database Files and Folders.
 
  .DESCRIPTION
   The New-DatabaseDirectoryRuleSet cmdlet creates the access rules.
 
        .EXAMPLE
   New-DatabaseDirectoryRuleSet
 
         Creates the access rules.
 
  .INPUTS
   None
 
  .OUTPUTS
   System.Security.AccessControl.FileSystemAccessRule[]
 
  .NOTES
   AUTHOR: Michael Haken
   LASTEDIT: 4/16/2016
 #>

[CmdletBinding()]
Param(
[Parameter(Mandatory=$true)]
[System.Security.Principal.SecurityIdentifier]$SqlServiceAccountSid,
[Parameter(Mandatory=$true)]
[System.Security.Principal.SecurityIdentifier]$AdministratorsSid,
[Parameter()]
[System.Security.Principal.SecurityIdentifier]$SqlAgentSid = $null,
[Parameter()]
[switch]$IncludeLocalAdministrators
)

Begin {}

Process
{
$SqlServiceAce = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule($SqlServiceAccountSid,
            [System.Security.AccessControl.FileSystemRights]::FullControl,
            @([System.Security.AccessControl.InheritanceFlags]::ObjectInherit, [System.Security.AccessControl.InheritanceFlags]::ContainerInherit),
            [System.Security.AccessControl.PropagationFlags]::None,
            [System.Security.AccessControl.AccessControlType]::Allow
        )

$AdministratorsAce = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule($AdministratorsSid,
            [System.Security.AccessControl.FileSystemRights]::FullControl,
            @([System.Security.AccessControl.InheritanceFlags]::ObjectInherit, [System.Security.AccessControl.InheritanceFlags]::ContainerInherit),
            [System.Security.AccessControl.PropagationFlags]::None,
            [System.Security.AccessControl.AccessControlType]::Allow
        )

[System.Security.AccessControl.FileSystemAccessRule[]] $Rules = @($AdministratorsAce,$SqlServiceAce)

if ($SqlAgentSid -ne $null) {
$SqlAgentAce = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule($SqlAgentSid,
@([System.Security.AccessControl.FileSystemRights]::ReadAndExecute, [System.Security.AccessControl.FileSystemRights]::Write),
@([System.Security.AccessControl.InheritanceFlags]::ObjectInherit, [System.Security.AccessControl.InheritanceFlags]::ContainerInherit),
[System.Security.AccessControl.PropagationFlags]::None,
[System.Security.AccessControl.AccessControlType]::Allow
)

$Rules += $SqlAgentAce
}

if ($IncludeLocalAdministrators) {
$BuiltinAdministrators = New-Object -TypeName System.Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]::BuiltinAdministratorsSid, $null)

$LocalAdministratorsAce = New-Object System.Security.AccessControl.FileSystemAccessRule($BuiltinAdministrators,
[System.Security.AccessControl.FileSystemRights]::FullControl,
@([System.Security.AccessControl.InheritanceFlags]::ObjectInherit, [System.Security.AccessControl.InheritanceFlags]::ContainerInherit),
[System.Security.AccessControl.PropagationFlags]::None,
[System.Security.AccessControl.AccessControlType]::Allow)  

$Rules += $LocalAdministratorsAce  
}
}

End
{
Write-Output $Rules
}
}

Function New-SQLInstanceAuditLogAccessRuleSet {
<#
  .SYNOPSIS
   Creates the access rule set for the SQL Audit Logs.
 
  .DESCRIPTION
   The New-AuditLogRuleSet cmdlet creates the access rules.
 
        .EXAMPLE
   New-AuditLogRuleSet
 
         Creates the access rules.
 
  .INPUTS
   None
 
  .OUTPUTS
   System.Security.AccessControl.FileSystemAccessRule[]
 
  .NOTES
   AUTHOR: Michael Haken
   LASTEDIT: 4/16/2016
 #>

[CmdletBinding()]
Param(
[Parameter(Mandatory=$true)]
[System.Security.Principal.SecurityIdentifier]$SqlServiceAccountSid,
[Parameter(Mandatory=$true)]
[System.Security.Principal.SecurityIdentifier]$AuditAdministratorSid,
[Parameter(Mandatory=$true)]
[System.Security.Principal.SecurityIdentifier]$AuditorsSid,
[Parameter()]
[System.Security.Principal.SecurityIdentifier]$SqlAgentSid = $null

)

Begin {}

Process
{
<#
   Administrator(read)
 
   Users (none)
 
   Audit Administrator(Full Control)
 
   Auditors group (Read)
 
   SQL Server Service SID OR Service Account (Full Control)
 
   SQL Server SQL Agent Service SID OR Service Account, if SQL Server Agent is in use. (Read, Execute, Write)
  #>

        $BuiltinAdministrators = New-Object -TypeName System.Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]::BuiltinAdministratorsSid, $null)

        $AdministratorsAce = New-Object System.Security.AccessControl.FileSystemAccessRule($BuiltinAdministrators,
            [System.Security.AccessControl.FileSystemRights]::Read,
            @([System.Security.AccessControl.InheritanceFlags]::ObjectInherit, [System.Security.AccessControl.InheritanceFlags]::ContainerInherit),
            [System.Security.AccessControl.PropagationFlags]::None,
            [System.Security.AccessControl.AccessControlType]::Allow       
        )


        $AuditAdminAce = New-Object System.Security.AccessControl.FileSystemAccessRule($AuditAdministratorSid,
            [System.Security.AccessControl.FileSystemRights]::FullControl,
            @([System.Security.AccessControl.InheritanceFlags]::ObjectInherit, [System.Security.AccessControl.InheritanceFlags]::ContainerInherit),
            [System.Security.AccessControl.PropagationFlags]::None,
            [System.Security.AccessControl.AccessControlType]::Allow
        )

        $AuditorsAce = New-Object System.Security.AccessControl.FileSystemAccessRule($AuditorsSid,
            [System.Security.AccessControl.FileSystemRights]::Read,
            @([System.Security.AccessControl.InheritanceFlags]::ObjectInherit, [System.Security.AccessControl.InheritanceFlags]::ContainerInherit),
            [System.Security.AccessControl.PropagationFlags]::None,
            [System.Security.AccessControl.AccessControlType]::Allow
        )

$SqlServiceAce = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule($SqlServiceAccountSid,
            [System.Security.AccessControl.FileSystemRights]::FullControl,
            @([System.Security.AccessControl.InheritanceFlags]::ObjectInherit, [System.Security.AccessControl.InheritanceFlags]::ContainerInherit),
            [System.Security.AccessControl.PropagationFlags]::None,
            [System.Security.AccessControl.AccessControlType]::Allow
        )

[System.Security.AccessControl.FileSystemAccessRule[]] $Rules = @($AdministratorsAce,$AuditAdminAce,$AuditorsAce, $SqlServiceAce)

if ($SqlAgentSid -ne $null) {
$SqlAgentAce = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule($SqlAgentSid,
@([System.Security.AccessControl.FileSystemRights]::ReadAndExecute, [System.Security.AccessControl.FileSystemRights]::Write),
@([System.Security.AccessControl.InheritanceFlags]::ObjectInherit, [System.Security.AccessControl.InheritanceFlags]::ContainerInherit),
[System.Security.AccessControl.PropagationFlags]::None,
[System.Security.AccessControl.AccessControlType]::Allow
)

$Rules += $SqlAgentAce
}
}

End
{
Write-Output $Rules
}
}

Function New-SQLInstanceInstallationDirectoryAccessRuleSet {
<#
  .SYNOPSIS
   Creates the access rule set for the SQL installation directory.
 
  .DESCRIPTION
   The New-InstallationDirectoryRuleSet cmdlet creates the access rules.
 
        .EXAMPLE
   New-InstallationDirectoryRuleSet
 
         Creates the access rules.
 
  .INPUTS
   None
 
  .OUTPUTS
   System.DirectoryServices.FileSystemAccessRule[]
 
  .NOTES
   AUTHOR: Michael Haken
   LASTEDIT: 4/16/2016
 #>

[CmdletBinding()]
Param()

Begin {

}

Process {
$BuiltinAdministrators = New-Object -TypeName System.Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]::BuiltinAdministratorsSid, $null)

        $AdministratorAce = New-Object System.Security.AccessControl.FileSystemAccessRule($BuiltinAdministrators,
            [System.Security.AccessControl.FileSystemRights]::FullControl,
            @([System.Security.AccessControl.InheritanceFlags]::ObjectInherit, [System.Security.AccessControl.InheritanceFlags]::ContainerInherit),
            [System.Security.AccessControl.PropagationFlags]::None,
            [System.Security.AccessControl.AccessControlType]::Allow       
        )

$TrustedInstallerObj = New-Object -TypeName System.Security.Principal.NTAccount("NT Service", "TrustedInstaller")
$TrustedInstaller = ($TrustedInstallerObj.Translate([System.Security.Principal.SecurityIdentifier]))

        $TrustedInstallerAce = New-Object System.Security.AccessControl.FileSystemAccessRule($TrustedInstaller,
            [System.Security.AccessControl.FileSystemRights]::FullControl,
            @([System.Security.AccessControl.InheritanceFlags]::ObjectInherit, [System.Security.AccessControl.InheritanceFlags]::ContainerInherit),
            [System.Security.AccessControl.PropagationFlags]::None,
            [System.Security.AccessControl.AccessControlType]::Allow       
        )

$System = New-Object -TypeName System.Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]::LocalSystemSid, $null)

        $SystemAce = New-Object System.Security.AccessControl.FileSystemAccessRule($System,
            [System.Security.AccessControl.FileSystemRights]::FullControl,
            @([System.Security.AccessControl.InheritanceFlags]::ObjectInherit, [System.Security.AccessControl.InheritanceFlags]::ContainerInherit),
            [System.Security.AccessControl.PropagationFlags]::None,
            [System.Security.AccessControl.AccessControlType]::Allow       
        )

$Users = New-Object -TypeName System.Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]::BuiltinUsersSid, $null)

        $UsersAce = New-Object System.Security.AccessControl.FileSystemAccessRule($Users,
            @([System.Security.AccessControl.FileSystemRights]::ListDirectory, [System.Security.AccessControl.FileSystemRights]::ReadAndExecute),
            @([System.Security.AccessControl.InheritanceFlags]::ObjectInherit, [System.Security.AccessControl.InheritanceFlags]::ContainerInherit),
            [System.Security.AccessControl.PropagationFlags]::None,
            [System.Security.AccessControl.AccessControlType]::Allow       
        )

$CreatorOwner = New-Object -TypeName System.Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]::CreatorOwnerSid, $null)

        $CreatorOwnerAce = New-Object System.Security.AccessControl.FileSystemAccessRule($CreatorOwner,
            @([System.Security.AccessControl.FileSystemRights]::FullControl),
            @([System.Security.AccessControl.InheritanceFlags]::ObjectInherit, [System.Security.AccessControl.InheritanceFlags]::ContainerInherit),
            [System.Security.AccessControl.PropagationFlags]::InheritOnly,
            [System.Security.AccessControl.AccessControlType]::Allow       
        )

$AllAppPackages = New-Object -TypeName System.Security.Principal.SecurityIdentifier("S-1-15-2-1")

        $AllAppPackagesAce = New-Object System.Security.AccessControl.FileSystemAccessRule($AllAppPackages,
            [System.Security.AccessControl.FileSystemRights]::FullControl,
            @([System.Security.AccessControl.InheritanceFlags]::ObjectInherit, [System.Security.AccessControl.InheritanceFlags]::ContainerInherit),
            [System.Security.AccessControl.PropagationFlags]::None,
            [System.Security.AccessControl.AccessControlType]::Allow       
        )

[System.Security.AccessControl.FileSystemAccessRule[]] $Rules = @($AdministratorsAce,$TrustedInstallerAce,$SystemAce,$UsersAce,$CreatorOwnerAce,$AllAppPackagesAce)
}

End {
Write-Output $Rules
}
}

Function New-SQLInstanceInstallationDirectoryAuditRuleSet {
<#
  .SYNOPSIS
   Creates the audit rule set for the SQL installation directory.
 
  .DESCRIPTION
   The New-InstallationDirectoryAuditRuleSet cmdlet builds the required audit rule for auditing the SQL server installation directory.
 
        .EXAMPLE
   New-InstallationDirectoryAuditRuleSet
 
         Creates the audit rules.
 
  .INPUTS
   None
 
  .OUTPUTS
   System.Security.AccessControl.FileSystemAuditRule[]
 
  .NOTES
   AUTHOR: Michael Haken
   LAST UPDATED: 4/16/2016
 #>

[CmdletBinding()]
Param()

Begin
{
$Everyone = New-Object System.Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]::WorldSid, $null)
}
    
Process
{
$EveryoneFail = New-Object System.Security.AccessControl.FileSystemAuditRule($Everyone,
[System.Security.AccessControl.FileSystemRights]::Modify, 
@([System.Security.AccessControl.InheritanceFlags]::ContainerInherit, [System.Security.AccessControl.InheritanceFlags]::ObjectInherit),
[System.Security.AccessControl.PropagationFlags]::None,
[System.Security.AccessControl.AuditFlags]::Failure)

$EveryoneSuccess = New-Object System.Security.AccessControl.FileSystemAuditRule($Everyone,
[System.Security.AccessControl.FileSystemRights]::Modify, 
@([System.Security.AccessControl.InheritanceFlags]::ContainerInherit, [System.Security.AccessControl.InheritanceFlags]::ObjectInherit),
[System.Security.AccessControl.PropagationFlags]::None,
[System.Security.AccessControl.AuditFlags]::Success)

[System.Security.AccessControl.FileSystemAuditRule[]]$Rules = @($EveryoneFail, $EveryoneSuccess)
}

End
{
Write-Output $Rules
}
}

Function Get-SQLAuditObjectTypes {
[CmdletBinding()]
Param()

Begin {}

Process {}

End {
Write-Output $script:AuditObjectTypes
}
}

Function Import-SqlModule {
<#
  .SYNOPSIS
   Imports the SQLPS module and snapins.
 
  .DESCRIPTION
   The cmdlet checks for the SQLPS, Microsoft.SqlServer.Management.PSSnapins, and Microsoft.SqlServer.Management.PSProvider modules and loads them. It optionally adds the SQL Server Management Objects .NET assembly.
 
   At the end of the cmdlet, the PSDrive is set to SQLSERVER:\.
 
  .PARAMETER Version
   The version of SQL being configured, select from either 10 (SQL 2005), 11 (SQL 2008), 12 (SQL 2014), or 13 (SQL 2016). This defaults to 12. It is used to locate the correct modules in the filesystem.
 
  .INPUTS
   System.Int
 
  .OUTPUTS
   None
 
        .EXAMPLE
   Import-SqlModule
 
   Imports the SQL modules.
 
  .EXAMPLE
   Import-SqlModule -LoadSMO
 
   Imports the SQL modules and loads the SMO .NET assembly.
 
  .NOTES
   AUTHOR: Michael Haken
   LAST UPDATE: 4/18/2016
 #>
    [CmdletBinding()]
    Param(
        [Parameter(Position=0,ValueFromPipeline=$true)]
        [ValidateSet(10,11,12,13)]
        [int]$Version = 12,
[Parameter(Position=1)]
[switch]$LoadSMO
    )

    Begin {

    }

    Process {
        Write-Verbose -Message "Loading SQLPS PowerShell Modules."

        if (!(Get-Module -Name SQLPS)) {

            Import-Module -Name "${env:ProgramFiles(x86)}\Microsoft SQL Server\$($Version)0\Tools\PowerShell\Modules\SQLPS\SQLPS.PS1" -ErrorAction Stop -DisableNameChecking
            Write-Verbose -Message "Successfully loaded SQLPS Module."
Write-Debug -Message "Successfully loaded SQLPS Module."
        }
        else {
            Write-Debug "SQLPS module already loaded"
        }
        
        if (!(Get-Module -Name Microsoft.SqlServer.Management.PSSnapins)) {                                                                                                                                                     
            Import-Module -Name "${env:ProgramFiles(x86)}\Microsoft SQL Server\$($Version)0\Tools\PowerShell\Modules\SQLPS\Microsoft.SqlServer.Management.PSSnapins.dll" -ErrorAction Stop -DisableNameChecking
            Write-Verbose -Message "Successfully added SQL PS Snapin module."
Write-Debug -Message "Successfully added SQL PS Snapin module."
        }
        else {
            Write-Debug -Message "Microsoft.SqlServer.Management.PSSnapins module already loaded."
        }

        if(!(Get-Module -Name Microsoft.SqlServer.Management.PSProvider)) {
            Import-Module -Name "${env:ProgramFiles(x86)}\Microsoft SQL Server\$($Version)0\Tools\PowerShell\Modules\SQLPS\Microsoft.SqlServer.Management.PSProvider.dll" -ErrorAction Stop -DisableNameChecking
            Write-Verbose -Message "Successfully added SQL PS Provider module."
Write-Debug -Message "Successfully added SQL PS Provider module."
        }
        else {
            Write-Debug -Message "Microsoft.SqlServer.Management.PSProvider module already loaded."
        }

if ($LoadSMO) {
[System.Reflection.Assembly]::LoadWithPartialName('Microsoft.SqlServer.Smo') | Out-Null
            [System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.ConnectionInfoExtended") | Out-Null
            [System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SmoExtended") | Out-Null
            [System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.ConnectionInfo") | Out-Null
            [System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SmoEnum") | Out-Null
            [System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SqlWmiManagement") | Out-Null
Write-Debug -Message 'SQL Server Management Objects .NET assembly successfully loaded'
}
    }

    End {
        Push-Location "SQLSERVER:"
    }
}

Function Get-AccountSid {
<#
  .SYNOPSIS
   Gets the SID of a given username.
 
  .DESCRIPTION
   The cmdlet gets the SID of a username, which could a service account, local account, or domain account.
 
  .PARAMETER UserName
   The name of the user or service account to get the SID of.
 
  .PARAMETER ComputerName
   If the account is local to another machine, such as an NT SERVICE account or a true local account, specify the computer name the account is on.
 
  .PARAMETER SqlServer
   An existing connection to a SQL Instance using a Microsoft.SqlServer.Management.Smo.Server object. Use this enumerate the SID from a SQL Login.
 
  .PARAMETER Credential
   The credentials used to connect to the remote machine.
    
  .INPUTS
   None
 
  .OUTPUTS
   System.Security.Principal.SecurityIdentifier
 
        .EXAMPLE
   Get-AccountSid -UserName "Administrator"
 
   Gets the SID for the Administrator account.
 
  .EXAMPLE
   Get-AccountSid -UserName "NT AUTHORITY\Authenticated Users"
 
   Gets the SID for the Authenticated Users group.
 
  .EXAMPLE
   Get-AccountSid -UserName "NT AUTHORITY\System"
 
   Gets the SID for the SYSTEM account. The user name could also just be "System".
 
  .EXAMPLE
   Get-AccountSid -UserName "NT SERVICE\MSSQLSERVER" -ComputerName SqlServer
 
   Gets the SID for the virtual MSSQLSERVER service principal.
 
  .NOTES
   AUTHOR: Michael Haken
   LAST UPDATE: 4/20/2016
 #>
[CmdletBinding(DefaultParameterSetName="Computer")]
Param(
[Parameter(Position=0,Mandatory=$true,ValueFromPipeline=$true)]
[string]$UserName,
[Parameter(Position=1, ParameterSetName="Computer")]
[string]$ComputerName = [System.String]::Empty,
[Parameter(Position=1, ParameterSetName="Sql", Mandatory=$true)]
$SqlServer,
[Parameter(ParameterSetName="Computer")] 
[System.Management.Automation.PSCredential]
[System.Management.Automation.Credential()]
$Credential = [System.Management.Automation.PSCredential]::Empty  
)

Begin {
Write-Verbose "Getting SID for $UserName."
}

Process{
if ($PSCmdlet.ParameterSetName -eq "Sql") {
if ($SqlServer -ne $null -and $SqlServer.GetType() -ne [Microsoft.SqlServer.Management.Smo.Server]) {
throw "SqlServer parameter must be an existing Microsoft.SqlServer.Management.Smo.Server object."
}
$Offset = 0
$UserSid = New-Object -TypeName System.Security.Principal.SecurityIdentifier([System.Byte[]]($SqlServer.Logins | Where-Object {$_.Name -eq $UserName} | Select-Object -First 1 | Select-Object -ExpandProperty Sid), $Offset)
}
else {
if (![System.String]::IsNullOrEmpty($UserName)) {
if ($UserName.IndexOf("\") -ne -1) {
$Parts = $UserName.Split("\")
$Domain = $Parts[0]
$Name = $Parts[1]	
}
elseif ($UserName.IndexOf("@") -ne -1) {
$Parts = $UserName.Split("@")
$Domain = $Parts[1]
$Name = $Parts[0]
}
else {
try {
$Domain = (Get-ADDomain -Current LocalComputer -ErrorAction Stop).Name
}
catch [Exception] {
$Domain = $ComputerName
}

$Name = $UserName
}

if ($ComputerName -iin $script:LocalNames) {
$User = New-Object -TypeName System.Security.Principal.NTAccount($Domain, $Name)
$UserSid = $User.Translate([System.Security.Principal.SecurityIdentifier])
}
else {
$Session = New-PSSession -ComputerName $ComputerName -Credential $Credential

 $UserSid = Invoke-Command -Session $Session -ScriptBlock { 
$User = New-Object -TypeName System.Security.Principal.NTAccount($args[0], $args[1])
Write-Output $User.Translate([System.Security.Principal.SecurityIdentifier])
} -ArgumentList @($Domain, $Name)

Remove-PSSession -Session $Session
}
}
else {
$UserSid = $null
}
}
}

End {
Write-Output $UserSid
}
}

Function Set-FilePermissions {
<#
  .SYNOPSIS
   Sets permissions on a file or directory.
 
  .DESCRIPTION
   Will set permissions on file or directory with the provided rule set.
 
  .PARAMETER Path
   The path to the file to set permissions on.
 
  .PARAMETER Rules
   An array of File Access Rules to apply to the path.
 
  .PARAMETER Replace
   Indictates if all permissions on the path should be replaced with these. Otherwise the specified access rules will just be added to the target.
 
  .PARAMETER ForceInheritance
   Indicates if all permissions of child items should have their permissions replaced with these if the target is a directory.
 
        .EXAMPLE
   Set-Permissions -Path "c:\test.txt" -Rules $Rules
 
   Creates the rule set on the test.txt file.
 
  .INPUTS
   System.String, System.Security.AccessControl.FileSystemAccessRule[], System.Management.Automation.SwitchParameter, System.Management.Automation.SwitchParameter
 
  .OUTPUTS
   None
 
  .NOTES
   AUTHOR: Michael Haken
   LAST UPDATE: 2/28/2016
 #>

    Param 
    (
        [Parameter(Position=0,Mandatory=$true,ValueFromPipeLineByPropertyName=$true)]
        [string]$Path,
        [Parameter(Position=1,Mandatory=$true,ValueFromPipeLineByPropertyName=$true)]
        [System.Security.AccessControl.FileSystemAccessRule[]]$Rules,
[Parameter(Position=2,ValueFromPipeLineByPropertyName=$true)]
[switch]$Replace = $false,
[Parameter(Position=3,ValueFromPipeLineByPropertyName=$true)]
[switch]$ForceInheritance = $false
    )

    Begin 
{
Write-Verbose -Message "Setting permissions on $Path."
Push-Location -Path $env:SystemDrive
}

    Process
    {
try
        {
$Acl = Get-Acl -Path $Path

            if ($Acl -ne $null)
            {
#Should the permissions be replaced
if($Replace)
{
$OldAcls = $Acl.Access

foreach ($Rule in $OldAcls)
{
$Acl.RemoveAccessRule($Rule) | Out-Null
}
}
#Only remove the permissions for principals we're updating
else
{
$OldAcls = $Acl.Access | Where-Object {$Rules.IdentityReference -eq  $_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier])}

foreach ($Rule in $OldAcls)
{
$Acl.RemoveAccessRule($Rule) | Out-Null
}
}

                foreach ($Rule in $Rules)
                {
                    $Acl.AddAccessRule($Rule) | Out-Null
                }

                Set-Acl -Path $Path -AclObject $Acl

#If child permissions should be forced to inherit
if ($ForceInheritance)
{
Get-ChildItem -Path $Path -Recurse -Force | ForEach-Object {

                        $ChildAcl = Get-Acl -Path $_.FullName 
                        $ChildPath = $_.FullName

Write-Debug -Message "Forcing inheritance on $ChildPath."

                        foreach ($ChildRule in $ChildAcl.Access)
                        {
try
{
$ChildAcl.RemoveAccessRule($ChildRule) | Out-Null
}
catch [Exception]
{
Write-Warning "Error removing ACL from $ChildPath`: $($_.ToString())"
}
                        }

$ChildAcl.SetAccessRuleProtection($false,$false)

                        Set-Acl -Path $_.FullName -AclObject $ChildAcl | Out-Null
}
}
            }
            else
            {
                Write-Warning "Could not retrieve the ACL for $Path"
            }
        }
        catch [System.Exception]
        {
            Write-Warning $_.Exception.Message
        }
    }
    
    End {
Pop-Location 
}
}

Function Reset-InheritedPermissions {
<#
  .SYNOPSIS
   Resets a folder or a file's inherited permissions.
 
  .DESCRIPTION
   Will force inherited permissions at the path and optionally all of its children.
 
  .PARAMETER Path
   The path to the file to reset permissions on.
 
  .PARAMETER ResetChildPermissions
 
        .EXAMPLE
   Reset-InheritedPermissions -Path "c:\Program Files\Microsoft SQL Server"
 
   Forces inherited permissions on the Microsoft SQL Server directory and all of its children.
 
  .INPUTS
   System.String
 
  .OUTPUTS
   None
 
  .NOTES
   AUTHOR: Michael Haken
   LAST UPDATE: 4/20/2016
 #>
[CmdletBinding()]
Param(
[Parameter(Position=0,Mandatory=$true,ValueFromPipeline=$true)]
[string]$Path,
[Parameter(Position=1)]
[switch]$ResetChildPermissions
)

Begin {
Write-Verbose -Message "Setting inherited permissions on $Path."
Push-Location -Path c:\
}

Process {
try
        {
$Acl = Get-Acl -Path $Path

if ($Acl -ne $null)
{
$OldAcls = $Acl.Access

foreach ($Rule in $OldAcls)
{
$Acl.RemoveAccessRule($Rule) | Out-Null
}

$Acl.SetAccessRuleProtection($false,$false)	

Set-Acl -Path $Path -AclObject $Acl

if ($ResetChildPermissions) {

Get-ChildItem -Path $Path -Recurse -Force | ForEach-Object {

Write-Debug -Message "Setting inherited permissions on $ChildPath."

$ChildAcl = Get-Acl -Path $_.FullName 
$ChildPath = $_.FullName

foreach ($ChildRule in $ChildAcl.Access)
{
try
{
$ChildAcl.RemoveAccessRule($ChildRule) | Out-Null
}
catch [Exception]
{
Write-Warning "Error removing ACL from $ChildPath : $($_.Exception.Message)"
}
}

$ChildAcl.SetAccessRuleProtection($false,$false)

Set-Acl -Path $_.FullName -AclObject $ChildAcl | Out-Null
}
}
}
else
{
Write-Warning "Could not retrieve the ACL for $Path"
}
}
catch [System.Exception]
        {
            Write-Warning $_.Exception.Message
        }
}

End {
Pop-Location
}
}

Function Set-Auditing {
<#
  .SYNOPSIS
   Sets auditing on file system object.
 
  .DESCRIPTION
   The Set-Auditing cmdlet applies an audit rule set to a file system object.
 
  .PARAMETER Path
   The path to set auditing on.
 
  .PARAMETER AuditRules
   The array of FileSystemAuditRule.
 
  .PARAMETER ForceInheritance
   Forces inherited permissions on child objects.
 
        .EXAMPLE
   Set-Auditing -Path "c:\windows" -AuditRules $Rules
 
         Implements the audit rules.
 
  .INPUTS
   None
 
  .OUTPUTS
   None
 
  .NOTES
   AUTHOR: Michael Haken
   LASTEDIT: 4/16/2016
 #>

[CmdletBinding()]
    Param 
    (
        [Parameter(Position=0,ValueFromPipelineByPropertyName=$true,Mandatory=$true)]
        [string]$Path,
        [Parameter(Position=1,ValueFromPipelineByPropertyName=$true,Mandatory=$true)]
        [System.Security.AccessControl.FileSystemAuditRule[]]$AuditRules,
[Parameter(Position=2,ValueFromPipelineByPropertyName=$true)]
[switch]$ForceInheritance
    )

    Begin
    {
Push-Location -Path $env:SystemDrive
Write-Verbose -Message "Setting auditing on $Path."
    }

    Process
{
try
        {
$Acl = Get-Acl -Path $Path -Audit

if ($Acl -ne $null)
{
foreach ($Rule in $Rules)
{
$Acl.AddAuditRule($Rule)
}

Set-Acl -Path $Path -AclObject $Acl

#Enables inheritance on child objects
if ($ForceInheritance) {
Get-ChildItem -Path $Path -Recurse -Force | ForEach-Object {

$ChildAcl = Get-Acl -Path $_.FullName -Audit
$ChildPath = $_.FullName

Write-Debug -Message "Forcing inheritance on $ChildPath."
                
#Allows inheritance to change rules
$ChildAcl.SetAuditRuleProtection($false,$false)

#Because audit rules weren't explicitly removed, they are still present in addition to the inherited ones.
Set-Acl -Path $_.FullName -AclObject $ChildAcl | Out-Null
}
}
}
else
{
Write-Warning "Could not retrieve the ACL for $Path."
}
        }
        catch [System.Exception]
        {
Write-Warning $_.Exception.Message
        }
    }

    End {
Pop-Location
}
}

Function Where-NotMatchIn {
    Param(
        [Parameter(Position=0,ValueFromPipeline=$true)]
        [Object[]]$Input,
        [Parameter(Position=1)]
        [string[]]$Matches,
        [Parameter()]
        [string]$Property = [System.String]::Empty
    )

    Begin {
        $ReturnArray = @()
    }

    Process {

        foreach($Item in $Input) {
            $Match = $false

            if ($Property -eq [System.String]::Empty) {
                $Value = $Item
            }
            else {
                $Value = $Item.$Property
            }

            foreach ($Matcher in $Matches) {
                if ($Value -like $Matcher) {
                    $Match = $true
                    break
                }
            }

            if (!$Match) {
                $ReturnArray += $Item
            }
        }
    }

    End {
        Write-Output $ReturnArray
    }
}

#endregion

$script:AuditObjectTypes = @(
[PSCustomObject]@{Id = 8259; Name = "Check Constraint"},
[PSCustomObject]@{Id = 8260; Name = "Default (constraint or standalone)"},
[PSCustomObject]@{Id = 8262; Name = "Foreign-key Constraint" },
[PSCustomObject]@{Id = 8272; Name = "Stored Procedure" },
[PSCustomObject]@{Id = 8274; Name = "Rule" },
[PSCustomObject]@{Id = 8275; Name = "System Table"},
[PSCustomObject]@{Id = 8276; Name = "Trigger on Server"},
[PSCustomObject]@{Id = 8277; Name = "(User-defined) Table"},
[PSCustomObject]@{Id = 8278; Name = "View"},
[PSCustomObject]@{Id = 8280; Name = "Extended Stored Procedure"},
[PSCustomObject]@{Id = 16724; Name = "CLR Trigger"},
[PSCustomObject]@{Id = 16964; Name = "Database"},
[PSCustomObject]@{Id = 16975; Name = "Object"},
[PSCustomObject]@{Id = 17222; Name = "FullText Catalog"},
[PSCustomObject]@{Id = 17232; Name = "CLR Stored Procedure"},
[PSCustomObject]@{Id = 17235; Name = "Schema"},
[PSCustomObject]@{Id = 17475; Name = "Credential"},
[PSCustomObject]@{Id = 17491; Name = "DDL Event"},
[PSCustomObject]@{Id = 17741; Name = "Management Event"},
[PSCustomObject]@{Id = 17747; Name = "Security Event"},
[PSCustomObject]@{Id = 17749; Name = "User Event"},
[PSCustomObject]@{Id = 17985; Name= "CLR Aggregate Function"},
[PSCustomObject]@{Id = 17993; Name = "Inline Table-valued SQL Function"},
[PSCustomObject]@{Id = 18000; Name = "Partition Function"},
[PSCustomObject]@{Id = 18002; Name = "Replication Filter Procedure"},
[PSCustomObject]@{Id = 18004; Name = "Table-valued SQL Function"},
[PSCustomObject]@{Id = 18259; Name = "Server Role"},
[PSCustomObject]@{Id = 18263; Name = "Microsoft Windows Group"},
[PSCustomObject]@{Id = 19265; Name = "Asymmetric Key"},
[PSCustomObject]@{Id = 19277; Name = "Master Key"},
[PSCustomObject]@{Id = 19280; Name = "Primary Key"},
[PSCustomObject]@{Id = 19283; Name = "ObfusKey"},
[PSCustomObject]@{Id = 19521; Name = "Asymmetric Key Login"},
[PSCustomObject]@{Id = 19523; Name = "Certificate Login"},
[PSCustomObject]@{Id = 19538; Name = "Role"},
[PSCustomObject]@{Id = 19539; Name = "SQL Login"},
[PSCustomObject]@{Id = 19543; Name = "Windows Login"},
[PSCustomObject]@{Id = 20034; Name = "Remote Service Binding"},
[PSCustomObject]@{Id = 20036; Name = "Event Notification on Database"},
[PSCustomObject]@{Id = 20037; Name = "Event Notification"},
[PSCustomObject]@{Id = 20038; Name = "Scalar SQL Function"},
[PSCustomObject]@{Id = 20047; Name = "Event Notification on Object"},
[PSCustomObject]@{Id = 20051; Name = "Synonym"},
[PSCustomObject]@{Id = 20307; Name = "Sequence"},
[PSCustomObject]@{Id = 20549; Name = "End Point"},
[PSCustomObject]@{Id = 20801; Name = "Adhoc Queries which may be cached"},
[PSCustomObject]@{Id = 20816; Name = "Prepared Queries which may be cached"},
[PSCustomObject]@{Id = 20819; Name = "Service Broker Service Queue"},
[PSCustomObject]@{Id = 20821; Name = "Unique Constraint"},
[PSCustomObject]@{Id = 21057; Name = "Application Role"},
[PSCustomObject]@{Id = 21059; Name = "Certificate"},
[PSCustomObject]@{Id = 21075; Name = "Server"},
[PSCustomObject]@{Id = 21076; Name = "Transact-SQL Trigger"},
[PSCustomObject]@{Id = 21313; Name = "Assembly"},
[PSCustomObject]@{Id = 21318; Name = "CLR Scalar Function"},
[PSCustomObject]@{Id = 21321; Name = "Inline scalar SQL Function"},
[PSCustomObject]@{Id = 21328; Name = "Partition Scheme"},
[PSCustomObject]@{Id = 21333; Name = "User"},
[PSCustomObject]@{Id = 21571; Name = "Service Broker Service Contract"},
[PSCustomObject]@{Id = 21572; Name = "Trigger on Database"},
[PSCustomObject]@{Id = 21574; Name = "CLR Table-valued Function"},
[PSCustomObject]@{Id = 21577; Name = "Internal Table (For example, XML Node Table, Queue Table.)"},
[PSCustomObject]@{Id = 21581; Name = "Service Broker Message Type"},
[PSCustomObject]@{Id = 21586; Name = "Service Broker Route"},
[PSCustomObject]@{Id = 21587; Name = "Statistics"}
[PSCustomObject]@{Id = 21825; Name = "User"},
[PSCustomObject]@{Id = 21827; Name = "User"},
[PSCustomObject]@{Id = 21831; Name = "User"},
[PSCustomObject]@{Id = 21843; Name = "User"},
[PSCustomObject]@{Id = 21847; Name = "User"},
[PSCustomObject]@{Id = 22099; Name = "Service Broker Service"},
[PSCustomObject]@{Id = 22601; Name = "Index"},
[PSCustomObject]@{Id = 22604; Name = "Certificate Login"},
[PSCustomObject]@{Id = 22611; Name = "XMLSchema"},
[PSCustomObject]@{Id = 22868; Name = "Type"}
) 