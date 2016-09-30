# DISA SQL 2014 STIG
A collection of PowerShell and SQL scripts to automate the STIG process of a Microsoft SQL 2014 Server.

## PowerShell Module

To install the PowerShell module, copy both the psm1 and psd1 files to your PSModulePath.

You can find your PSModulePath by running the command

```
$Env:PSModulePath
[Environment]::GetEnvironmentVariable("PSModulePath")
```

Once you have installed the module to the module directory, use the command ```Import-Module SqlStig``` to import it into your session.

You may also manually import the module using the command

```
Import-Module -Name %PathToModule%
```

*From PowerShell Gallery*

> Configures all of the settings required by the SQL 2014 Draft STIG excluding the Logon Trigger requirement (I find this to essentially break everytime) and TDE.
> 
> Run both the Set-SQLInstanceStigItems and Set-SQLDatabaseStigItems to completely STIG the Instance. Requires some prior setup for Database Mail and Windows Groups.

Before running the script, create a new group on the computer called 'SQL Admins', and make sure that either the builtin Administrators group or your DBA is a member. If you are on a Windows Active Directory, ensure that there is a SQL Admins group created somewhere there.

In order to run the Powershell module itself, modify these commands to fit your environment.

```
Set-SQLInstanceStigItems -SqlAdministratorsName "<domain>\SQL Admins" `
                        -AuditorAdministratorsName "<domain>\SQL Admins" `
                        -AuditorsName "<domain>\SQL Admins" `
                        -ServerAuditor "<domain>\SQL Admins" `
                        -DatabaseAuditor "<domain>\SQL Admins" `
                        -ComputerName "<hostname>" `
                        -AuditDestination "ApplicationLog" `
                        -SysAdminRoleMembers @("<domain>\SQL Admins") `
                        -ServerAdminRoleMembers @("<domain>\SQL Admins") `
                        -DBCreatorRoleMembers @("<domain>\SQL Admins") `
                        -Verbose
```
```
Set-SQLDatabaseStigItems -ComputerName "<hostname>" `
                        -AllDatabases `
                        -OperatorToEmail "SQL Adminss" `
                        -MailProfile "MSSQLSERVER Profile" `
                        -Verbose
```

## SQL Scripts

Please see header comments in each script for their individual setup requirements.

## Notes

Now, I have noticed that the PowerShell module fails out on a couple of checks, and you may want to do a manual check after running. However, the bulk of STIG items will be knocked out by the combination of both the PowerShell Module and SQL scripts.

When running these, please try to run them as the builtin Administrator account on the system.
