# DISA-SQL-2014-STIG
A collection of PowerShell and SQL scripts to automate the STIG process of a Microsoft SQL 2014 Server.

## PowerShell Module

Configures all of the settings required by the SQL 2014 Draft STIG excluding the Logon Trigger requirement (I find this to essentially break everytime) and TDE.

Run both the Set-SQLInstanceStigItems and Set-SQLDatabaseStigItems to completely STIG the Instance. Requires some prior setup for Database Mail and Windows Groups.

## SQL Scripts

Please see header comments in each script for their individual setup requirements.
