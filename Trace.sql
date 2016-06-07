

--       Run this script to create and start an audit trace that audits required events.

--       Note:       Replace 'D:<path>\<filename>' with the path and file name to your audit file.
--                   Adjust the other parameters of SP_TRACE_CREATE to suit your system's circumstances.

--       The database server must be restarted for the trace to take effect.

--       Notes:
--       1. It is acceptable to have the required event IDs spread across multiple
--       traces, provided all of the traces are always active, and the event IDs are
--       grouped in a logical manner.
--       2. It is acceptable, from an auditing point of view, to include the same
--       event IDs in multiple traces. However, the effect of this redundancy on
--       performance, storage, and the consolidation of audit logs into a central
--       repository, should be taken into account.
--       3. It is acceptable to trace additional event IDs. This is the minimum list.
--       4. The DBA may find it useful to disable or modify the default trace 
--       that is set up by the SQL Server installation process. 
--       (Note that the script does NOT include code to do this.)
--       Use the following query to obtain a list of all event IDs, and their meaning:
--       SELECT * FROM sys.trace_events;
--       5. Because this script is designed to address multiple
--       requirements/vulnerabilities, it may appear to exceed the needs of some
--       individual requirements. However, it does represent the aggregate of all
--       such requirements.
--       6. Microsoft has flagged the trace techniques and tools used in this script
--       as deprecated. They will be removed after SQL Server 2016. Plan for
--       a transition to SQL Server Audit and/or Extended Events.


USE master;
GO

BEGIN TRY DROP PROCEDURE STIG_Trace END TRY BEGIN CATCH END CATCH;
GO

CREATE PROCEDURE STIG_Trace AS
-- Create a Queue
DECLARE @rc INT;
DECLARE @TraceID INT;
DECLARE @options INT = 6; -- SHUTDOWN_ON_ERROR (4), with Rollover (2)
	-- @options = 4 would provide stronger protection, but SP_TRACE_CREATE does not accept this documented setting.
DECLARE @tracefile NVARCHAR(128) = 'D:<path>\<filename>';  -- Trace file location and beginning of file name (SQL Server adds a suffix)
DECLARE @maxfilesize BIGINT = 500; -- Trace file size limit in megabytes
DECLARE @stoptime datetime = null; -- do not stop
DECLARE @filecount INT = 10; -- Number of trace files in the rollover set
EXEC @rc = SP_TRACE_CREATE
      @TraceID output,
      @options,
      @tracefile,
      @maxfilesize,
      @stoptime,
      @filecount
;
IF (@rc != 0) GOTO Error;

-- Set the events:
DECLARE @on BIT = 1;


-- Audit Login
-- Occurs when a user successfully logs in to SQL Server.
EXEC SP_TRACE_SETEVENT @TraceID, 14, 1,  @on; -- TextData
EXEC SP_TRACE_SETEVENT @TraceID, 14, 6,  @on; -- NTUserName
EXEC SP_TRACE_SETEVENT @TraceID, 14, 7,  @on; -- NTDomainName
EXEC SP_TRACE_SETEVENT @TraceID, 14, 8,  @on; -- HostName
EXEC SP_TRACE_SETEVENT @TraceID, 14, 9,  @on; -- ClientProcessID
EXEC SP_TRACE_SETEVENT @TraceID, 14, 10, @on; -- ApplicationName
EXEC SP_TRACE_SETEVENT @TraceID, 14, 11, @on; -- LoginName
EXEC SP_TRACE_SETEVENT @TraceID, 14, 12, @on; -- SPID
EXEC SP_TRACE_SETEVENT @TraceID, 14, 13, @on; -- Duration
EXEC SP_TRACE_SETEVENT @TraceID, 14, 14, @on; -- StartTime
EXEC SP_TRACE_SETEVENT @TraceID, 14, 15, @on; -- EndTime
EXEC SP_TRACE_SETEVENT @TraceID, 14, 19, @on; -- Permissions
EXEC SP_TRACE_SETEVENT @TraceID, 14, 21, @on; -- EventSubClass
EXEC SP_TRACE_SETEVENT @TraceID, 14, 23, @on; -- Success (successful use of permissions)
EXEC SP_TRACE_SETEVENT @TraceID, 14, 26, @on; -- ServerName
EXEC SP_TRACE_SETEVENT @TraceID, 14, 28, @on; -- ObjectType
EXEC SP_TRACE_SETEVENT @TraceID, 14, 30, @on; -- State
EXEC SP_TRACE_SETEVENT @TraceID, 14, 31, @on; -- Error
EXEC SP_TRACE_SETEVENT @TraceID, 14, 34, @on; -- ObjectName
EXEC SP_TRACE_SETEVENT @TraceID, 14, 35, @on; -- DatabaseName
EXEC SP_TRACE_SETEVENT @TraceID, 14, 37, @on; -- OwnerName
EXEC SP_TRACE_SETEVENT @TraceID, 14, 38, @on; -- RoleName
EXEC SP_TRACE_SETEVENT @TraceID, 14, 39, @on; -- TargetUserName
EXEC SP_TRACE_SETEVENT @TraceID, 14, 40, @on; -- DBUserName
EXEC SP_TRACE_SETEVENT @TraceID, 14, 41, @on; -- LoginSid
EXEC SP_TRACE_SETEVENT @TraceID, 14, 42, @on; -- TargetLoginName
EXEC SP_TRACE_SETEVENT @TraceID, 14, 43, @on; -- TargetLoginSid
EXEC SP_TRACE_SETEVENT @TraceID, 14, 44, @on; -- ColumnPermissions
EXEC SP_TRACE_SETEVENT @TraceID, 14, 45, @on; -- LinkedServerName
EXEC SP_TRACE_SETEVENT @TraceID, 14, 46, @on; -- ProviderName
EXEC SP_TRACE_SETEVENT @TraceID, 14, 51, @on; -- EventSequence
EXEC SP_TRACE_SETEVENT @TraceID, 14, 59, @on; -- ParentName
EXEC SP_TRACE_SETEVENT @TraceID, 14, 60, @on; -- IsSystem
EXEC SP_TRACE_SETEVENT @TraceID, 14, 64, @on; -- SessionLoginName
-- Audit Logout
-- Occurs when a user logs out of SQL Server.
EXEC SP_TRACE_SETEVENT @TraceID, 15, 1,  @on; -- TextData
EXEC SP_TRACE_SETEVENT @TraceID, 15, 6,  @on; -- NTUserName
EXEC SP_TRACE_SETEVENT @TraceID, 15, 7,  @on; -- NTDomainName
EXEC SP_TRACE_SETEVENT @TraceID, 15, 8,  @on; -- HostName
EXEC SP_TRACE_SETEVENT @TraceID, 15, 9,  @on; -- ClientProcessID
EXEC SP_TRACE_SETEVENT @TraceID, 15, 10, @on; -- ApplicationName
EXEC SP_TRACE_SETEVENT @TraceID, 15, 11, @on; -- LoginName
EXEC SP_TRACE_SETEVENT @TraceID, 15, 12, @on; -- SPID
EXEC SP_TRACE_SETEVENT @TraceID, 15, 13, @on; -- Duration
EXEC SP_TRACE_SETEVENT @TraceID, 15, 14, @on; -- StartTime
EXEC SP_TRACE_SETEVENT @TraceID, 15, 15, @on; -- EndTime
EXEC SP_TRACE_SETEVENT @TraceID, 15, 19, @on; -- Permissions
EXEC SP_TRACE_SETEVENT @TraceID, 15, 21, @on; -- EventSubClass
EXEC SP_TRACE_SETEVENT @TraceID, 15, 23, @on; -- Success (successful use of permissions)
EXEC SP_TRACE_SETEVENT @TraceID, 15, 26, @on; -- ServerName
EXEC SP_TRACE_SETEVENT @TraceID, 15, 28, @on; -- ObjectType
EXEC SP_TRACE_SETEVENT @TraceID, 15, 30, @on; -- State
EXEC SP_TRACE_SETEVENT @TraceID, 15, 31, @on; -- Error
EXEC SP_TRACE_SETEVENT @TraceID, 15, 34, @on; -- ObjectName
EXEC SP_TRACE_SETEVENT @TraceID, 15, 35, @on; -- DatabaseName
EXEC SP_TRACE_SETEVENT @TraceID, 15, 37, @on; -- OwnerName
EXEC SP_TRACE_SETEVENT @TraceID, 15, 38, @on; -- RoleName
EXEC SP_TRACE_SETEVENT @TraceID, 15, 39, @on; -- TargetUserName
EXEC SP_TRACE_SETEVENT @TraceID, 15, 40, @on; -- DBUserName
EXEC SP_TRACE_SETEVENT @TraceID, 15, 41, @on; -- LoginSid
EXEC SP_TRACE_SETEVENT @TraceID, 15, 42, @on; -- TargetLoginName
EXEC SP_TRACE_SETEVENT @TraceID, 15, 43, @on; -- TargetLoginSid
EXEC SP_TRACE_SETEVENT @TraceID, 15, 44, @on; -- ColumnPermissions
EXEC SP_TRACE_SETEVENT @TraceID, 15, 45, @on; -- LinkedServerName
EXEC SP_TRACE_SETEVENT @TraceID, 15, 46, @on; -- ProviderName
EXEC SP_TRACE_SETEVENT @TraceID, 15, 51, @on; -- EventSequence
EXEC SP_TRACE_SETEVENT @TraceID, 15, 59, @on; -- ParentName
EXEC SP_TRACE_SETEVENT @TraceID, 15, 60, @on; -- IsSystem
EXEC SP_TRACE_SETEVENT @TraceID, 15, 64, @on; -- SessionLoginName
-- Attention
-- Occurs when attention events, such as client interrupt requests
-- or broken client connections, happen.
EXEC SP_TRACE_SETEVENT @TraceID, 16, 1,  @on; -- TextData
EXEC SP_TRACE_SETEVENT @TraceID, 16, 6,  @on; -- NTUserName
EXEC SP_TRACE_SETEVENT @TraceID, 16, 7,  @on; -- NTDomainName
EXEC SP_TRACE_SETEVENT @TraceID, 16, 8,  @on; -- HostName
EXEC SP_TRACE_SETEVENT @TraceID, 16, 9,  @on; -- ClientProcessID
EXEC SP_TRACE_SETEVENT @TraceID, 16, 10, @on; -- ApplicationName
EXEC SP_TRACE_SETEVENT @TraceID, 16, 11, @on; -- LoginName
EXEC SP_TRACE_SETEVENT @TraceID, 16, 12, @on; -- SPID
EXEC SP_TRACE_SETEVENT @TraceID, 16, 13, @on; -- Duration
EXEC SP_TRACE_SETEVENT @TraceID, 16, 14, @on; -- StartTime
EXEC SP_TRACE_SETEVENT @TraceID, 16, 15, @on; -- EndTime
EXEC SP_TRACE_SETEVENT @TraceID, 16, 19, @on; -- Permissions
EXEC SP_TRACE_SETEVENT @TraceID, 16, 21, @on; -- EventSubClass
EXEC SP_TRACE_SETEVENT @TraceID, 16, 23, @on; -- Success (successful use of permissions)
EXEC SP_TRACE_SETEVENT @TraceID, 16, 26, @on; -- ServerName
EXEC SP_TRACE_SETEVENT @TraceID, 16, 28, @on; -- ObjectType
EXEC SP_TRACE_SETEVENT @TraceID, 16, 30, @on; -- State
EXEC SP_TRACE_SETEVENT @TraceID, 16, 31, @on; -- Error
EXEC SP_TRACE_SETEVENT @TraceID, 16, 34, @on; -- ObjectName
EXEC SP_TRACE_SETEVENT @TraceID, 16, 35, @on; -- DatabaseName
EXEC SP_TRACE_SETEVENT @TraceID, 16, 37, @on; -- OwnerName
EXEC SP_TRACE_SETEVENT @TraceID, 16, 38, @on; -- RoleName
EXEC SP_TRACE_SETEVENT @TraceID, 16, 39, @on; -- TargetUserName
EXEC SP_TRACE_SETEVENT @TraceID, 16, 40, @on; -- DBUserName
EXEC SP_TRACE_SETEVENT @TraceID, 16, 41, @on; -- LoginSid
EXEC SP_TRACE_SETEVENT @TraceID, 16, 42, @on; -- TargetLoginName
EXEC SP_TRACE_SETEVENT @TraceID, 16, 43, @on; -- TargetLoginSid
EXEC SP_TRACE_SETEVENT @TraceID, 16, 44, @on; -- ColumnPermissions
EXEC SP_TRACE_SETEVENT @TraceID, 16, 45, @on; -- LinkedServerName
EXEC SP_TRACE_SETEVENT @TraceID, 16, 46, @on; -- ProviderName
EXEC SP_TRACE_SETEVENT @TraceID, 16, 51, @on; -- EventSequence
EXEC SP_TRACE_SETEVENT @TraceID, 16, 59, @on; -- ParentName
EXEC SP_TRACE_SETEVENT @TraceID, 16, 60, @on; -- IsSystem
EXEC SP_TRACE_SETEVENT @TraceID, 16, 64, @on; -- SessionLoginName
-- ExistingConnection
-- Detects all activity by users connected to SQL Server before the trace started.
EXEC SP_TRACE_SETEVENT @TraceID, 17, 1,  @on; -- TextData
EXEC SP_TRACE_SETEVENT @TraceID, 17, 6,  @on; -- NTUserName
EXEC SP_TRACE_SETEVENT @TraceID, 17, 7,  @on; -- NTDomainName
EXEC SP_TRACE_SETEVENT @TraceID, 17, 8,  @on; -- HostName
EXEC SP_TRACE_SETEVENT @TraceID, 17, 9,  @on; -- ClientProcessID
EXEC SP_TRACE_SETEVENT @TraceID, 17, 10, @on; -- ApplicationName
EXEC SP_TRACE_SETEVENT @TraceID, 17, 11, @on; -- LoginName
EXEC SP_TRACE_SETEVENT @TraceID, 17, 12, @on; -- SPID
EXEC SP_TRACE_SETEVENT @TraceID, 17, 13, @on; -- Duration
EXEC SP_TRACE_SETEVENT @TraceID, 17, 14, @on; -- StartTime
EXEC SP_TRACE_SETEVENT @TraceID, 17, 15, @on; -- EndTime
EXEC SP_TRACE_SETEVENT @TraceID, 17, 19, @on; -- Permissions
EXEC SP_TRACE_SETEVENT @TraceID, 17, 21, @on; -- EventSubClass
EXEC SP_TRACE_SETEVENT @TraceID, 17, 23, @on; -- Success (successful use of permissions)
EXEC SP_TRACE_SETEVENT @TraceID, 17, 26, @on; -- ServerName
EXEC SP_TRACE_SETEVENT @TraceID, 17, 28, @on; -- ObjectType
EXEC SP_TRACE_SETEVENT @TraceID, 17, 30, @on; -- State
EXEC SP_TRACE_SETEVENT @TraceID, 17, 31, @on; -- Error
EXEC SP_TRACE_SETEVENT @TraceID, 17, 34, @on; -- ObjectName
EXEC SP_TRACE_SETEVENT @TraceID, 17, 35, @on; -- DatabaseName
EXEC SP_TRACE_SETEVENT @TraceID, 17, 37, @on; -- OwnerName
EXEC SP_TRACE_SETEVENT @TraceID, 17, 38, @on; -- RoleName
EXEC SP_TRACE_SETEVENT @TraceID, 17, 39, @on; -- TargetUserName
EXEC SP_TRACE_SETEVENT @TraceID, 17, 40, @on; -- DBUserName
EXEC SP_TRACE_SETEVENT @TraceID, 17, 41, @on; -- LoginSid
EXEC SP_TRACE_SETEVENT @TraceID, 17, 42, @on; -- TargetLoginName
EXEC SP_TRACE_SETEVENT @TraceID, 17, 43, @on; -- TargetLoginSid
EXEC SP_TRACE_SETEVENT @TraceID, 17, 44, @on; -- ColumnPermissions
EXEC SP_TRACE_SETEVENT @TraceID, 17, 45, @on; -- LinkedServerName
EXEC SP_TRACE_SETEVENT @TraceID, 17, 46, @on; -- ProviderName
EXEC SP_TRACE_SETEVENT @TraceID, 17, 51, @on; -- EventSequence
EXEC SP_TRACE_SETEVENT @TraceID, 17, 59, @on; -- ParentName
EXEC SP_TRACE_SETEVENT @TraceID, 17, 60, @on; -- IsSystem
EXEC SP_TRACE_SETEVENT @TraceID, 17, 64, @on; -- SessionLoginName
-- Audit Server Starts and Stops
-- Occurs when the SQL Server service state is modified.
EXEC SP_TRACE_SETEVENT @TraceID, 18, 1,  @on; -- TextData
EXEC SP_TRACE_SETEVENT @TraceID, 18, 6,  @on; -- NTUserName
EXEC SP_TRACE_SETEVENT @TraceID, 18, 7,  @on; -- NTDomainName
EXEC SP_TRACE_SETEVENT @TraceID, 18, 8,  @on; -- HostName
EXEC SP_TRACE_SETEVENT @TraceID, 18, 9,  @on; -- ClientProcessID
EXEC SP_TRACE_SETEVENT @TraceID, 18, 10, @on; -- ApplicationName
EXEC SP_TRACE_SETEVENT @TraceID, 18, 11, @on; -- LoginName
EXEC SP_TRACE_SETEVENT @TraceID, 18, 12, @on; -- SPID
EXEC SP_TRACE_SETEVENT @TraceID, 18, 13, @on; -- Duration
EXEC SP_TRACE_SETEVENT @TraceID, 18, 14, @on; -- StartTime
EXEC SP_TRACE_SETEVENT @TraceID, 18, 15, @on; -- EndTime
EXEC SP_TRACE_SETEVENT @TraceID, 18, 19, @on; -- Permissions
EXEC SP_TRACE_SETEVENT @TraceID, 18, 21, @on; -- EventSubClass
EXEC SP_TRACE_SETEVENT @TraceID, 18, 23, @on; -- Success (successful use of permissions)
EXEC SP_TRACE_SETEVENT @TraceID, 18, 26, @on; -- ServerName
EXEC SP_TRACE_SETEVENT @TraceID, 18, 28, @on; -- ObjectType
EXEC SP_TRACE_SETEVENT @TraceID, 18, 30, @on; -- State
EXEC SP_TRACE_SETEVENT @TraceID, 18, 31, @on; -- Error
EXEC SP_TRACE_SETEVENT @TraceID, 18, 34, @on; -- ObjectName
EXEC SP_TRACE_SETEVENT @TraceID, 18, 35, @on; -- DatabaseName
EXEC SP_TRACE_SETEVENT @TraceID, 18, 37, @on; -- OwnerName
EXEC SP_TRACE_SETEVENT @TraceID, 18, 38, @on; -- RoleName
EXEC SP_TRACE_SETEVENT @TraceID, 18, 39, @on; -- TargetUserName
EXEC SP_TRACE_SETEVENT @TraceID, 18, 40, @on; -- DBUserName
EXEC SP_TRACE_SETEVENT @TraceID, 18, 41, @on; -- LoginSid
EXEC SP_TRACE_SETEVENT @TraceID, 18, 42, @on; -- TargetLoginName
EXEC SP_TRACE_SETEVENT @TraceID, 18, 43, @on; -- TargetLoginSid
EXEC SP_TRACE_SETEVENT @TraceID, 18, 44, @on; -- ColumnPermissions
EXEC SP_TRACE_SETEVENT @TraceID, 18, 45, @on; -- LinkedServerName
EXEC SP_TRACE_SETEVENT @TraceID, 18, 46, @on; -- ProviderName
EXEC SP_TRACE_SETEVENT @TraceID, 18, 51, @on; -- EventSequence
EXEC SP_TRACE_SETEVENT @TraceID, 18, 59, @on; -- ParentName
EXEC SP_TRACE_SETEVENT @TraceID, 18, 60, @on; -- IsSystem
EXEC SP_TRACE_SETEVENT @TraceID, 18, 64, @on; -- SessionLoginName
-- Audit Login Failed
-- Indicates that a login attempt to SQL Server from a client failed.
EXEC SP_TRACE_SETEVENT @TraceID, 20, 1,  @on; -- TextData
EXEC SP_TRACE_SETEVENT @TraceID, 20, 6,  @on; -- NTUserName
EXEC SP_TRACE_SETEVENT @TraceID, 20, 7,  @on; -- NTDomainName
EXEC SP_TRACE_SETEVENT @TraceID, 20, 8,  @on; -- HostName
EXEC SP_TRACE_SETEVENT @TraceID, 20, 9,  @on; -- ClientProcessID
EXEC SP_TRACE_SETEVENT @TraceID, 20, 10, @on; -- ApplicationName
EXEC SP_TRACE_SETEVENT @TraceID, 20, 11, @on; -- LoginName
EXEC SP_TRACE_SETEVENT @TraceID, 20, 12, @on; -- SPID
EXEC SP_TRACE_SETEVENT @TraceID, 20, 13, @on; -- Duration
EXEC SP_TRACE_SETEVENT @TraceID, 20, 14, @on; -- StartTime
EXEC SP_TRACE_SETEVENT @TraceID, 20, 15, @on; -- EndTime
EXEC SP_TRACE_SETEVENT @TraceID, 20, 19, @on; -- Permissions
EXEC SP_TRACE_SETEVENT @TraceID, 20, 21, @on; -- EventSubClass
EXEC SP_TRACE_SETEVENT @TraceID, 20, 23, @on; -- Success (successful use of permissions)
EXEC SP_TRACE_SETEVENT @TraceID, 20, 26, @on; -- ServerName
EXEC SP_TRACE_SETEVENT @TraceID, 20, 28, @on; -- ObjectType
EXEC SP_TRACE_SETEVENT @TraceID, 20, 30, @on; -- State
EXEC SP_TRACE_SETEVENT @TraceID, 20, 31, @on; -- Error
EXEC SP_TRACE_SETEVENT @TraceID, 20, 34, @on; -- ObjectName
EXEC SP_TRACE_SETEVENT @TraceID, 20, 35, @on; -- DatabaseName
EXEC SP_TRACE_SETEVENT @TraceID, 20, 37, @on; -- OwnerName
EXEC SP_TRACE_SETEVENT @TraceID, 20, 38, @on; -- RoleName
EXEC SP_TRACE_SETEVENT @TraceID, 20, 39, @on; -- TargetUserName
EXEC SP_TRACE_SETEVENT @TraceID, 20, 40, @on; -- DBUserName
EXEC SP_TRACE_SETEVENT @TraceID, 20, 41, @on; -- LoginSid
EXEC SP_TRACE_SETEVENT @TraceID, 20, 42, @on; -- TargetLoginName
EXEC SP_TRACE_SETEVENT @TraceID, 20, 43, @on; -- TargetLoginSid
EXEC SP_TRACE_SETEVENT @TraceID, 20, 44, @on; -- ColumnPermissions
EXEC SP_TRACE_SETEVENT @TraceID, 20, 45, @on; -- LinkedServerName
EXEC SP_TRACE_SETEVENT @TraceID, 20, 46, @on; -- ProviderName
EXEC SP_TRACE_SETEVENT @TraceID, 20, 51, @on; -- EventSequence
EXEC SP_TRACE_SETEVENT @TraceID, 20, 59, @on; -- ParentName
EXEC SP_TRACE_SETEVENT @TraceID, 20, 60, @on; -- IsSystem
EXEC SP_TRACE_SETEVENT @TraceID, 20, 64, @on; -- SessionLoginName
-- SP:Starting
EXEC SP_TRACE_SETEVENT @TraceID, 42, 1,  @on; -- TextData
EXEC SP_TRACE_SETEVENT @TraceID, 42, 6,  @on; -- NTUserName
EXEC SP_TRACE_SETEVENT @TraceID, 42, 7,  @on; -- NTDomainName
EXEC SP_TRACE_SETEVENT @TraceID, 42, 8,  @on; -- HostName
EXEC SP_TRACE_SETEVENT @TraceID, 42, 9,  @on; -- ClientProcessID
EXEC SP_TRACE_SETEVENT @TraceID, 42, 10, @on; -- ApplicationName
EXEC SP_TRACE_SETEVENT @TraceID, 42, 11, @on; -- LoginName
EXEC SP_TRACE_SETEVENT @TraceID, 42, 12, @on; -- SPID
EXEC SP_TRACE_SETEVENT @TraceID, 42, 13, @on; -- Duration
EXEC SP_TRACE_SETEVENT @TraceID, 42, 14, @on; -- StartTime
EXEC SP_TRACE_SETEVENT @TraceID, 42, 15, @on; -- EndTime
EXEC SP_TRACE_SETEVENT @TraceID, 42, 19, @on; -- Permissions
EXEC SP_TRACE_SETEVENT @TraceID, 42, 21, @on; -- EventSubClass
EXEC SP_TRACE_SETEVENT @TraceID, 42, 23, @on; -- Success (successful use of permissions)
EXEC SP_TRACE_SETEVENT @TraceID, 42, 26, @on; -- ServerName
EXEC SP_TRACE_SETEVENT @TraceID, 42, 28, @on; -- ObjectType
EXEC SP_TRACE_SETEVENT @TraceID, 42, 30, @on; -- State
EXEC SP_TRACE_SETEVENT @TraceID, 42, 31, @on; -- Error
EXEC SP_TRACE_SETEVENT @TraceID, 42, 34, @on; -- ObjectName
EXEC SP_TRACE_SETEVENT @TraceID, 42, 35, @on; -- DatabaseName
EXEC SP_TRACE_SETEVENT @TraceID, 42, 37, @on; -- OwnerName
EXEC SP_TRACE_SETEVENT @TraceID, 42, 38, @on; -- RoleName
EXEC SP_TRACE_SETEVENT @TraceID, 42, 39, @on; -- TargetUserName
EXEC SP_TRACE_SETEVENT @TraceID, 42, 40, @on; -- DBUserName
EXEC SP_TRACE_SETEVENT @TraceID, 42, 41, @on; -- LoginSid
EXEC SP_TRACE_SETEVENT @TraceID, 42, 42, @on; -- TargetLoginName
EXEC SP_TRACE_SETEVENT @TraceID, 42, 43, @on; -- TargetLoginSid
EXEC SP_TRACE_SETEVENT @TraceID, 42, 44, @on; -- ColumnPermissions
EXEC SP_TRACE_SETEVENT @TraceID, 42, 45, @on; -- LinkedServerName
EXEC SP_TRACE_SETEVENT @TraceID, 42, 46, @on; -- ProviderName
EXEC SP_TRACE_SETEVENT @TraceID, 42, 51, @on; -- EventSequence
EXEC SP_TRACE_SETEVENT @TraceID, 42, 59, @on; -- ParentName
EXEC SP_TRACE_SETEVENT @TraceID, 42, 60, @on; -- IsSystem
EXEC SP_TRACE_SETEVENT @TraceID, 42, 64, @on; -- SessionLoginName
-- SP:Completed
EXEC SP_TRACE_SETEVENT @TraceID, 43, 1,  @on; -- TextData
EXEC SP_TRACE_SETEVENT @TraceID, 43, 6,  @on; -- NTUserName
EXEC SP_TRACE_SETEVENT @TraceID, 43, 7,  @on; -- NTDomainName
EXEC SP_TRACE_SETEVENT @TraceID, 43, 8,  @on; -- HostName
EXEC SP_TRACE_SETEVENT @TraceID, 43, 9,  @on; -- ClientProcessID
EXEC SP_TRACE_SETEVENT @TraceID, 43, 10, @on; -- ApplicationName
EXEC SP_TRACE_SETEVENT @TraceID, 43, 11, @on; -- LoginName
EXEC SP_TRACE_SETEVENT @TraceID, 43, 12, @on; -- SPID
EXEC SP_TRACE_SETEVENT @TraceID, 43, 13, @on; -- Duration
EXEC SP_TRACE_SETEVENT @TraceID, 43, 14, @on; -- StartTime
EXEC SP_TRACE_SETEVENT @TraceID, 43, 15, @on; -- EndTime
EXEC SP_TRACE_SETEVENT @TraceID, 43, 19, @on; -- Permissions
EXEC SP_TRACE_SETEVENT @TraceID, 43, 21, @on; -- EventSubClass
EXEC SP_TRACE_SETEVENT @TraceID, 43, 23, @on; -- Success (successful use of permissions)
EXEC SP_TRACE_SETEVENT @TraceID, 43, 26, @on; -- ServerName
EXEC SP_TRACE_SETEVENT @TraceID, 43, 28, @on; -- ObjectType
EXEC SP_TRACE_SETEVENT @TraceID, 43, 30, @on; -- State
EXEC SP_TRACE_SETEVENT @TraceID, 43, 31, @on; -- Error
EXEC SP_TRACE_SETEVENT @TraceID, 43, 34, @on; -- ObjectName
EXEC SP_TRACE_SETEVENT @TraceID, 43, 35, @on; -- DatabaseName
EXEC SP_TRACE_SETEVENT @TraceID, 43, 37, @on; -- OwnerName
EXEC SP_TRACE_SETEVENT @TraceID, 43, 38, @on; -- RoleName
EXEC SP_TRACE_SETEVENT @TraceID, 43, 39, @on; -- TargetUserName
EXEC SP_TRACE_SETEVENT @TraceID, 43, 40, @on; -- DBUserName
EXEC SP_TRACE_SETEVENT @TraceID, 43, 41, @on; -- LoginSid
EXEC SP_TRACE_SETEVENT @TraceID, 43, 42, @on; -- TargetLoginName
EXEC SP_TRACE_SETEVENT @TraceID, 43, 43, @on; -- TargetLoginSid
EXEC SP_TRACE_SETEVENT @TraceID, 43, 44, @on; -- ColumnPermissions
EXEC SP_TRACE_SETEVENT @TraceID, 43, 45, @on; -- LinkedServerName
EXEC SP_TRACE_SETEVENT @TraceID, 43, 46, @on; -- ProviderName
EXEC SP_TRACE_SETEVENT @TraceID, 43, 51, @on; -- EventSequence
EXEC SP_TRACE_SETEVENT @TraceID, 43, 59, @on; -- ParentName
EXEC SP_TRACE_SETEVENT @TraceID, 43, 60, @on; -- IsSystem
EXEC SP_TRACE_SETEVENT @TraceID, 43, 64, @on; -- SessionLoginName
-- Object:Created
EXEC SP_TRACE_SETEVENT @TraceID, 46, 1,  @on; -- TextData
EXEC SP_TRACE_SETEVENT @TraceID, 46, 6,  @on; -- NTUserName
EXEC SP_TRACE_SETEVENT @TraceID, 46, 7,  @on; -- NTDomainName
EXEC SP_TRACE_SETEVENT @TraceID, 46, 8,  @on; -- HostName
EXEC SP_TRACE_SETEVENT @TraceID, 46, 9,  @on; -- ClientProcessID
EXEC SP_TRACE_SETEVENT @TraceID, 46, 10, @on; -- ApplicationName
EXEC SP_TRACE_SETEVENT @TraceID, 46, 11, @on; -- LoginName
EXEC SP_TRACE_SETEVENT @TraceID, 46, 12, @on; -- SPID
EXEC SP_TRACE_SETEVENT @TraceID, 46, 13, @on; -- Duration
EXEC SP_TRACE_SETEVENT @TraceID, 46, 14, @on; -- StartTime
EXEC SP_TRACE_SETEVENT @TraceID, 46, 15, @on; -- EndTime
EXEC SP_TRACE_SETEVENT @TraceID, 46, 19, @on; -- Permissions
EXEC SP_TRACE_SETEVENT @TraceID, 46, 21, @on; -- EventSubClass
EXEC SP_TRACE_SETEVENT @TraceID, 46, 23, @on; -- Success (successful use of permissions)
EXEC SP_TRACE_SETEVENT @TraceID, 46, 26, @on; -- ServerName
EXEC SP_TRACE_SETEVENT @TraceID, 46, 28, @on; -- ObjectType
EXEC SP_TRACE_SETEVENT @TraceID, 46, 30, @on; -- State
EXEC SP_TRACE_SETEVENT @TraceID, 46, 31, @on; -- Error
EXEC SP_TRACE_SETEVENT @TraceID, 46, 34, @on; -- ObjectName
EXEC SP_TRACE_SETEVENT @TraceID, 46, 35, @on; -- DatabaseName
EXEC SP_TRACE_SETEVENT @TraceID, 46, 37, @on; -- OwnerName
EXEC SP_TRACE_SETEVENT @TraceID, 46, 38, @on; -- RoleName
EXEC SP_TRACE_SETEVENT @TraceID, 46, 39, @on; -- TargetUserName
EXEC SP_TRACE_SETEVENT @TraceID, 46, 40, @on; -- DBUserName
EXEC SP_TRACE_SETEVENT @TraceID, 46, 41, @on; -- LoginSid
EXEC SP_TRACE_SETEVENT @TraceID, 46, 42, @on; -- TargetLoginName
EXEC SP_TRACE_SETEVENT @TraceID, 46, 43, @on; -- TargetLoginSid
EXEC SP_TRACE_SETEVENT @TraceID, 46, 44, @on; -- ColumnPermissions
EXEC SP_TRACE_SETEVENT @TraceID, 46, 45, @on; -- LinkedServerName
EXEC SP_TRACE_SETEVENT @TraceID, 46, 46, @on; -- ProviderName
EXEC SP_TRACE_SETEVENT @TraceID, 46, 51, @on; -- EventSequence
EXEC SP_TRACE_SETEVENT @TraceID, 46, 59, @on; -- ParentName
EXEC SP_TRACE_SETEVENT @TraceID, 46, 60, @on; -- IsSystem
EXEC SP_TRACE_SETEVENT @TraceID, 46, 64, @on; -- SessionLoginName
-- Object:Deleted
EXEC SP_TRACE_SETEVENT @TraceID, 47, 1,  @on; -- TextData
EXEC SP_TRACE_SETEVENT @TraceID, 47, 6,  @on; -- NTUserName
EXEC SP_TRACE_SETEVENT @TraceID, 47, 7,  @on; -- NTDomainName
EXEC SP_TRACE_SETEVENT @TraceID, 47, 8,  @on; -- HostName
EXEC SP_TRACE_SETEVENT @TraceID, 47, 9,  @on; -- ClientProcessID
EXEC SP_TRACE_SETEVENT @TraceID, 47, 10, @on; -- ApplicationName
EXEC SP_TRACE_SETEVENT @TraceID, 47, 11, @on; -- LoginName
EXEC SP_TRACE_SETEVENT @TraceID, 47, 12, @on; -- SPID
EXEC SP_TRACE_SETEVENT @TraceID, 47, 13, @on; -- Duration
EXEC SP_TRACE_SETEVENT @TraceID, 47, 14, @on; -- StartTime
EXEC SP_TRACE_SETEVENT @TraceID, 47, 15, @on; -- EndTime
EXEC SP_TRACE_SETEVENT @TraceID, 47, 19, @on; -- Permissions
EXEC SP_TRACE_SETEVENT @TraceID, 47, 21, @on; -- EventSubClass
EXEC SP_TRACE_SETEVENT @TraceID, 47, 23, @on; -- Success (successful use of permissions)
EXEC SP_TRACE_SETEVENT @TraceID, 47, 26, @on; -- ServerName
EXEC SP_TRACE_SETEVENT @TraceID, 47, 28, @on; -- ObjectType
EXEC SP_TRACE_SETEVENT @TraceID, 47, 30, @on; -- State
EXEC SP_TRACE_SETEVENT @TraceID, 47, 31, @on; -- Error
EXEC SP_TRACE_SETEVENT @TraceID, 47, 34, @on; -- ObjectName
EXEC SP_TRACE_SETEVENT @TraceID, 47, 35, @on; -- DatabaseName
EXEC SP_TRACE_SETEVENT @TraceID, 47, 37, @on; -- OwnerName
EXEC SP_TRACE_SETEVENT @TraceID, 47, 38, @on; -- RoleName
EXEC SP_TRACE_SETEVENT @TraceID, 47, 39, @on; -- TargetUserName
EXEC SP_TRACE_SETEVENT @TraceID, 47, 40, @on; -- DBUserName
EXEC SP_TRACE_SETEVENT @TraceID, 47, 41, @on; -- LoginSid
EXEC SP_TRACE_SETEVENT @TraceID, 47, 42, @on; -- TargetLoginName
EXEC SP_TRACE_SETEVENT @TraceID, 47, 43, @on; -- TargetLoginSid
EXEC SP_TRACE_SETEVENT @TraceID, 47, 44, @on; -- ColumnPermissions
EXEC SP_TRACE_SETEVENT @TraceID, 47, 45, @on; -- LinkedServerName
EXEC SP_TRACE_SETEVENT @TraceID, 47, 46, @on; -- ProviderName
EXEC SP_TRACE_SETEVENT @TraceID, 47, 51, @on; -- EventSequence
EXEC SP_TRACE_SETEVENT @TraceID, 47, 59, @on; -- ParentName
EXEC SP_TRACE_SETEVENT @TraceID, 47, 60, @on; -- IsSystem
EXEC SP_TRACE_SETEVENT @TraceID, 47, 64, @on; -- SessionLoginName
-- User-defined Event
EXEC SP_TRACE_SETEVENT @TraceID, 90, 1,  @on; -- TextData
EXEC SP_TRACE_SETEVENT @TraceID, 90, 6,  @on; -- NTUserName
EXEC SP_TRACE_SETEVENT @TraceID, 90, 7,  @on; -- NTDomainName
EXEC SP_TRACE_SETEVENT @TraceID, 90, 8,  @on; -- HostName
EXEC SP_TRACE_SETEVENT @TraceID, 90, 9,  @on; -- ClientProcessID
EXEC SP_TRACE_SETEVENT @TraceID, 90, 10, @on; -- ApplicationName
EXEC SP_TRACE_SETEVENT @TraceID, 90, 11, @on; -- LoginName
EXEC SP_TRACE_SETEVENT @TraceID, 90, 12, @on; -- SPID
EXEC SP_TRACE_SETEVENT @TraceID, 90, 13, @on; -- Duration
EXEC SP_TRACE_SETEVENT @TraceID, 90, 14, @on; -- StartTime
EXEC SP_TRACE_SETEVENT @TraceID, 90, 15, @on; -- EndTime
EXEC SP_TRACE_SETEVENT @TraceID, 90, 19, @on; -- Permissions
EXEC SP_TRACE_SETEVENT @TraceID, 90, 21, @on; -- EventSubClass
EXEC SP_TRACE_SETEVENT @TraceID, 90, 23, @on; -- Success (successful use of permissions)
EXEC SP_TRACE_SETEVENT @TraceID, 90, 26, @on; -- ServerName
EXEC SP_TRACE_SETEVENT @TraceID, 90, 28, @on; -- ObjectType
EXEC SP_TRACE_SETEVENT @TraceID, 90, 30, @on; -- State
EXEC SP_TRACE_SETEVENT @TraceID, 90, 31, @on; -- Error
EXEC SP_TRACE_SETEVENT @TraceID, 90, 34, @on; -- ObjectName
EXEC SP_TRACE_SETEVENT @TraceID, 90, 35, @on; -- DatabaseName
EXEC SP_TRACE_SETEVENT @TraceID, 90, 37, @on; -- OwnerName
EXEC SP_TRACE_SETEVENT @TraceID, 90, 38, @on; -- RoleName
EXEC SP_TRACE_SETEVENT @TraceID, 90, 39, @on; -- TargetUserName
EXEC SP_TRACE_SETEVENT @TraceID, 90, 40, @on; -- DBUserName
EXEC SP_TRACE_SETEVENT @TraceID, 90, 41, @on; -- LoginSid
EXEC SP_TRACE_SETEVENT @TraceID, 90, 42, @on; -- TargetLoginName
EXEC SP_TRACE_SETEVENT @TraceID, 90, 43, @on; -- TargetLoginSid
EXEC SP_TRACE_SETEVENT @TraceID, 90, 44, @on; -- ColumnPermissions
EXEC SP_TRACE_SETEVENT @TraceID, 90, 45, @on; -- LinkedServerName
EXEC SP_TRACE_SETEVENT @TraceID, 90, 46, @on; -- ProviderName
EXEC SP_TRACE_SETEVENT @TraceID, 90, 51, @on; -- EventSequence
EXEC SP_TRACE_SETEVENT @TraceID, 90, 59, @on; -- ParentName
EXEC SP_TRACE_SETEVENT @TraceID, 90, 60, @on; -- IsSystem
EXEC SP_TRACE_SETEVENT @TraceID, 90, 64, @on; -- SessionLoginName
-- Audit Database Scope GDR Event
-- Occurs every time a GRANT, DENY, REVOKE for a statement
-- permission is issued by any user in SQL Server.
EXEC SP_TRACE_SETEVENT @TraceID, 102, 1,  @on; -- TextData
EXEC SP_TRACE_SETEVENT @TraceID, 102, 6,  @on; -- NTUserName
EXEC SP_TRACE_SETEVENT @TraceID, 102, 7,  @on; -- NTDomainName
EXEC SP_TRACE_SETEVENT @TraceID, 102, 8,  @on; -- HostName
EXEC SP_TRACE_SETEVENT @TraceID, 102, 9,  @on; -- ClientProcessID
EXEC SP_TRACE_SETEVENT @TraceID, 102, 10, @on; -- ApplicationName
EXEC SP_TRACE_SETEVENT @TraceID, 102, 11, @on; -- LoginName
EXEC SP_TRACE_SETEVENT @TraceID, 102, 12, @on; -- SPID
EXEC SP_TRACE_SETEVENT @TraceID, 102, 13, @on; -- Duration
EXEC SP_TRACE_SETEVENT @TraceID, 102, 14, @on; -- StartTime
EXEC SP_TRACE_SETEVENT @TraceID, 102, 15, @on; -- EndTime
EXEC SP_TRACE_SETEVENT @TraceID, 102, 19, @on; -- Permissions
EXEC SP_TRACE_SETEVENT @TraceID, 102, 21, @on; -- EventSubClass
EXEC SP_TRACE_SETEVENT @TraceID, 102, 23, @on; -- Success (successful use of permissions)
EXEC SP_TRACE_SETEVENT @TraceID, 102, 26, @on; -- ServerName
EXEC SP_TRACE_SETEVENT @TraceID, 102, 28, @on; -- ObjectType
EXEC SP_TRACE_SETEVENT @TraceID, 102, 30, @on; -- State
EXEC SP_TRACE_SETEVENT @TraceID, 102, 31, @on; -- Error
EXEC SP_TRACE_SETEVENT @TraceID, 102, 34, @on; -- ObjectName
EXEC SP_TRACE_SETEVENT @TraceID, 102, 35, @on; -- DatabaseName
EXEC SP_TRACE_SETEVENT @TraceID, 102, 37, @on; -- OwnerName
EXEC SP_TRACE_SETEVENT @TraceID, 102, 38, @on; -- RoleName
EXEC SP_TRACE_SETEVENT @TraceID, 102, 39, @on; -- TargetUserName
EXEC SP_TRACE_SETEVENT @TraceID, 102, 40, @on; -- DBUserName
EXEC SP_TRACE_SETEVENT @TraceID, 102, 41, @on; -- LoginSid
EXEC SP_TRACE_SETEVENT @TraceID, 102, 42, @on; -- TargetLoginName
EXEC SP_TRACE_SETEVENT @TraceID, 102, 43, @on; -- TargetLoginSid
EXEC SP_TRACE_SETEVENT @TraceID, 102, 44, @on; -- ColumnPermissions
EXEC SP_TRACE_SETEVENT @TraceID, 102, 45, @on; -- LinkedServerName
EXEC SP_TRACE_SETEVENT @TraceID, 102, 46, @on; -- ProviderName
EXEC SP_TRACE_SETEVENT @TraceID, 102, 51, @on; -- EventSequence
EXEC SP_TRACE_SETEVENT @TraceID, 102, 59, @on; -- ParentName
EXEC SP_TRACE_SETEVENT @TraceID, 102, 60, @on; -- IsSystem
EXEC SP_TRACE_SETEVENT @TraceID, 102, 64, @on; -- SessionLoginName
-- Audit Object GDR Event
-- Occurs every time a GRANT, DENY, REVOKE for an object
-- permission is issued by any user in SQL Server.
EXEC SP_TRACE_SETEVENT @TraceID, 103, 1,  @on; -- TextData
EXEC SP_TRACE_SETEVENT @TraceID, 103, 6,  @on; -- NTUserName
EXEC SP_TRACE_SETEVENT @TraceID, 103, 7,  @on; -- NTDomainName
EXEC SP_TRACE_SETEVENT @TraceID, 103, 8,  @on; -- HostName
EXEC SP_TRACE_SETEVENT @TraceID, 103, 9,  @on; -- ClientProcessID
EXEC SP_TRACE_SETEVENT @TraceID, 103, 10, @on; -- ApplicationName
EXEC SP_TRACE_SETEVENT @TraceID, 103, 11, @on; -- LoginName
EXEC SP_TRACE_SETEVENT @TraceID, 103, 12, @on; -- SPID
EXEC SP_TRACE_SETEVENT @TraceID, 103, 13, @on; -- Duration
EXEC SP_TRACE_SETEVENT @TraceID, 103, 14, @on; -- StartTime
EXEC SP_TRACE_SETEVENT @TraceID, 103, 15, @on; -- EndTime
EXEC SP_TRACE_SETEVENT @TraceID, 103, 19, @on; -- Permissions
EXEC SP_TRACE_SETEVENT @TraceID, 103, 21, @on; -- EventSubClass
EXEC SP_TRACE_SETEVENT @TraceID, 103, 23, @on; -- Success (successful use of permissions)
EXEC SP_TRACE_SETEVENT @TraceID, 103, 26, @on; -- ServerName
EXEC SP_TRACE_SETEVENT @TraceID, 103, 28, @on; -- ObjectType
EXEC SP_TRACE_SETEVENT @TraceID, 103, 30, @on; -- State
EXEC SP_TRACE_SETEVENT @TraceID, 103, 31, @on; -- Error
EXEC SP_TRACE_SETEVENT @TraceID, 103, 34, @on; -- ObjectName
EXEC SP_TRACE_SETEVENT @TraceID, 103, 35, @on; -- DatabaseName
EXEC SP_TRACE_SETEVENT @TraceID, 103, 37, @on; -- OwnerName
EXEC SP_TRACE_SETEVENT @TraceID, 103, 38, @on; -- RoleName
EXEC SP_TRACE_SETEVENT @TraceID, 103, 39, @on; -- TargetUserName
EXEC SP_TRACE_SETEVENT @TraceID, 103, 40, @on; -- DBUserName
EXEC SP_TRACE_SETEVENT @TraceID, 103, 41, @on; -- LoginSid
EXEC SP_TRACE_SETEVENT @TraceID, 103, 42, @on; -- TargetLoginName
EXEC SP_TRACE_SETEVENT @TraceID, 103, 43, @on; -- TargetLoginSid
EXEC SP_TRACE_SETEVENT @TraceID, 103, 44, @on; -- ColumnPermissions
EXEC SP_TRACE_SETEVENT @TraceID, 103, 45, @on; -- LinkedServerName
EXEC SP_TRACE_SETEVENT @TraceID, 103, 46, @on; -- ProviderName
EXEC SP_TRACE_SETEVENT @TraceID, 103, 51, @on; -- EventSequence
EXEC SP_TRACE_SETEVENT @TraceID, 103, 59, @on; -- ParentName
EXEC SP_TRACE_SETEVENT @TraceID, 103, 60, @on; -- IsSystem
EXEC SP_TRACE_SETEVENT @TraceID, 103, 64, @on; -- SessionLoginName
-- Audit AddLogin Event
-- Occurs when a SQL Server login is added or removed;
-- for sp_addlogin and sp_droplogin.
EXEC SP_TRACE_SETEVENT @TraceID, 104, 1,  @on; -- TextData
EXEC SP_TRACE_SETEVENT @TraceID, 104, 6,  @on; -- NTUserName
EXEC SP_TRACE_SETEVENT @TraceID, 104, 7,  @on; -- NTDomainName
EXEC SP_TRACE_SETEVENT @TraceID, 104, 8,  @on; -- HostName
EXEC SP_TRACE_SETEVENT @TraceID, 104, 9,  @on; -- ClientProcessID
EXEC SP_TRACE_SETEVENT @TraceID, 104, 10, @on; -- ApplicationName
EXEC SP_TRACE_SETEVENT @TraceID, 104, 11, @on; -- LoginName
EXEC SP_TRACE_SETEVENT @TraceID, 104, 12, @on; -- SPID
EXEC SP_TRACE_SETEVENT @TraceID, 104, 13, @on; -- Duration
EXEC SP_TRACE_SETEVENT @TraceID, 104, 14, @on; -- StartTime
EXEC SP_TRACE_SETEVENT @TraceID, 104, 15, @on; -- EndTime
EXEC SP_TRACE_SETEVENT @TraceID, 104, 19, @on; -- Permissions
EXEC SP_TRACE_SETEVENT @TraceID, 104, 21, @on; -- EventSubClass
EXEC SP_TRACE_SETEVENT @TraceID, 104, 23, @on; -- Success (successful use of permissions)
EXEC SP_TRACE_SETEVENT @TraceID, 104, 26, @on; -- ServerName
EXEC SP_TRACE_SETEVENT @TraceID, 104, 28, @on; -- ObjectType
EXEC SP_TRACE_SETEVENT @TraceID, 104, 30, @on; -- State
EXEC SP_TRACE_SETEVENT @TraceID, 104, 31, @on; -- Error
EXEC SP_TRACE_SETEVENT @TraceID, 104, 34, @on; -- ObjectName
EXEC SP_TRACE_SETEVENT @TraceID, 104, 35, @on; -- DatabaseName
EXEC SP_TRACE_SETEVENT @TraceID, 104, 37, @on; -- OwnerName
EXEC SP_TRACE_SETEVENT @TraceID, 104, 38, @on; -- RoleName
EXEC SP_TRACE_SETEVENT @TraceID, 104, 39, @on; -- TargetUserName
EXEC SP_TRACE_SETEVENT @TraceID, 104, 40, @on; -- DBUserName
EXEC SP_TRACE_SETEVENT @TraceID, 104, 41, @on; -- LoginSid
EXEC SP_TRACE_SETEVENT @TraceID, 104, 42, @on; -- TargetLoginName
EXEC SP_TRACE_SETEVENT @TraceID, 104, 43, @on; -- TargetLoginSid
EXEC SP_TRACE_SETEVENT @TraceID, 104, 44, @on; -- ColumnPermissions
EXEC SP_TRACE_SETEVENT @TraceID, 104, 45, @on; -- LinkedServerName
EXEC SP_TRACE_SETEVENT @TraceID, 104, 46, @on; -- ProviderName
EXEC SP_TRACE_SETEVENT @TraceID, 104, 51, @on; -- EventSequence
EXEC SP_TRACE_SETEVENT @TraceID, 104, 59, @on; -- ParentName
EXEC SP_TRACE_SETEVENT @TraceID, 104, 60, @on; -- IsSystem
EXEC SP_TRACE_SETEVENT @TraceID, 104, 64, @on; -- SessionLoginName
-- Audit Login GDR Event
-- Occurs when a Windows login right is added or removed;
-- for sp_grantlogin, sp_revokelogin, and sp_denylogin.
EXEC SP_TRACE_SETEVENT @TraceID, 105, 1,  @on; -- TextData
EXEC SP_TRACE_SETEVENT @TraceID, 105, 6,  @on; -- NTUserName
EXEC SP_TRACE_SETEVENT @TraceID, 105, 7,  @on; -- NTDomainName
EXEC SP_TRACE_SETEVENT @TraceID, 105, 8,  @on; -- HostName
EXEC SP_TRACE_SETEVENT @TraceID, 105, 9,  @on; -- ClientProcessID
EXEC SP_TRACE_SETEVENT @TraceID, 105, 10, @on; -- ApplicationName
EXEC SP_TRACE_SETEVENT @TraceID, 105, 11, @on; -- LoginName
EXEC SP_TRACE_SETEVENT @TraceID, 105, 12, @on; -- SPID
EXEC SP_TRACE_SETEVENT @TraceID, 105, 13, @on; -- Duration
EXEC SP_TRACE_SETEVENT @TraceID, 105, 14, @on; -- StartTime
EXEC SP_TRACE_SETEVENT @TraceID, 105, 15, @on; -- EndTime
EXEC SP_TRACE_SETEVENT @TraceID, 105, 19, @on; -- Permissions
EXEC SP_TRACE_SETEVENT @TraceID, 105, 21, @on; -- EventSubClass
EXEC SP_TRACE_SETEVENT @TraceID, 105, 23, @on; -- Success (successful use of permissions)
EXEC SP_TRACE_SETEVENT @TraceID, 105, 26, @on; -- ServerName
EXEC SP_TRACE_SETEVENT @TraceID, 105, 28, @on; -- ObjectType
EXEC SP_TRACE_SETEVENT @TraceID, 105, 30, @on; -- State
EXEC SP_TRACE_SETEVENT @TraceID, 105, 31, @on; -- Error
EXEC SP_TRACE_SETEVENT @TraceID, 105, 34, @on; -- ObjectName
EXEC SP_TRACE_SETEVENT @TraceID, 105, 35, @on; -- DatabaseName
EXEC SP_TRACE_SETEVENT @TraceID, 105, 37, @on; -- OwnerName
EXEC SP_TRACE_SETEVENT @TraceID, 105, 38, @on; -- RoleName
EXEC SP_TRACE_SETEVENT @TraceID, 105, 39, @on; -- TargetUserName
EXEC SP_TRACE_SETEVENT @TraceID, 105, 40, @on; -- DBUserName
EXEC SP_TRACE_SETEVENT @TraceID, 105, 41, @on; -- LoginSid
EXEC SP_TRACE_SETEVENT @TraceID, 105, 42, @on; -- TargetLoginName
EXEC SP_TRACE_SETEVENT @TraceID, 105, 43, @on; -- TargetLoginSid
EXEC SP_TRACE_SETEVENT @TraceID, 105, 44, @on; -- ColumnPermissions
EXEC SP_TRACE_SETEVENT @TraceID, 105, 45, @on; -- LinkedServerName
EXEC SP_TRACE_SETEVENT @TraceID, 105, 46, @on; -- ProviderName
EXEC SP_TRACE_SETEVENT @TraceID, 105, 51, @on; -- EventSequence
EXEC SP_TRACE_SETEVENT @TraceID, 105, 59, @on; -- ParentName
EXEC SP_TRACE_SETEVENT @TraceID, 105, 60, @on; -- IsSystem
EXEC SP_TRACE_SETEVENT @TraceID, 105, 64, @on; -- SessionLoginName
-- Audit Login Change Property Event
-- Occurs when a property of a login, except passwords,
-- is modified; for sp_defaultdb and sp_defaultlanguage.
EXEC SP_TRACE_SETEVENT @TraceID, 106, 1,  @on; -- TextData
EXEC SP_TRACE_SETEVENT @TraceID, 106, 6,  @on; -- NTUserName
EXEC SP_TRACE_SETEVENT @TraceID, 106, 7,  @on; -- NTDomainName
EXEC SP_TRACE_SETEVENT @TraceID, 106, 8,  @on; -- HostName
EXEC SP_TRACE_SETEVENT @TraceID, 106, 9,  @on; -- ClientProcessID
EXEC SP_TRACE_SETEVENT @TraceID, 106, 10, @on; -- ApplicationName
EXEC SP_TRACE_SETEVENT @TraceID, 106, 11, @on; -- LoginName
EXEC SP_TRACE_SETEVENT @TraceID, 106, 12, @on; -- SPID
EXEC SP_TRACE_SETEVENT @TraceID, 106, 13, @on; -- Duration
EXEC SP_TRACE_SETEVENT @TraceID, 106, 14, @on; -- StartTime
EXEC SP_TRACE_SETEVENT @TraceID, 106, 15, @on; -- EndTime
EXEC SP_TRACE_SETEVENT @TraceID, 106, 19, @on; -- Permissions
EXEC SP_TRACE_SETEVENT @TraceID, 106, 21, @on; -- EventSubClass
EXEC SP_TRACE_SETEVENT @TraceID, 106, 23, @on; -- Success (successful use of permissions)
EXEC SP_TRACE_SETEVENT @TraceID, 106, 26, @on; -- ServerName
EXEC SP_TRACE_SETEVENT @TraceID, 106, 28, @on; -- ObjectType
EXEC SP_TRACE_SETEVENT @TraceID, 106, 30, @on; -- State
EXEC SP_TRACE_SETEVENT @TraceID, 106, 31, @on; -- Error
EXEC SP_TRACE_SETEVENT @TraceID, 106, 34, @on; -- ObjectName
EXEC SP_TRACE_SETEVENT @TraceID, 106, 35, @on; -- DatabaseName
EXEC SP_TRACE_SETEVENT @TraceID, 106, 37, @on; -- OwnerName
EXEC SP_TRACE_SETEVENT @TraceID, 106, 38, @on; -- RoleName
EXEC SP_TRACE_SETEVENT @TraceID, 106, 39, @on; -- TargetUserName
EXEC SP_TRACE_SETEVENT @TraceID, 106, 40, @on; -- DBUserName
EXEC SP_TRACE_SETEVENT @TraceID, 106, 41, @on; -- LoginSid
EXEC SP_TRACE_SETEVENT @TraceID, 106, 42, @on; -- TargetLoginName
EXEC SP_TRACE_SETEVENT @TraceID, 106, 43, @on; -- TargetLoginSid
EXEC SP_TRACE_SETEVENT @TraceID, 106, 44, @on; -- ColumnPermissions
EXEC SP_TRACE_SETEVENT @TraceID, 106, 45, @on; -- LinkedServerName
EXEC SP_TRACE_SETEVENT @TraceID, 106, 46, @on; -- ProviderName
EXEC SP_TRACE_SETEVENT @TraceID, 106, 51, @on; -- EventSequence
EXEC SP_TRACE_SETEVENT @TraceID, 106, 59, @on; -- ParentName
EXEC SP_TRACE_SETEVENT @TraceID, 106, 60, @on; -- IsSystem
EXEC SP_TRACE_SETEVENT @TraceID, 106, 64, @on; -- SessionLoginName
-- Audit Login Change Password Event
-- Occurs when a SQL Server login password is changed.
-- Passwords are not recorded.
EXEC SP_TRACE_SETEVENT @TraceID, 107, 1,  @on; -- TextData
EXEC SP_TRACE_SETEVENT @TraceID, 107, 6,  @on; -- NTUserName
EXEC SP_TRACE_SETEVENT @TraceID, 107, 7,  @on; -- NTDomainName
EXEC SP_TRACE_SETEVENT @TraceID, 107, 8,  @on; -- HostName
EXEC SP_TRACE_SETEVENT @TraceID, 107, 9,  @on; -- ClientProcessID
EXEC SP_TRACE_SETEVENT @TraceID, 107, 10, @on; -- ApplicationName
EXEC SP_TRACE_SETEVENT @TraceID, 107, 11, @on; -- LoginName
EXEC SP_TRACE_SETEVENT @TraceID, 107, 12, @on; -- SPID
EXEC SP_TRACE_SETEVENT @TraceID, 107, 13, @on; -- Duration
EXEC SP_TRACE_SETEVENT @TraceID, 107, 14, @on; -- StartTime
EXEC SP_TRACE_SETEVENT @TraceID, 107, 15, @on; -- EndTime
EXEC SP_TRACE_SETEVENT @TraceID, 107, 19, @on; -- Permissions
EXEC SP_TRACE_SETEVENT @TraceID, 107, 21, @on; -- EventSubClass
EXEC SP_TRACE_SETEVENT @TraceID, 107, 23, @on; -- Success (successful use of permissions)
EXEC SP_TRACE_SETEVENT @TraceID, 107, 26, @on; -- ServerName
EXEC SP_TRACE_SETEVENT @TraceID, 107, 28, @on; -- ObjectType
EXEC SP_TRACE_SETEVENT @TraceID, 107, 30, @on; -- State
EXEC SP_TRACE_SETEVENT @TraceID, 107, 31, @on; -- Error
EXEC SP_TRACE_SETEVENT @TraceID, 107, 34, @on; -- ObjectName
EXEC SP_TRACE_SETEVENT @TraceID, 107, 35, @on; -- DatabaseName
EXEC SP_TRACE_SETEVENT @TraceID, 107, 37, @on; -- OwnerName
EXEC SP_TRACE_SETEVENT @TraceID, 107, 38, @on; -- RoleName
EXEC SP_TRACE_SETEVENT @TraceID, 107, 39, @on; -- TargetUserName
EXEC SP_TRACE_SETEVENT @TraceID, 107, 40, @on; -- DBUserName
EXEC SP_TRACE_SETEVENT @TraceID, 107, 41, @on; -- LoginSid
EXEC SP_TRACE_SETEVENT @TraceID, 107, 42, @on; -- TargetLoginName
EXEC SP_TRACE_SETEVENT @TraceID, 107, 43, @on; -- TargetLoginSid
EXEC SP_TRACE_SETEVENT @TraceID, 107, 44, @on; -- ColumnPermissions
EXEC SP_TRACE_SETEVENT @TraceID, 107, 45, @on; -- LinkedServerName
EXEC SP_TRACE_SETEVENT @TraceID, 107, 46, @on; -- ProviderName
EXEC SP_TRACE_SETEVENT @TraceID, 107, 51, @on; -- EventSequence
EXEC SP_TRACE_SETEVENT @TraceID, 107, 59, @on; -- ParentName
EXEC SP_TRACE_SETEVENT @TraceID, 107, 60, @on; -- IsSystem
EXEC SP_TRACE_SETEVENT @TraceID, 107, 64, @on; -- SessionLoginName
-- Audit Add Login to Server Role Event
-- Occurs when a login is added or removed from a fixed server role;
-- for sp_addsrvrolemember, and sp_dropsrvrolemember.
EXEC SP_TRACE_SETEVENT @TraceID, 108, 1,  @on; -- TextData
EXEC SP_TRACE_SETEVENT @TraceID, 108, 6,  @on; -- NTUserName
EXEC SP_TRACE_SETEVENT @TraceID, 108, 7,  @on; -- NTDomainName
EXEC SP_TRACE_SETEVENT @TraceID, 108, 8,  @on; -- HostName
EXEC SP_TRACE_SETEVENT @TraceID, 108, 9,  @on; -- ClientProcessID
EXEC SP_TRACE_SETEVENT @TraceID, 108, 10, @on; -- ApplicationName
EXEC SP_TRACE_SETEVENT @TraceID, 108, 11, @on; -- LoginName
EXEC SP_TRACE_SETEVENT @TraceID, 108, 12, @on; -- SPID
EXEC SP_TRACE_SETEVENT @TraceID, 108, 13, @on; -- Duration
EXEC SP_TRACE_SETEVENT @TraceID, 108, 14, @on; -- StartTime
EXEC SP_TRACE_SETEVENT @TraceID, 108, 15, @on; -- EndTime
EXEC SP_TRACE_SETEVENT @TraceID, 108, 19, @on; -- Permissions
EXEC SP_TRACE_SETEVENT @TraceID, 108, 21, @on; -- EventSubClass
EXEC SP_TRACE_SETEVENT @TraceID, 108, 23, @on; -- Success (successful use of permissions)
EXEC SP_TRACE_SETEVENT @TraceID, 108, 26, @on; -- ServerName
EXEC SP_TRACE_SETEVENT @TraceID, 108, 28, @on; -- ObjectType
EXEC SP_TRACE_SETEVENT @TraceID, 108, 30, @on; -- State
EXEC SP_TRACE_SETEVENT @TraceID, 108, 31, @on; -- Error
EXEC SP_TRACE_SETEVENT @TraceID, 108, 34, @on; -- ObjectName
EXEC SP_TRACE_SETEVENT @TraceID, 108, 35, @on; -- DatabaseName
EXEC SP_TRACE_SETEVENT @TraceID, 108, 37, @on; -- OwnerName
EXEC SP_TRACE_SETEVENT @TraceID, 108, 38, @on; -- RoleName
EXEC SP_TRACE_SETEVENT @TraceID, 108, 39, @on; -- TargetUserName
EXEC SP_TRACE_SETEVENT @TraceID, 108, 40, @on; -- DBUserName
EXEC SP_TRACE_SETEVENT @TraceID, 108, 41, @on; -- LoginSid
EXEC SP_TRACE_SETEVENT @TraceID, 108, 42, @on; -- TargetLoginName
EXEC SP_TRACE_SETEVENT @TraceID, 108, 43, @on; -- TargetLoginSid
EXEC SP_TRACE_SETEVENT @TraceID, 108, 44, @on; -- ColumnPermissions
EXEC SP_TRACE_SETEVENT @TraceID, 108, 45, @on; -- LinkedServerName
EXEC SP_TRACE_SETEVENT @TraceID, 108, 46, @on; -- ProviderName
EXEC SP_TRACE_SETEVENT @TraceID, 108, 51, @on; -- EventSequence
EXEC SP_TRACE_SETEVENT @TraceID, 108, 59, @on; -- ParentName
EXEC SP_TRACE_SETEVENT @TraceID, 108, 60, @on; -- IsSystem
EXEC SP_TRACE_SETEVENT @TraceID, 108, 64, @on; -- SessionLoginName
-- Audit Add DB User Event
-- Occurs when a login is added or removed as a database user
-- (Windows or SQL Server) to a database; for sp_grantdbaccess,
-- sp_revokedbaccess, sp_adduser, and sp_dropuser.
EXEC SP_TRACE_SETEVENT @TraceID, 109, 1,  @on; -- TextData
EXEC SP_TRACE_SETEVENT @TraceID, 109, 6,  @on; -- NTUserName
EXEC SP_TRACE_SETEVENT @TraceID, 109, 7,  @on; -- NTDomainName
EXEC SP_TRACE_SETEVENT @TraceID, 109, 8,  @on; -- HostName
EXEC SP_TRACE_SETEVENT @TraceID, 109, 9,  @on; -- ClientProcessID
EXEC SP_TRACE_SETEVENT @TraceID, 109, 10, @on; -- ApplicationName
EXEC SP_TRACE_SETEVENT @TraceID, 109, 11, @on; -- LoginName
EXEC SP_TRACE_SETEVENT @TraceID, 109, 12, @on; -- SPID
EXEC SP_TRACE_SETEVENT @TraceID, 109, 13, @on; -- Duration
EXEC SP_TRACE_SETEVENT @TraceID, 109, 14, @on; -- StartTime
EXEC SP_TRACE_SETEVENT @TraceID, 109, 15, @on; -- EndTime
EXEC SP_TRACE_SETEVENT @TraceID, 109, 19, @on; -- Permissions
EXEC SP_TRACE_SETEVENT @TraceID, 109, 21, @on; -- EventSubClass
EXEC SP_TRACE_SETEVENT @TraceID, 109, 23, @on; -- Success (successful use of permissions)
EXEC SP_TRACE_SETEVENT @TraceID, 109, 26, @on; -- ServerName
EXEC SP_TRACE_SETEVENT @TraceID, 109, 28, @on; -- ObjectType
EXEC SP_TRACE_SETEVENT @TraceID, 109, 30, @on; -- State
EXEC SP_TRACE_SETEVENT @TraceID, 109, 31, @on; -- Error
EXEC SP_TRACE_SETEVENT @TraceID, 109, 34, @on; -- ObjectName
EXEC SP_TRACE_SETEVENT @TraceID, 109, 35, @on; -- DatabaseName
EXEC SP_TRACE_SETEVENT @TraceID, 109, 37, @on; -- OwnerName
EXEC SP_TRACE_SETEVENT @TraceID, 109, 38, @on; -- RoleName
EXEC SP_TRACE_SETEVENT @TraceID, 109, 39, @on; -- TargetUserName
EXEC SP_TRACE_SETEVENT @TraceID, 109, 40, @on; -- DBUserName
EXEC SP_TRACE_SETEVENT @TraceID, 109, 41, @on; -- LoginSid
EXEC SP_TRACE_SETEVENT @TraceID, 109, 42, @on; -- TargetLoginName
EXEC SP_TRACE_SETEVENT @TraceID, 109, 43, @on; -- TargetLoginSid
EXEC SP_TRACE_SETEVENT @TraceID, 109, 44, @on; -- ColumnPermissions
EXEC SP_TRACE_SETEVENT @TraceID, 109, 45, @on; -- LinkedServerName
EXEC SP_TRACE_SETEVENT @TraceID, 109, 46, @on; -- ProviderName
EXEC SP_TRACE_SETEVENT @TraceID, 109, 51, @on; -- EventSequence
EXEC SP_TRACE_SETEVENT @TraceID, 109, 59, @on; -- ParentName
EXEC SP_TRACE_SETEVENT @TraceID, 109, 60, @on; -- IsSystem
EXEC SP_TRACE_SETEVENT @TraceID, 109, 64, @on; -- SessionLoginName
-- Audit Add Member to DB Role Event
-- Occurs when a login is added or removed as a database user
-- (fixed or user-defined) to a database; for sp_addrolemember,
-- sp_droprolemember, and sp_changegroup.
EXEC SP_TRACE_SETEVENT @TraceID, 110, 1,  @on; -- TextData
EXEC SP_TRACE_SETEVENT @TraceID, 110, 6,  @on; -- NTUserName
EXEC SP_TRACE_SETEVENT @TraceID, 110, 7,  @on; -- NTDomainName
EXEC SP_TRACE_SETEVENT @TraceID, 110, 8,  @on; -- HostName
EXEC SP_TRACE_SETEVENT @TraceID, 110, 9,  @on; -- ClientProcessID
EXEC SP_TRACE_SETEVENT @TraceID, 110, 10, @on; -- ApplicationName
EXEC SP_TRACE_SETEVENT @TraceID, 110, 11, @on; -- LoginName
EXEC SP_TRACE_SETEVENT @TraceID, 110, 12, @on; -- SPID
EXEC SP_TRACE_SETEVENT @TraceID, 110, 13, @on; -- Duration
EXEC SP_TRACE_SETEVENT @TraceID, 110, 14, @on; -- StartTime
EXEC SP_TRACE_SETEVENT @TraceID, 110, 15, @on; -- EndTime
EXEC SP_TRACE_SETEVENT @TraceID, 110, 19, @on; -- Permissions
EXEC SP_TRACE_SETEVENT @TraceID, 110, 21, @on; -- EventSubClass
EXEC SP_TRACE_SETEVENT @TraceID, 110, 23, @on; -- Success (successful use of permissions)
EXEC SP_TRACE_SETEVENT @TraceID, 110, 26, @on; -- ServerName
EXEC SP_TRACE_SETEVENT @TraceID, 110, 28, @on; -- ObjectType
EXEC SP_TRACE_SETEVENT @TraceID, 110, 30, @on; -- State
EXEC SP_TRACE_SETEVENT @TraceID, 110, 31, @on; -- Error
EXEC SP_TRACE_SETEVENT @TraceID, 110, 34, @on; -- ObjectName
EXEC SP_TRACE_SETEVENT @TraceID, 110, 35, @on; -- DatabaseName
EXEC SP_TRACE_SETEVENT @TraceID, 110, 37, @on; -- OwnerName
EXEC SP_TRACE_SETEVENT @TraceID, 110, 38, @on; -- RoleName
EXEC SP_TRACE_SETEVENT @TraceID, 110, 39, @on; -- TargetUserName
EXEC SP_TRACE_SETEVENT @TraceID, 110, 40, @on; -- DBUserName
EXEC SP_TRACE_SETEVENT @TraceID, 110, 41, @on; -- LoginSid
EXEC SP_TRACE_SETEVENT @TraceID, 110, 42, @on; -- TargetLoginName
EXEC SP_TRACE_SETEVENT @TraceID, 110, 43, @on; -- TargetLoginSid
EXEC SP_TRACE_SETEVENT @TraceID, 110, 44, @on; -- ColumnPermissions
EXEC SP_TRACE_SETEVENT @TraceID, 110, 45, @on; -- LinkedServerName
EXEC SP_TRACE_SETEVENT @TraceID, 110, 46, @on; -- ProviderName
EXEC SP_TRACE_SETEVENT @TraceID, 110, 51, @on; -- EventSequence
EXEC SP_TRACE_SETEVENT @TraceID, 110, 59, @on; -- ParentName
EXEC SP_TRACE_SETEVENT @TraceID, 110, 60, @on; -- IsSystem
EXEC SP_TRACE_SETEVENT @TraceID, 110, 64, @on; -- SessionLoginName
-- Audit Add Role Event
-- Occurs when a login is added or removed as a database user to a
-- database; for sp_addrole and sp_droprole.
EXEC SP_TRACE_SETEVENT @TraceID, 111, 1,  @on; -- TextData
EXEC SP_TRACE_SETEVENT @TraceID, 111, 6,  @on; -- NTUserName
EXEC SP_TRACE_SETEVENT @TraceID, 111, 7,  @on; -- NTDomainName
EXEC SP_TRACE_SETEVENT @TraceID, 111, 8,  @on; -- HostName
EXEC SP_TRACE_SETEVENT @TraceID, 111, 9,  @on; -- ClientProcessID
EXEC SP_TRACE_SETEVENT @TraceID, 111, 10, @on; -- ApplicationName
EXEC SP_TRACE_SETEVENT @TraceID, 111, 11, @on; -- LoginName
EXEC SP_TRACE_SETEVENT @TraceID, 111, 12, @on; -- SPID
EXEC SP_TRACE_SETEVENT @TraceID, 111, 13, @on; -- Duration
EXEC SP_TRACE_SETEVENT @TraceID, 111, 14, @on; -- StartTime
EXEC SP_TRACE_SETEVENT @TraceID, 111, 15, @on; -- EndTime
EXEC SP_TRACE_SETEVENT @TraceID, 111, 19, @on; -- Permissions
EXEC SP_TRACE_SETEVENT @TraceID, 111, 21, @on; -- EventSubClass
EXEC SP_TRACE_SETEVENT @TraceID, 111, 23, @on; -- Success (successful use of permissions)
EXEC SP_TRACE_SETEVENT @TraceID, 111, 26, @on; -- ServerName
EXEC SP_TRACE_SETEVENT @TraceID, 111, 28, @on; -- ObjectType
EXEC SP_TRACE_SETEVENT @TraceID, 111, 30, @on; -- State
EXEC SP_TRACE_SETEVENT @TraceID, 111, 31, @on; -- Error
EXEC SP_TRACE_SETEVENT @TraceID, 111, 34, @on; -- ObjectName
EXEC SP_TRACE_SETEVENT @TraceID, 111, 35, @on; -- DatabaseName
EXEC SP_TRACE_SETEVENT @TraceID, 111, 37, @on; -- OwnerName
EXEC SP_TRACE_SETEVENT @TraceID, 111, 38, @on; -- RoleName
EXEC SP_TRACE_SETEVENT @TraceID, 111, 39, @on; -- TargetUserName
EXEC SP_TRACE_SETEVENT @TraceID, 111, 40, @on; -- DBUserName
EXEC SP_TRACE_SETEVENT @TraceID, 111, 41, @on; -- LoginSid
EXEC SP_TRACE_SETEVENT @TraceID, 111, 42, @on; -- TargetLoginName
EXEC SP_TRACE_SETEVENT @TraceID, 111, 43, @on; -- TargetLoginSid
EXEC SP_TRACE_SETEVENT @TraceID, 111, 44, @on; -- ColumnPermissions
EXEC SP_TRACE_SETEVENT @TraceID, 111, 45, @on; -- LinkedServerName
EXEC SP_TRACE_SETEVENT @TraceID, 111, 46, @on; -- ProviderName
EXEC SP_TRACE_SETEVENT @TraceID, 111, 51, @on; -- EventSequence
EXEC SP_TRACE_SETEVENT @TraceID, 111, 59, @on; -- ParentName
EXEC SP_TRACE_SETEVENT @TraceID, 111, 60, @on; -- IsSystem
EXEC SP_TRACE_SETEVENT @TraceID, 111, 64, @on; -- SessionLoginName
-- Audit App Role Change Password Event
-- Occurs when a password of an application role is changed.
EXEC SP_TRACE_SETEVENT @TraceID, 112, 1,  @on; -- TextData
EXEC SP_TRACE_SETEVENT @TraceID, 112, 6,  @on; -- NTUserName
EXEC SP_TRACE_SETEVENT @TraceID, 112, 7,  @on; -- NTDomainName
EXEC SP_TRACE_SETEVENT @TraceID, 112, 8,  @on; -- HostName
EXEC SP_TRACE_SETEVENT @TraceID, 112, 9,  @on; -- ClientProcessID
EXEC SP_TRACE_SETEVENT @TraceID, 112, 10, @on; -- ApplicationName
EXEC SP_TRACE_SETEVENT @TraceID, 112, 11, @on; -- LoginName
EXEC SP_TRACE_SETEVENT @TraceID, 112, 12, @on; -- SPID
EXEC SP_TRACE_SETEVENT @TraceID, 112, 13, @on; -- Duration
EXEC SP_TRACE_SETEVENT @TraceID, 112, 14, @on; -- StartTime
EXEC SP_TRACE_SETEVENT @TraceID, 112, 15, @on; -- EndTime
EXEC SP_TRACE_SETEVENT @TraceID, 112, 19, @on; -- Permissions
EXEC SP_TRACE_SETEVENT @TraceID, 112, 21, @on; -- EventSubClass
EXEC SP_TRACE_SETEVENT @TraceID, 112, 23, @on; -- Success (successful use of permissions)
EXEC SP_TRACE_SETEVENT @TraceID, 112, 26, @on; -- ServerName
EXEC SP_TRACE_SETEVENT @TraceID, 112, 28, @on; -- ObjectType
EXEC SP_TRACE_SETEVENT @TraceID, 112, 30, @on; -- State
EXEC SP_TRACE_SETEVENT @TraceID, 112, 31, @on; -- Error
EXEC SP_TRACE_SETEVENT @TraceID, 112, 34, @on; -- ObjectName
EXEC SP_TRACE_SETEVENT @TraceID, 112, 35, @on; -- DatabaseName
EXEC SP_TRACE_SETEVENT @TraceID, 112, 37, @on; -- OwnerName
EXEC SP_TRACE_SETEVENT @TraceID, 112, 38, @on; -- RoleName
EXEC SP_TRACE_SETEVENT @TraceID, 112, 39, @on; -- TargetUserName
EXEC SP_TRACE_SETEVENT @TraceID, 112, 40, @on; -- DBUserName
EXEC SP_TRACE_SETEVENT @TraceID, 112, 41, @on; -- LoginSid
EXEC SP_TRACE_SETEVENT @TraceID, 112, 42, @on; -- TargetLoginName
EXEC SP_TRACE_SETEVENT @TraceID, 112, 43, @on; -- TargetLoginSid
EXEC SP_TRACE_SETEVENT @TraceID, 112, 44, @on; -- ColumnPermissions
EXEC SP_TRACE_SETEVENT @TraceID, 112, 45, @on; -- LinkedServerName
EXEC SP_TRACE_SETEVENT @TraceID, 112, 46, @on; -- ProviderName
EXEC SP_TRACE_SETEVENT @TraceID, 112, 51, @on; -- EventSequence
EXEC SP_TRACE_SETEVENT @TraceID, 112, 59, @on; -- ParentName
EXEC SP_TRACE_SETEVENT @TraceID, 112, 60, @on; -- IsSystem
EXEC SP_TRACE_SETEVENT @TraceID, 112, 64, @on; -- SessionLoginName
-- Audit Statement Permission Event
-- Occurs when a statement permission (such as CREATE TABLE) is used.
EXEC SP_TRACE_SETEVENT @TraceID, 113, 1,  @on; -- TextData
EXEC SP_TRACE_SETEVENT @TraceID, 113, 6,  @on; -- NTUserName
EXEC SP_TRACE_SETEVENT @TraceID, 113, 7,  @on; -- NTDomainName
EXEC SP_TRACE_SETEVENT @TraceID, 113, 8,  @on; -- HostName
EXEC SP_TRACE_SETEVENT @TraceID, 113, 9,  @on; -- ClientProcessID
EXEC SP_TRACE_SETEVENT @TraceID, 113, 10, @on; -- ApplicationName
EXEC SP_TRACE_SETEVENT @TraceID, 113, 11, @on; -- LoginName
EXEC SP_TRACE_SETEVENT @TraceID, 113, 12, @on; -- SPID
EXEC SP_TRACE_SETEVENT @TraceID, 113, 13, @on; -- Duration
EXEC SP_TRACE_SETEVENT @TraceID, 113, 14, @on; -- StartTime
EXEC SP_TRACE_SETEVENT @TraceID, 113, 15, @on; -- EndTime
EXEC SP_TRACE_SETEVENT @TraceID, 113, 19, @on; -- Permissions
EXEC SP_TRACE_SETEVENT @TraceID, 113, 21, @on; -- EventSubClass
EXEC SP_TRACE_SETEVENT @TraceID, 113, 23, @on; -- Success (successful use of permissions)
EXEC SP_TRACE_SETEVENT @TraceID, 113, 26, @on; -- ServerName
EXEC SP_TRACE_SETEVENT @TraceID, 113, 28, @on; -- ObjectType
EXEC SP_TRACE_SETEVENT @TraceID, 113, 30, @on; -- State
EXEC SP_TRACE_SETEVENT @TraceID, 113, 31, @on; -- Error
EXEC SP_TRACE_SETEVENT @TraceID, 113, 34, @on; -- ObjectName
EXEC SP_TRACE_SETEVENT @TraceID, 113, 35, @on; -- DatabaseName
EXEC SP_TRACE_SETEVENT @TraceID, 113, 37, @on; -- OwnerName
EXEC SP_TRACE_SETEVENT @TraceID, 113, 38, @on; -- RoleName
EXEC SP_TRACE_SETEVENT @TraceID, 113, 39, @on; -- TargetUserName
EXEC SP_TRACE_SETEVENT @TraceID, 113, 40, @on; -- DBUserName
EXEC SP_TRACE_SETEVENT @TraceID, 113, 41, @on; -- LoginSid
EXEC SP_TRACE_SETEVENT @TraceID, 113, 42, @on; -- TargetLoginName
EXEC SP_TRACE_SETEVENT @TraceID, 113, 43, @on; -- TargetLoginSid
EXEC SP_TRACE_SETEVENT @TraceID, 113, 44, @on; -- ColumnPermissions
EXEC SP_TRACE_SETEVENT @TraceID, 113, 45, @on; -- LinkedServerName
EXEC SP_TRACE_SETEVENT @TraceID, 113, 46, @on; -- ProviderName
EXEC SP_TRACE_SETEVENT @TraceID, 113, 51, @on; -- EventSequence
EXEC SP_TRACE_SETEVENT @TraceID, 113, 59, @on; -- ParentName
EXEC SP_TRACE_SETEVENT @TraceID, 113, 60, @on; -- IsSystem
EXEC SP_TRACE_SETEVENT @TraceID, 113, 64, @on; -- SessionLoginName
-- Audit Backup/Restore Event
-- Occurs when a BACKUP or RESTORE command is issued.
EXEC SP_TRACE_SETEVENT @TraceID, 115, 1,  @on; -- TextData
EXEC SP_TRACE_SETEVENT @TraceID, 115, 6,  @on; -- NTUserName
EXEC SP_TRACE_SETEVENT @TraceID, 115, 7,  @on; -- NTDomainName
EXEC SP_TRACE_SETEVENT @TraceID, 115, 8,  @on; -- HostName
EXEC SP_TRACE_SETEVENT @TraceID, 115, 9,  @on; -- ClientProcessID
EXEC SP_TRACE_SETEVENT @TraceID, 115, 10, @on; -- ApplicationName
EXEC SP_TRACE_SETEVENT @TraceID, 115, 11, @on; -- LoginName
EXEC SP_TRACE_SETEVENT @TraceID, 115, 12, @on; -- SPID
EXEC SP_TRACE_SETEVENT @TraceID, 115, 13, @on; -- Duration
EXEC SP_TRACE_SETEVENT @TraceID, 115, 14, @on; -- StartTime
EXEC SP_TRACE_SETEVENT @TraceID, 115, 15, @on; -- EndTime
EXEC SP_TRACE_SETEVENT @TraceID, 115, 19, @on; -- Permissions
EXEC SP_TRACE_SETEVENT @TraceID, 115, 21, @on; -- EventSubClass
EXEC SP_TRACE_SETEVENT @TraceID, 115, 23, @on; -- Success (successful use of permissions)
EXEC SP_TRACE_SETEVENT @TraceID, 115, 26, @on; -- ServerName
EXEC SP_TRACE_SETEVENT @TraceID, 115, 28, @on; -- ObjectType
EXEC SP_TRACE_SETEVENT @TraceID, 115, 30, @on; -- State
EXEC SP_TRACE_SETEVENT @TraceID, 115, 31, @on; -- Error
EXEC SP_TRACE_SETEVENT @TraceID, 115, 34, @on; -- ObjectName
EXEC SP_TRACE_SETEVENT @TraceID, 115, 35, @on; -- DatabaseName
EXEC SP_TRACE_SETEVENT @TraceID, 115, 37, @on; -- OwnerName
EXEC SP_TRACE_SETEVENT @TraceID, 115, 38, @on; -- RoleName
EXEC SP_TRACE_SETEVENT @TraceID, 115, 39, @on; -- TargetUserName
EXEC SP_TRACE_SETEVENT @TraceID, 115, 40, @on; -- DBUserName
EXEC SP_TRACE_SETEVENT @TraceID, 115, 41, @on; -- LoginSid
EXEC SP_TRACE_SETEVENT @TraceID, 115, 42, @on; -- TargetLoginName
EXEC SP_TRACE_SETEVENT @TraceID, 115, 43, @on; -- TargetLoginSid
EXEC SP_TRACE_SETEVENT @TraceID, 115, 44, @on; -- ColumnPermissions
EXEC SP_TRACE_SETEVENT @TraceID, 115, 45, @on; -- LinkedServerName
EXEC SP_TRACE_SETEVENT @TraceID, 115, 46, @on; -- ProviderName
EXEC SP_TRACE_SETEVENT @TraceID, 115, 51, @on; -- EventSequence
EXEC SP_TRACE_SETEVENT @TraceID, 115, 59, @on; -- ParentName
EXEC SP_TRACE_SETEVENT @TraceID, 115, 60, @on; -- IsSystem
EXEC SP_TRACE_SETEVENT @TraceID, 115, 64, @on; -- SessionLoginName
-- Audit DBCC Event
-- Occurs when DBCC commands are issued.
EXEC SP_TRACE_SETEVENT @TraceID, 116, 1,  @on; -- TextData
EXEC SP_TRACE_SETEVENT @TraceID, 116, 6,  @on; -- NTUserName
EXEC SP_TRACE_SETEVENT @TraceID, 116, 7,  @on; -- NTDomainName
EXEC SP_TRACE_SETEVENT @TraceID, 116, 8,  @on; -- HostName
EXEC SP_TRACE_SETEVENT @TraceID, 116, 9,  @on; -- ClientProcessID
EXEC SP_TRACE_SETEVENT @TraceID, 116, 10, @on; -- ApplicationName
EXEC SP_TRACE_SETEVENT @TraceID, 116, 11, @on; -- LoginName
EXEC SP_TRACE_SETEVENT @TraceID, 116, 12, @on; -- SPID
EXEC SP_TRACE_SETEVENT @TraceID, 116, 13, @on; -- Duration
EXEC SP_TRACE_SETEVENT @TraceID, 116, 14, @on; -- StartTime
EXEC SP_TRACE_SETEVENT @TraceID, 116, 15, @on; -- EndTime
EXEC SP_TRACE_SETEVENT @TraceID, 116, 19, @on; -- Permissions
EXEC SP_TRACE_SETEVENT @TraceID, 116, 21, @on; -- EventSubClass
EXEC SP_TRACE_SETEVENT @TraceID, 116, 23, @on; -- Success (successful use of permissions)
EXEC SP_TRACE_SETEVENT @TraceID, 116, 26, @on; -- ServerName
EXEC SP_TRACE_SETEVENT @TraceID, 116, 28, @on; -- ObjectType
EXEC SP_TRACE_SETEVENT @TraceID, 116, 30, @on; -- State
EXEC SP_TRACE_SETEVENT @TraceID, 116, 31, @on; -- Error
EXEC SP_TRACE_SETEVENT @TraceID, 116, 34, @on; -- ObjectName
EXEC SP_TRACE_SETEVENT @TraceID, 116, 35, @on; -- DatabaseName
EXEC SP_TRACE_SETEVENT @TraceID, 116, 37, @on; -- OwnerName
EXEC SP_TRACE_SETEVENT @TraceID, 116, 38, @on; -- RoleName
EXEC SP_TRACE_SETEVENT @TraceID, 116, 39, @on; -- TargetUserName
EXEC SP_TRACE_SETEVENT @TraceID, 116, 40, @on; -- DBUserName
EXEC SP_TRACE_SETEVENT @TraceID, 116, 41, @on; -- LoginSid
EXEC SP_TRACE_SETEVENT @TraceID, 116, 42, @on; -- TargetLoginName
EXEC SP_TRACE_SETEVENT @TraceID, 116, 43, @on; -- TargetLoginSid
EXEC SP_TRACE_SETEVENT @TraceID, 116, 44, @on; -- ColumnPermissions
EXEC SP_TRACE_SETEVENT @TraceID, 116, 45, @on; -- LinkedServerName
EXEC SP_TRACE_SETEVENT @TraceID, 116, 46, @on; -- ProviderName
EXEC SP_TRACE_SETEVENT @TraceID, 116, 51, @on; -- EventSequence
EXEC SP_TRACE_SETEVENT @TraceID, 116, 59, @on; -- ParentName
EXEC SP_TRACE_SETEVENT @TraceID, 116, 60, @on; -- IsSystem
EXEC SP_TRACE_SETEVENT @TraceID, 116, 64, @on; -- SessionLoginName
-- Audit Change Audit Event
-- Occurs when audit trace modifications are made.
EXEC SP_TRACE_SETEVENT @TraceID, 117, 1,  @on; -- TextData
EXEC SP_TRACE_SETEVENT @TraceID, 117, 6,  @on; -- NTUserName
EXEC SP_TRACE_SETEVENT @TraceID, 117, 7,  @on; -- NTDomainName
EXEC SP_TRACE_SETEVENT @TraceID, 117, 8,  @on; -- HostName
EXEC SP_TRACE_SETEVENT @TraceID, 117, 9,  @on; -- ClientProcessID
EXEC SP_TRACE_SETEVENT @TraceID, 117, 10, @on; -- ApplicationName
EXEC SP_TRACE_SETEVENT @TraceID, 117, 11, @on; -- LoginName
EXEC SP_TRACE_SETEVENT @TraceID, 117, 12, @on; -- SPID
EXEC SP_TRACE_SETEVENT @TraceID, 117, 13, @on; -- Duration
EXEC SP_TRACE_SETEVENT @TraceID, 117, 14, @on; -- StartTime
EXEC SP_TRACE_SETEVENT @TraceID, 117, 15, @on; -- EndTime
EXEC SP_TRACE_SETEVENT @TraceID, 117, 19, @on; -- Permissions
EXEC SP_TRACE_SETEVENT @TraceID, 117, 21, @on; -- EventSubClass
EXEC SP_TRACE_SETEVENT @TraceID, 117, 23, @on; -- Success (successful use of permissions)
EXEC SP_TRACE_SETEVENT @TraceID, 117, 26, @on; -- ServerName
EXEC SP_TRACE_SETEVENT @TraceID, 117, 28, @on; -- ObjectType
EXEC SP_TRACE_SETEVENT @TraceID, 117, 30, @on; -- State
EXEC SP_TRACE_SETEVENT @TraceID, 117, 31, @on; -- Error
EXEC SP_TRACE_SETEVENT @TraceID, 117, 34, @on; -- ObjectName
EXEC SP_TRACE_SETEVENT @TraceID, 117, 35, @on; -- DatabaseName
EXEC SP_TRACE_SETEVENT @TraceID, 117, 37, @on; -- OwnerName
EXEC SP_TRACE_SETEVENT @TraceID, 117, 38, @on; -- RoleName
EXEC SP_TRACE_SETEVENT @TraceID, 117, 39, @on; -- TargetUserName
EXEC SP_TRACE_SETEVENT @TraceID, 117, 40, @on; -- DBUserName
EXEC SP_TRACE_SETEVENT @TraceID, 117, 41, @on; -- LoginSid
EXEC SP_TRACE_SETEVENT @TraceID, 117, 42, @on; -- TargetLoginName
EXEC SP_TRACE_SETEVENT @TraceID, 117, 43, @on; -- TargetLoginSid
EXEC SP_TRACE_SETEVENT @TraceID, 117, 44, @on; -- ColumnPermissions
EXEC SP_TRACE_SETEVENT @TraceID, 117, 45, @on; -- LinkedServerName
EXEC SP_TRACE_SETEVENT @TraceID, 117, 46, @on; -- ProviderName
EXEC SP_TRACE_SETEVENT @TraceID, 117, 51, @on; -- EventSequence
EXEC SP_TRACE_SETEVENT @TraceID, 117, 59, @on; -- ParentName
EXEC SP_TRACE_SETEVENT @TraceID, 117, 60, @on; -- IsSystem
EXEC SP_TRACE_SETEVENT @TraceID, 117, 64, @on; -- SessionLoginName
-- Audit Object Derived Permission Event
-- Occurs when a CREATE, ALTER, and DROP object commands are issued.
EXEC SP_TRACE_SETEVENT @TraceID, 118, 1,  @on; -- TextData
EXEC SP_TRACE_SETEVENT @TraceID, 118, 6,  @on; -- NTUserName
EXEC SP_TRACE_SETEVENT @TraceID, 118, 7,  @on; -- NTDomainName
EXEC SP_TRACE_SETEVENT @TraceID, 118, 8,  @on; -- HostName
EXEC SP_TRACE_SETEVENT @TraceID, 118, 9,  @on; -- ClientProcessID
EXEC SP_TRACE_SETEVENT @TraceID, 118, 10, @on; -- ApplicationName
EXEC SP_TRACE_SETEVENT @TraceID, 118, 11, @on; -- LoginName
EXEC SP_TRACE_SETEVENT @TraceID, 118, 12, @on; -- SPID
EXEC SP_TRACE_SETEVENT @TraceID, 118, 13, @on; -- Duration
EXEC SP_TRACE_SETEVENT @TraceID, 118, 14, @on; -- StartTime
EXEC SP_TRACE_SETEVENT @TraceID, 118, 15, @on; -- EndTime
EXEC SP_TRACE_SETEVENT @TraceID, 118, 19, @on; -- Permissions
EXEC SP_TRACE_SETEVENT @TraceID, 118, 21, @on; -- EventSubClass
EXEC SP_TRACE_SETEVENT @TraceID, 118, 23, @on; -- Success (successful use of permissions)
EXEC SP_TRACE_SETEVENT @TraceID, 118, 26, @on; -- ServerName
EXEC SP_TRACE_SETEVENT @TraceID, 118, 28, @on; -- ObjectType
EXEC SP_TRACE_SETEVENT @TraceID, 118, 30, @on; -- State
EXEC SP_TRACE_SETEVENT @TraceID, 118, 31, @on; -- Error
EXEC SP_TRACE_SETEVENT @TraceID, 118, 34, @on; -- ObjectName
EXEC SP_TRACE_SETEVENT @TraceID, 118, 35, @on; -- DatabaseName
EXEC SP_TRACE_SETEVENT @TraceID, 118, 37, @on; -- OwnerName
EXEC SP_TRACE_SETEVENT @TraceID, 118, 38, @on; -- RoleName
EXEC SP_TRACE_SETEVENT @TraceID, 118, 39, @on; -- TargetUserName
EXEC SP_TRACE_SETEVENT @TraceID, 118, 40, @on; -- DBUserName
EXEC SP_TRACE_SETEVENT @TraceID, 118, 41, @on; -- LoginSid
EXEC SP_TRACE_SETEVENT @TraceID, 118, 42, @on; -- TargetLoginName
EXEC SP_TRACE_SETEVENT @TraceID, 118, 43, @on; -- TargetLoginSid
EXEC SP_TRACE_SETEVENT @TraceID, 118, 44, @on; -- ColumnPermissions
EXEC SP_TRACE_SETEVENT @TraceID, 118, 45, @on; -- LinkedServerName
EXEC SP_TRACE_SETEVENT @TraceID, 118, 46, @on; -- ProviderName
EXEC SP_TRACE_SETEVENT @TraceID, 118, 51, @on; -- EventSequence
EXEC SP_TRACE_SETEVENT @TraceID, 118, 59, @on; -- ParentName
EXEC SP_TRACE_SETEVENT @TraceID, 118, 60, @on; -- IsSystem
EXEC SP_TRACE_SETEVENT @TraceID, 118, 64, @on; -- SessionLoginName
-- Audit Database Management Event
-- Occurs when a CREATE, ALTER, or DROP statement executes on
-- database objects, such as schemas.
EXEC SP_TRACE_SETEVENT @TraceID, 128, 1,  @on; -- TextData
EXEC SP_TRACE_SETEVENT @TraceID, 128, 6,  @on; -- NTUserName
EXEC SP_TRACE_SETEVENT @TraceID, 128, 7,  @on; -- NTDomainName
EXEC SP_TRACE_SETEVENT @TraceID, 128, 8,  @on; -- HostName
EXEC SP_TRACE_SETEVENT @TraceID, 128, 9,  @on; -- ClientProcessID
EXEC SP_TRACE_SETEVENT @TraceID, 128, 10, @on; -- ApplicationName
EXEC SP_TRACE_SETEVENT @TraceID, 128, 11, @on; -- LoginName
EXEC SP_TRACE_SETEVENT @TraceID, 128, 12, @on; -- SPID
EXEC SP_TRACE_SETEVENT @TraceID, 128, 13, @on; -- Duration
EXEC SP_TRACE_SETEVENT @TraceID, 128, 14, @on; -- StartTime
EXEC SP_TRACE_SETEVENT @TraceID, 128, 15, @on; -- EndTime
EXEC SP_TRACE_SETEVENT @TraceID, 128, 19, @on; -- Permissions
EXEC SP_TRACE_SETEVENT @TraceID, 128, 21, @on; -- EventSubClass
EXEC SP_TRACE_SETEVENT @TraceID, 128, 23, @on; -- Success (successful use of permissions)
EXEC SP_TRACE_SETEVENT @TraceID, 128, 26, @on; -- ServerName
EXEC SP_TRACE_SETEVENT @TraceID, 128, 28, @on; -- ObjectType
EXEC SP_TRACE_SETEVENT @TraceID, 128, 30, @on; -- State
EXEC SP_TRACE_SETEVENT @TraceID, 128, 31, @on; -- Error
EXEC SP_TRACE_SETEVENT @TraceID, 128, 34, @on; -- ObjectName
EXEC SP_TRACE_SETEVENT @TraceID, 128, 35, @on; -- DatabaseName
EXEC SP_TRACE_SETEVENT @TraceID, 128, 37, @on; -- OwnerName
EXEC SP_TRACE_SETEVENT @TraceID, 128, 38, @on; -- RoleName
EXEC SP_TRACE_SETEVENT @TraceID, 128, 39, @on; -- TargetUserName
EXEC SP_TRACE_SETEVENT @TraceID, 128, 40, @on; -- DBUserName
EXEC SP_TRACE_SETEVENT @TraceID, 128, 41, @on; -- LoginSid
EXEC SP_TRACE_SETEVENT @TraceID, 128, 42, @on; -- TargetLoginName
EXEC SP_TRACE_SETEVENT @TraceID, 128, 43, @on; -- TargetLoginSid
EXEC SP_TRACE_SETEVENT @TraceID, 128, 44, @on; -- ColumnPermissions
EXEC SP_TRACE_SETEVENT @TraceID, 128, 45, @on; -- LinkedServerName
EXEC SP_TRACE_SETEVENT @TraceID, 128, 46, @on; -- ProviderName
EXEC SP_TRACE_SETEVENT @TraceID, 128, 51, @on; -- EventSequence
EXEC SP_TRACE_SETEVENT @TraceID, 128, 59, @on; -- ParentName
EXEC SP_TRACE_SETEVENT @TraceID, 128, 60, @on; -- IsSystem
EXEC SP_TRACE_SETEVENT @TraceID, 128, 64, @on; -- SessionLoginName
-- Audit Database Object Management Event
-- Occurs when a CREATE, ALTER, or DROP statement executes on
-- database objects, such as schemas.
EXEC SP_TRACE_SETEVENT @TraceID, 129, 1,  @on; -- TextData
EXEC SP_TRACE_SETEVENT @TraceID, 129, 6,  @on; -- NTUserName
EXEC SP_TRACE_SETEVENT @TraceID, 129, 7,  @on; -- NTDomainName
EXEC SP_TRACE_SETEVENT @TraceID, 129, 8,  @on; -- HostName
EXEC SP_TRACE_SETEVENT @TraceID, 129, 9,  @on; -- ClientProcessID
EXEC SP_TRACE_SETEVENT @TraceID, 129, 10, @on; -- ApplicationName
EXEC SP_TRACE_SETEVENT @TraceID, 129, 11, @on; -- LoginName
EXEC SP_TRACE_SETEVENT @TraceID, 129, 12, @on; -- SPID
EXEC SP_TRACE_SETEVENT @TraceID, 129, 13, @on; -- Duration
EXEC SP_TRACE_SETEVENT @TraceID, 129, 14, @on; -- StartTime
EXEC SP_TRACE_SETEVENT @TraceID, 129, 15, @on; -- EndTime
EXEC SP_TRACE_SETEVENT @TraceID, 129, 19, @on; -- Permissions
EXEC SP_TRACE_SETEVENT @TraceID, 129, 21, @on; -- EventSubClass
EXEC SP_TRACE_SETEVENT @TraceID, 129, 23, @on; -- Success (successful use of permissions)
EXEC SP_TRACE_SETEVENT @TraceID, 129, 26, @on; -- ServerName
EXEC SP_TRACE_SETEVENT @TraceID, 129, 28, @on; -- ObjectType
EXEC SP_TRACE_SETEVENT @TraceID, 129, 30, @on; -- State
EXEC SP_TRACE_SETEVENT @TraceID, 129, 31, @on; -- Error
EXEC SP_TRACE_SETEVENT @TraceID, 129, 34, @on; -- ObjectName
EXEC SP_TRACE_SETEVENT @TraceID, 129, 35, @on; -- DatabaseName
EXEC SP_TRACE_SETEVENT @TraceID, 129, 37, @on; -- OwnerName
EXEC SP_TRACE_SETEVENT @TraceID, 129, 38, @on; -- RoleName
EXEC SP_TRACE_SETEVENT @TraceID, 129, 39, @on; -- TargetUserName
EXEC SP_TRACE_SETEVENT @TraceID, 129, 40, @on; -- DBUserName
EXEC SP_TRACE_SETEVENT @TraceID, 129, 41, @on; -- LoginSid
EXEC SP_TRACE_SETEVENT @TraceID, 129, 42, @on; -- TargetLoginName
EXEC SP_TRACE_SETEVENT @TraceID, 129, 43, @on; -- TargetLoginSid
EXEC SP_TRACE_SETEVENT @TraceID, 129, 44, @on; -- ColumnPermissions
EXEC SP_TRACE_SETEVENT @TraceID, 129, 45, @on; -- LinkedServerName
EXEC SP_TRACE_SETEVENT @TraceID, 129, 46, @on; -- ProviderName
EXEC SP_TRACE_SETEVENT @TraceID, 129, 51, @on; -- EventSequence
EXEC SP_TRACE_SETEVENT @TraceID, 129, 59, @on; -- ParentName
EXEC SP_TRACE_SETEVENT @TraceID, 129, 60, @on; -- IsSystem
EXEC SP_TRACE_SETEVENT @TraceID, 129, 64, @on; -- SessionLoginName
-- Audit Database Principal Management Event
-- Occurs when principals, such as users, are created, altered, or
-- dropped from a database.
EXEC SP_TRACE_SETEVENT @TraceID, 130, 1,  @on; -- TextData
EXEC SP_TRACE_SETEVENT @TraceID, 130, 6,  @on; -- NTUserName
EXEC SP_TRACE_SETEVENT @TraceID, 130, 7,  @on; -- NTDomainName
EXEC SP_TRACE_SETEVENT @TraceID, 130, 8,  @on; -- HostName
EXEC SP_TRACE_SETEVENT @TraceID, 130, 9,  @on; -- ClientProcessID
EXEC SP_TRACE_SETEVENT @TraceID, 130, 10, @on; -- ApplicationName
EXEC SP_TRACE_SETEVENT @TraceID, 130, 11, @on; -- LoginName
EXEC SP_TRACE_SETEVENT @TraceID, 130, 12, @on; -- SPID
EXEC SP_TRACE_SETEVENT @TraceID, 130, 13, @on; -- Duration
EXEC SP_TRACE_SETEVENT @TraceID, 130, 14, @on; -- StartTime
EXEC SP_TRACE_SETEVENT @TraceID, 130, 15, @on; -- EndTime
EXEC SP_TRACE_SETEVENT @TraceID, 130, 19, @on; -- Permissions
EXEC SP_TRACE_SETEVENT @TraceID, 130, 21, @on; -- EventSubClass
EXEC SP_TRACE_SETEVENT @TraceID, 130, 23, @on; -- Success (successful use of permissions)
EXEC SP_TRACE_SETEVENT @TraceID, 130, 26, @on; -- ServerName
EXEC SP_TRACE_SETEVENT @TraceID, 130, 28, @on; -- ObjectType
EXEC SP_TRACE_SETEVENT @TraceID, 130, 30, @on; -- State
EXEC SP_TRACE_SETEVENT @TraceID, 130, 31, @on; -- Error
EXEC SP_TRACE_SETEVENT @TraceID, 130, 34, @on; -- ObjectName
EXEC SP_TRACE_SETEVENT @TraceID, 130, 35, @on; -- DatabaseName
EXEC SP_TRACE_SETEVENT @TraceID, 130, 37, @on; -- OwnerName
EXEC SP_TRACE_SETEVENT @TraceID, 130, 38, @on; -- RoleName
EXEC SP_TRACE_SETEVENT @TraceID, 130, 39, @on; -- TargetUserName
EXEC SP_TRACE_SETEVENT @TraceID, 130, 40, @on; -- DBUserName
EXEC SP_TRACE_SETEVENT @TraceID, 130, 41, @on; -- LoginSid
EXEC SP_TRACE_SETEVENT @TraceID, 130, 42, @on; -- TargetLoginName
EXEC SP_TRACE_SETEVENT @TraceID, 130, 43, @on; -- TargetLoginSid
EXEC SP_TRACE_SETEVENT @TraceID, 130, 44, @on; -- ColumnPermissions
EXEC SP_TRACE_SETEVENT @TraceID, 130, 45, @on; -- LinkedServerName
EXEC SP_TRACE_SETEVENT @TraceID, 130, 46, @on; -- ProviderName
EXEC SP_TRACE_SETEVENT @TraceID, 130, 51, @on; -- EventSequence
EXEC SP_TRACE_SETEVENT @TraceID, 130, 59, @on; -- ParentName
EXEC SP_TRACE_SETEVENT @TraceID, 130, 60, @on; -- IsSystem
EXEC SP_TRACE_SETEVENT @TraceID, 130, 64, @on; -- SessionLoginName
-- Audit Schema Object Management Event
-- Occurs when server objects are created, altered, or dropped.
EXEC SP_TRACE_SETEVENT @TraceID, 131, 1,  @on; -- TextData
EXEC SP_TRACE_SETEVENT @TraceID, 131, 6,  @on; -- NTUserName
EXEC SP_TRACE_SETEVENT @TraceID, 131, 7,  @on; -- NTDomainName
EXEC SP_TRACE_SETEVENT @TraceID, 131, 8,  @on; -- HostName
EXEC SP_TRACE_SETEVENT @TraceID, 131, 9,  @on; -- ClientProcessID
EXEC SP_TRACE_SETEVENT @TraceID, 131, 10, @on; -- ApplicationName
EXEC SP_TRACE_SETEVENT @TraceID, 131, 11, @on; -- LoginName
EXEC SP_TRACE_SETEVENT @TraceID, 131, 12, @on; -- SPID
EXEC SP_TRACE_SETEVENT @TraceID, 131, 13, @on; -- Duration
EXEC SP_TRACE_SETEVENT @TraceID, 131, 14, @on; -- StartTime
EXEC SP_TRACE_SETEVENT @TraceID, 131, 15, @on; -- EndTime
EXEC SP_TRACE_SETEVENT @TraceID, 131, 19, @on; -- Permissions
EXEC SP_TRACE_SETEVENT @TraceID, 131, 21, @on; -- EventSubClass
EXEC SP_TRACE_SETEVENT @TraceID, 131, 23, @on; -- Success (successful use of permissions)
EXEC SP_TRACE_SETEVENT @TraceID, 131, 26, @on; -- ServerName
EXEC SP_TRACE_SETEVENT @TraceID, 131, 28, @on; -- ObjectType
EXEC SP_TRACE_SETEVENT @TraceID, 131, 30, @on; -- State
EXEC SP_TRACE_SETEVENT @TraceID, 131, 31, @on; -- Error
EXEC SP_TRACE_SETEVENT @TraceID, 131, 34, @on; -- ObjectName
EXEC SP_TRACE_SETEVENT @TraceID, 131, 35, @on; -- DatabaseName
EXEC SP_TRACE_SETEVENT @TraceID, 131, 37, @on; -- OwnerName
EXEC SP_TRACE_SETEVENT @TraceID, 131, 38, @on; -- RoleName
EXEC SP_TRACE_SETEVENT @TraceID, 131, 39, @on; -- TargetUserName
EXEC SP_TRACE_SETEVENT @TraceID, 131, 40, @on; -- DBUserName
EXEC SP_TRACE_SETEVENT @TraceID, 131, 41, @on; -- LoginSid
EXEC SP_TRACE_SETEVENT @TraceID, 131, 42, @on; -- TargetLoginName
EXEC SP_TRACE_SETEVENT @TraceID, 131, 43, @on; -- TargetLoginSid
EXEC SP_TRACE_SETEVENT @TraceID, 131, 44, @on; -- ColumnPermissions
EXEC SP_TRACE_SETEVENT @TraceID, 131, 45, @on; -- LinkedServerName
EXEC SP_TRACE_SETEVENT @TraceID, 131, 46, @on; -- ProviderName
EXEC SP_TRACE_SETEVENT @TraceID, 131, 51, @on; -- EventSequence
EXEC SP_TRACE_SETEVENT @TraceID, 131, 59, @on; -- ParentName
EXEC SP_TRACE_SETEVENT @TraceID, 131, 60, @on; -- IsSystem
EXEC SP_TRACE_SETEVENT @TraceID, 131, 64, @on; -- SessionLoginName
-- Audit Server Principal Impersonation Event
-- Occurs when there is an impersonation within server scope, such
-- as EXECUTE AS LOGIN.
EXEC SP_TRACE_SETEVENT @TraceID, 132, 1,  @on; -- TextData
EXEC SP_TRACE_SETEVENT @TraceID, 132, 6,  @on; -- NTUserName
EXEC SP_TRACE_SETEVENT @TraceID, 132, 7,  @on; -- NTDomainName
EXEC SP_TRACE_SETEVENT @TraceID, 132, 8,  @on; -- HostName
EXEC SP_TRACE_SETEVENT @TraceID, 132, 9,  @on; -- ClientProcessID
EXEC SP_TRACE_SETEVENT @TraceID, 132, 10, @on; -- ApplicationName
EXEC SP_TRACE_SETEVENT @TraceID, 132, 11, @on; -- LoginName
EXEC SP_TRACE_SETEVENT @TraceID, 132, 12, @on; -- SPID
EXEC SP_TRACE_SETEVENT @TraceID, 132, 13, @on; -- Duration
EXEC SP_TRACE_SETEVENT @TraceID, 132, 14, @on; -- StartTime
EXEC SP_TRACE_SETEVENT @TraceID, 132, 15, @on; -- EndTime
EXEC SP_TRACE_SETEVENT @TraceID, 132, 19, @on; -- Permissions
EXEC SP_TRACE_SETEVENT @TraceID, 132, 21, @on; -- EventSubClass
EXEC SP_TRACE_SETEVENT @TraceID, 132, 23, @on; -- Success (successful use of permissions)
EXEC SP_TRACE_SETEVENT @TraceID, 132, 26, @on; -- ServerName
EXEC SP_TRACE_SETEVENT @TraceID, 132, 28, @on; -- ObjectType
EXEC SP_TRACE_SETEVENT @TraceID, 132, 30, @on; -- State
EXEC SP_TRACE_SETEVENT @TraceID, 132, 31, @on; -- Error
EXEC SP_TRACE_SETEVENT @TraceID, 132, 34, @on; -- ObjectName
EXEC SP_TRACE_SETEVENT @TraceID, 132, 35, @on; -- DatabaseName
EXEC SP_TRACE_SETEVENT @TraceID, 132, 37, @on; -- OwnerName
EXEC SP_TRACE_SETEVENT @TraceID, 132, 38, @on; -- RoleName
EXEC SP_TRACE_SETEVENT @TraceID, 132, 39, @on; -- TargetUserName
EXEC SP_TRACE_SETEVENT @TraceID, 132, 40, @on; -- DBUserName
EXEC SP_TRACE_SETEVENT @TraceID, 132, 41, @on; -- LoginSid
EXEC SP_TRACE_SETEVENT @TraceID, 132, 42, @on; -- TargetLoginName
EXEC SP_TRACE_SETEVENT @TraceID, 132, 43, @on; -- TargetLoginSid
EXEC SP_TRACE_SETEVENT @TraceID, 132, 44, @on; -- ColumnPermissions
EXEC SP_TRACE_SETEVENT @TraceID, 132, 45, @on; -- LinkedServerName
EXEC SP_TRACE_SETEVENT @TraceID, 132, 46, @on; -- ProviderName
EXEC SP_TRACE_SETEVENT @TraceID, 132, 51, @on; -- EventSequence
EXEC SP_TRACE_SETEVENT @TraceID, 132, 59, @on; -- ParentName
EXEC SP_TRACE_SETEVENT @TraceID, 132, 60, @on; -- IsSystem
EXEC SP_TRACE_SETEVENT @TraceID, 132, 64, @on; -- SessionLoginName
-- Audit Database Principal Impersonation Event
-- Occurs when an impersonation occurs within the database scope,
-- such as EXECUTE AS USER or SETUSER.
EXEC SP_TRACE_SETEVENT @TraceID, 133, 1,  @on; -- TextData
EXEC SP_TRACE_SETEVENT @TraceID, 133, 6,  @on; -- NTUserName
EXEC SP_TRACE_SETEVENT @TraceID, 133, 7,  @on; -- NTDomainName
EXEC SP_TRACE_SETEVENT @TraceID, 133, 8,  @on; -- HostName
EXEC SP_TRACE_SETEVENT @TraceID, 133, 9,  @on; -- ClientProcessID
EXEC SP_TRACE_SETEVENT @TraceID, 133, 10, @on; -- ApplicationName
EXEC SP_TRACE_SETEVENT @TraceID, 133, 11, @on; -- LoginName
EXEC SP_TRACE_SETEVENT @TraceID, 133, 12, @on; -- SPID
EXEC SP_TRACE_SETEVENT @TraceID, 133, 13, @on; -- Duration
EXEC SP_TRACE_SETEVENT @TraceID, 133, 14, @on; -- StartTime
EXEC SP_TRACE_SETEVENT @TraceID, 133, 15, @on; -- EndTime
EXEC SP_TRACE_SETEVENT @TraceID, 133, 19, @on; -- Permissions
EXEC SP_TRACE_SETEVENT @TraceID, 133, 21, @on; -- EventSubClass
EXEC SP_TRACE_SETEVENT @TraceID, 133, 23, @on; -- Success (successful use of permissions)
EXEC SP_TRACE_SETEVENT @TraceID, 133, 26, @on; -- ServerName
EXEC SP_TRACE_SETEVENT @TraceID, 133, 28, @on; -- ObjectType
EXEC SP_TRACE_SETEVENT @TraceID, 133, 30, @on; -- State
EXEC SP_TRACE_SETEVENT @TraceID, 133, 31, @on; -- Error
EXEC SP_TRACE_SETEVENT @TraceID, 133, 34, @on; -- ObjectName
EXEC SP_TRACE_SETEVENT @TraceID, 133, 35, @on; -- DatabaseName
EXEC SP_TRACE_SETEVENT @TraceID, 133, 37, @on; -- OwnerName
EXEC SP_TRACE_SETEVENT @TraceID, 133, 38, @on; -- RoleName
EXEC SP_TRACE_SETEVENT @TraceID, 133, 39, @on; -- TargetUserName
EXEC SP_TRACE_SETEVENT @TraceID, 133, 40, @on; -- DBUserName
EXEC SP_TRACE_SETEVENT @TraceID, 133, 41, @on; -- LoginSid
EXEC SP_TRACE_SETEVENT @TraceID, 133, 42, @on; -- TargetLoginName
EXEC SP_TRACE_SETEVENT @TraceID, 133, 43, @on; -- TargetLoginSid
EXEC SP_TRACE_SETEVENT @TraceID, 133, 44, @on; -- ColumnPermissions
EXEC SP_TRACE_SETEVENT @TraceID, 133, 45, @on; -- LinkedServerName
EXEC SP_TRACE_SETEVENT @TraceID, 133, 46, @on; -- ProviderName
EXEC SP_TRACE_SETEVENT @TraceID, 133, 51, @on; -- EventSequence
EXEC SP_TRACE_SETEVENT @TraceID, 133, 59, @on; -- ParentName
EXEC SP_TRACE_SETEVENT @TraceID, 133, 60, @on; -- IsSystem
EXEC SP_TRACE_SETEVENT @TraceID, 133, 64, @on; -- SessionLoginName
-- Audit Server Object Take Ownership Event
-- Occurs when the owner is changed for objects in server scope.
EXEC SP_TRACE_SETEVENT @TraceID, 134, 1,  @on; -- TextData
EXEC SP_TRACE_SETEVENT @TraceID, 134, 6,  @on; -- NTUserName
EXEC SP_TRACE_SETEVENT @TraceID, 134, 7,  @on; -- NTDomainName
EXEC SP_TRACE_SETEVENT @TraceID, 134, 8,  @on; -- HostName
EXEC SP_TRACE_SETEVENT @TraceID, 134, 9,  @on; -- ClientProcessID
EXEC SP_TRACE_SETEVENT @TraceID, 134, 10, @on; -- ApplicationName
EXEC SP_TRACE_SETEVENT @TraceID, 134, 11, @on; -- LoginName
EXEC SP_TRACE_SETEVENT @TraceID, 134, 12, @on; -- SPID
EXEC SP_TRACE_SETEVENT @TraceID, 134, 13, @on; -- Duration
EXEC SP_TRACE_SETEVENT @TraceID, 134, 14, @on; -- StartTime
EXEC SP_TRACE_SETEVENT @TraceID, 134, 15, @on; -- EndTime
EXEC SP_TRACE_SETEVENT @TraceID, 134, 19, @on; -- Permissions
EXEC SP_TRACE_SETEVENT @TraceID, 134, 21, @on; -- EventSubClass
EXEC SP_TRACE_SETEVENT @TraceID, 134, 23, @on; -- Success (successful use of permissions)
EXEC SP_TRACE_SETEVENT @TraceID, 134, 26, @on; -- ServerName
EXEC SP_TRACE_SETEVENT @TraceID, 134, 28, @on; -- ObjectType
EXEC SP_TRACE_SETEVENT @TraceID, 134, 30, @on; -- State
EXEC SP_TRACE_SETEVENT @TraceID, 134, 31, @on; -- Error
EXEC SP_TRACE_SETEVENT @TraceID, 134, 34, @on; -- ObjectName
EXEC SP_TRACE_SETEVENT @TraceID, 134, 35, @on; -- DatabaseName
EXEC SP_TRACE_SETEVENT @TraceID, 134, 37, @on; -- OwnerName
EXEC SP_TRACE_SETEVENT @TraceID, 134, 38, @on; -- RoleName
EXEC SP_TRACE_SETEVENT @TraceID, 134, 39, @on; -- TargetUserName
EXEC SP_TRACE_SETEVENT @TraceID, 134, 40, @on; -- DBUserName
EXEC SP_TRACE_SETEVENT @TraceID, 134, 41, @on; -- LoginSid
EXEC SP_TRACE_SETEVENT @TraceID, 134, 42, @on; -- TargetLoginName
EXEC SP_TRACE_SETEVENT @TraceID, 134, 43, @on; -- TargetLoginSid
EXEC SP_TRACE_SETEVENT @TraceID, 134, 44, @on; -- ColumnPermissions
EXEC SP_TRACE_SETEVENT @TraceID, 134, 45, @on; -- LinkedServerName
EXEC SP_TRACE_SETEVENT @TraceID, 134, 46, @on; -- ProviderName
EXEC SP_TRACE_SETEVENT @TraceID, 134, 51, @on; -- EventSequence
EXEC SP_TRACE_SETEVENT @TraceID, 134, 59, @on; -- ParentName
EXEC SP_TRACE_SETEVENT @TraceID, 134, 60, @on; -- IsSystem
EXEC SP_TRACE_SETEVENT @TraceID, 134, 64, @on; -- SessionLoginName
-- Audit Database Object Take Ownership Event
-- Occurs when a change of owner for objects within database scope
-- occurs.
EXEC SP_TRACE_SETEVENT @TraceID, 135, 1,  @on; -- TextData
EXEC SP_TRACE_SETEVENT @TraceID, 135, 6,  @on; -- NTUserName
EXEC SP_TRACE_SETEVENT @TraceID, 135, 7,  @on; -- NTDomainName
EXEC SP_TRACE_SETEVENT @TraceID, 135, 8,  @on; -- HostName
EXEC SP_TRACE_SETEVENT @TraceID, 135, 9,  @on; -- ClientProcessID
EXEC SP_TRACE_SETEVENT @TraceID, 135, 10, @on; -- ApplicationName
EXEC SP_TRACE_SETEVENT @TraceID, 135, 11, @on; -- LoginName
EXEC SP_TRACE_SETEVENT @TraceID, 135, 12, @on; -- SPID
EXEC SP_TRACE_SETEVENT @TraceID, 135, 13, @on; -- Duration
EXEC SP_TRACE_SETEVENT @TraceID, 135, 14, @on; -- StartTime
EXEC SP_TRACE_SETEVENT @TraceID, 135, 15, @on; -- EndTime
EXEC SP_TRACE_SETEVENT @TraceID, 135, 19, @on; -- Permissions
EXEC SP_TRACE_SETEVENT @TraceID, 135, 21, @on; -- EventSubClass
EXEC SP_TRACE_SETEVENT @TraceID, 135, 23, @on; -- Success (successful use of permissions)
EXEC SP_TRACE_SETEVENT @TraceID, 135, 26, @on; -- ServerName
EXEC SP_TRACE_SETEVENT @TraceID, 135, 28, @on; -- ObjectType
EXEC SP_TRACE_SETEVENT @TraceID, 135, 30, @on; -- State
EXEC SP_TRACE_SETEVENT @TraceID, 135, 31, @on; -- Error
EXEC SP_TRACE_SETEVENT @TraceID, 135, 34, @on; -- ObjectName
EXEC SP_TRACE_SETEVENT @TraceID, 135, 35, @on; -- DatabaseName
EXEC SP_TRACE_SETEVENT @TraceID, 135, 37, @on; -- OwnerName
EXEC SP_TRACE_SETEVENT @TraceID, 135, 38, @on; -- RoleName
EXEC SP_TRACE_SETEVENT @TraceID, 135, 39, @on; -- TargetUserName
EXEC SP_TRACE_SETEVENT @TraceID, 135, 40, @on; -- DBUserName
EXEC SP_TRACE_SETEVENT @TraceID, 135, 41, @on; -- LoginSid
EXEC SP_TRACE_SETEVENT @TraceID, 135, 42, @on; -- TargetLoginName
EXEC SP_TRACE_SETEVENT @TraceID, 135, 43, @on; -- TargetLoginSid
EXEC SP_TRACE_SETEVENT @TraceID, 135, 44, @on; -- ColumnPermissions
EXEC SP_TRACE_SETEVENT @TraceID, 135, 45, @on; -- LinkedServerName
EXEC SP_TRACE_SETEVENT @TraceID, 135, 46, @on; -- ProviderName
EXEC SP_TRACE_SETEVENT @TraceID, 135, 51, @on; -- EventSequence
EXEC SP_TRACE_SETEVENT @TraceID, 135, 59, @on; -- ParentName
EXEC SP_TRACE_SETEVENT @TraceID, 135, 60, @on; -- IsSystem
EXEC SP_TRACE_SETEVENT @TraceID, 135, 64, @on; -- SessionLoginName
-- Audit Change Database Owner
-- Occurs when ALTER AUTHORIZATION is used to change the owner of a
-- database and permissions are checked to do that.
EXEC SP_TRACE_SETEVENT @TraceID, 152, 1,  @on; -- TextData
EXEC SP_TRACE_SETEVENT @TraceID, 152, 6,  @on; -- NTUserName
EXEC SP_TRACE_SETEVENT @TraceID, 152, 7,  @on; -- NTDomainName
EXEC SP_TRACE_SETEVENT @TraceID, 152, 8,  @on; -- HostName
EXEC SP_TRACE_SETEVENT @TraceID, 152, 9,  @on; -- ClientProcessID
EXEC SP_TRACE_SETEVENT @TraceID, 152, 10, @on; -- ApplicationName
EXEC SP_TRACE_SETEVENT @TraceID, 152, 11, @on; -- LoginName
EXEC SP_TRACE_SETEVENT @TraceID, 152, 12, @on; -- SPID
EXEC SP_TRACE_SETEVENT @TraceID, 152, 13, @on; -- Duration
EXEC SP_TRACE_SETEVENT @TraceID, 152, 14, @on; -- StartTime
EXEC SP_TRACE_SETEVENT @TraceID, 152, 15, @on; -- EndTime
EXEC SP_TRACE_SETEVENT @TraceID, 152, 19, @on; -- Permissions
EXEC SP_TRACE_SETEVENT @TraceID, 152, 21, @on; -- EventSubClass
EXEC SP_TRACE_SETEVENT @TraceID, 152, 23, @on; -- Success (successful use of permissions)
EXEC SP_TRACE_SETEVENT @TraceID, 152, 26, @on; -- ServerName
EXEC SP_TRACE_SETEVENT @TraceID, 152, 28, @on; -- ObjectType
EXEC SP_TRACE_SETEVENT @TraceID, 152, 30, @on; -- State
EXEC SP_TRACE_SETEVENT @TraceID, 152, 31, @on; -- Error
EXEC SP_TRACE_SETEVENT @TraceID, 152, 34, @on; -- ObjectName
EXEC SP_TRACE_SETEVENT @TraceID, 152, 35, @on; -- DatabaseName
EXEC SP_TRACE_SETEVENT @TraceID, 152, 37, @on; -- OwnerName
EXEC SP_TRACE_SETEVENT @TraceID, 152, 38, @on; -- RoleName
EXEC SP_TRACE_SETEVENT @TraceID, 152, 39, @on; -- TargetUserName
EXEC SP_TRACE_SETEVENT @TraceID, 152, 40, @on; -- DBUserName
EXEC SP_TRACE_SETEVENT @TraceID, 152, 41, @on; -- LoginSid
EXEC SP_TRACE_SETEVENT @TraceID, 152, 42, @on; -- TargetLoginName
EXEC SP_TRACE_SETEVENT @TraceID, 152, 43, @on; -- TargetLoginSid
EXEC SP_TRACE_SETEVENT @TraceID, 152, 44, @on; -- ColumnPermissions
EXEC SP_TRACE_SETEVENT @TraceID, 152, 45, @on; -- LinkedServerName
EXEC SP_TRACE_SETEVENT @TraceID, 152, 46, @on; -- ProviderName
EXEC SP_TRACE_SETEVENT @TraceID, 152, 51, @on; -- EventSequence
EXEC SP_TRACE_SETEVENT @TraceID, 152, 59, @on; -- ParentName
EXEC SP_TRACE_SETEVENT @TraceID, 152, 60, @on; -- IsSystem
EXEC SP_TRACE_SETEVENT @TraceID, 152, 64, @on; -- SessionLoginName
-- Audit Schema Object Take Ownership Event
-- Occurs when ALTER AUTHORIZATION is used to assign an owner to an
-- object and permissions are checked to do that.
EXEC SP_TRACE_SETEVENT @TraceID, 153, 1,  @on; -- TextData
EXEC SP_TRACE_SETEVENT @TraceID, 153, 6,  @on; -- NTUserName
EXEC SP_TRACE_SETEVENT @TraceID, 153, 7,  @on; -- NTDomainName
EXEC SP_TRACE_SETEVENT @TraceID, 153, 8,  @on; -- HostName
EXEC SP_TRACE_SETEVENT @TraceID, 153, 9,  @on; -- ClientProcessID
EXEC SP_TRACE_SETEVENT @TraceID, 153, 10, @on; -- ApplicationName
EXEC SP_TRACE_SETEVENT @TraceID, 153, 11, @on; -- LoginName
EXEC SP_TRACE_SETEVENT @TraceID, 153, 12, @on; -- SPID
EXEC SP_TRACE_SETEVENT @TraceID, 153, 13, @on; -- Duration
EXEC SP_TRACE_SETEVENT @TraceID, 153, 14, @on; -- StartTime
EXEC SP_TRACE_SETEVENT @TraceID, 153, 15, @on; -- EndTime
EXEC SP_TRACE_SETEVENT @TraceID, 153, 19, @on; -- Permissions
EXEC SP_TRACE_SETEVENT @TraceID, 153, 21, @on; -- EventSubClass
EXEC SP_TRACE_SETEVENT @TraceID, 153, 23, @on; -- Success (successful use of permissions)
EXEC SP_TRACE_SETEVENT @TraceID, 153, 26, @on; -- ServerName
EXEC SP_TRACE_SETEVENT @TraceID, 153, 28, @on; -- ObjectType
EXEC SP_TRACE_SETEVENT @TraceID, 153, 30, @on; -- State
EXEC SP_TRACE_SETEVENT @TraceID, 153, 31, @on; -- Error
EXEC SP_TRACE_SETEVENT @TraceID, 153, 34, @on; -- ObjectName
EXEC SP_TRACE_SETEVENT @TraceID, 153, 35, @on; -- DatabaseName
EXEC SP_TRACE_SETEVENT @TraceID, 153, 37, @on; -- OwnerName
EXEC SP_TRACE_SETEVENT @TraceID, 153, 38, @on; -- RoleName
EXEC SP_TRACE_SETEVENT @TraceID, 153, 39, @on; -- TargetUserName
EXEC SP_TRACE_SETEVENT @TraceID, 153, 40, @on; -- DBUserName
EXEC SP_TRACE_SETEVENT @TraceID, 153, 41, @on; -- LoginSid
EXEC SP_TRACE_SETEVENT @TraceID, 153, 42, @on; -- TargetLoginName
EXEC SP_TRACE_SETEVENT @TraceID, 153, 43, @on; -- TargetLoginSid
EXEC SP_TRACE_SETEVENT @TraceID, 153, 44, @on; -- ColumnPermissions
EXEC SP_TRACE_SETEVENT @TraceID, 153, 45, @on; -- LinkedServerName
EXEC SP_TRACE_SETEVENT @TraceID, 153, 46, @on; -- ProviderName
EXEC SP_TRACE_SETEVENT @TraceID, 153, 51, @on; -- EventSequence
EXEC SP_TRACE_SETEVENT @TraceID, 153, 59, @on; -- ParentName
EXEC SP_TRACE_SETEVENT @TraceID, 153, 60, @on; -- IsSystem
EXEC SP_TRACE_SETEVENT @TraceID, 153, 64, @on; -- SessionLoginName
-- User error message
EXEC SP_TRACE_SETEVENT @TraceID, 162, 1,  @on; -- TextData
EXEC SP_TRACE_SETEVENT @TraceID, 162, 6,  @on; -- NTUserName
EXEC SP_TRACE_SETEVENT @TraceID, 162, 7,  @on; -- NTDomainName
EXEC SP_TRACE_SETEVENT @TraceID, 162, 8,  @on; -- HostName
EXEC SP_TRACE_SETEVENT @TraceID, 162, 9,  @on; -- ClientProcessID
EXEC SP_TRACE_SETEVENT @TraceID, 162, 10, @on; -- ApplicationName
EXEC SP_TRACE_SETEVENT @TraceID, 162, 11, @on; -- LoginName
EXEC SP_TRACE_SETEVENT @TraceID, 162, 12, @on; -- SPID
EXEC SP_TRACE_SETEVENT @TraceID, 162, 13, @on; -- Duration
EXEC SP_TRACE_SETEVENT @TraceID, 162, 14, @on; -- StartTime
EXEC SP_TRACE_SETEVENT @TraceID, 162, 15, @on; -- EndTime
EXEC SP_TRACE_SETEVENT @TraceID, 162, 19, @on; -- Permissions
EXEC SP_TRACE_SETEVENT @TraceID, 162, 21, @on; -- EventSubClass
EXEC SP_TRACE_SETEVENT @TraceID, 162, 23, @on; -- Success (successful use of permissions)
EXEC SP_TRACE_SETEVENT @TraceID, 162, 26, @on; -- ServerName
EXEC SP_TRACE_SETEVENT @TraceID, 162, 28, @on; -- ObjectType
EXEC SP_TRACE_SETEVENT @TraceID, 162, 30, @on; -- State
EXEC SP_TRACE_SETEVENT @TraceID, 162, 31, @on; -- Error
EXEC SP_TRACE_SETEVENT @TraceID, 162, 34, @on; -- ObjectName
EXEC SP_TRACE_SETEVENT @TraceID, 162, 35, @on; -- DatabaseName
EXEC SP_TRACE_SETEVENT @TraceID, 162, 37, @on; -- OwnerName
EXEC SP_TRACE_SETEVENT @TraceID, 162, 38, @on; -- RoleName
EXEC SP_TRACE_SETEVENT @TraceID, 162, 39, @on; -- TargetUserName
EXEC SP_TRACE_SETEVENT @TraceID, 162, 40, @on; -- DBUserName
EXEC SP_TRACE_SETEVENT @TraceID, 162, 41, @on; -- LoginSid
EXEC SP_TRACE_SETEVENT @TraceID, 162, 42, @on; -- TargetLoginName
EXEC SP_TRACE_SETEVENT @TraceID, 162, 43, @on; -- TargetLoginSid
EXEC SP_TRACE_SETEVENT @TraceID, 162, 44, @on; -- ColumnPermissions
EXEC SP_TRACE_SETEVENT @TraceID, 162, 45, @on; -- LinkedServerName
EXEC SP_TRACE_SETEVENT @TraceID, 162, 46, @on; -- ProviderName
EXEC SP_TRACE_SETEVENT @TraceID, 162, 51, @on; -- EventSequence
EXEC SP_TRACE_SETEVENT @TraceID, 162, 59, @on; -- ParentName
EXEC SP_TRACE_SETEVENT @TraceID, 162, 60, @on; -- IsSystem
EXEC SP_TRACE_SETEVENT @TraceID, 162, 64, @on; -- SessionLoginName
-- 164 Object:Altered
EXEC SP_TRACE_SETEVENT @TraceID, 164, 1,  @on; -- TextData
EXEC SP_TRACE_SETEVENT @TraceID, 164, 6,  @on; -- NTUserName
EXEC SP_TRACE_SETEVENT @TraceID, 164, 7,  @on; -- NTDomainName
EXEC SP_TRACE_SETEVENT @TraceID, 164, 8,  @on; -- HostName
EXEC SP_TRACE_SETEVENT @TraceID, 164, 9,  @on; -- ClientProcessID
EXEC SP_TRACE_SETEVENT @TraceID, 164, 10, @on; -- ApplicationName
EXEC SP_TRACE_SETEVENT @TraceID, 164, 11, @on; -- LoginName
EXEC SP_TRACE_SETEVENT @TraceID, 164, 12, @on; -- SPID
EXEC SP_TRACE_SETEVENT @TraceID, 164, 13, @on; -- Duration
EXEC SP_TRACE_SETEVENT @TraceID, 164, 14, @on; -- StartTime
EXEC SP_TRACE_SETEVENT @TraceID, 164, 15, @on; -- EndTime
EXEC SP_TRACE_SETEVENT @TraceID, 164, 19, @on; -- Permissions
EXEC SP_TRACE_SETEVENT @TraceID, 164, 21, @on; -- EventSubClass
EXEC SP_TRACE_SETEVENT @TraceID, 164, 23, @on; -- Success (successful use of permissions)
EXEC SP_TRACE_SETEVENT @TraceID, 164, 26, @on; -- ServerName
EXEC SP_TRACE_SETEVENT @TraceID, 164, 28, @on; -- ObjectType
EXEC SP_TRACE_SETEVENT @TraceID, 164, 30, @on; -- State
EXEC SP_TRACE_SETEVENT @TraceID, 164, 31, @on; -- Error
EXEC SP_TRACE_SETEVENT @TraceID, 164, 34, @on; -- ObjectName
EXEC SP_TRACE_SETEVENT @TraceID, 164, 35, @on; -- DatabaseName
EXEC SP_TRACE_SETEVENT @TraceID, 164, 37, @on; -- OwnerName
EXEC SP_TRACE_SETEVENT @TraceID, 164, 38, @on; -- RoleName
EXEC SP_TRACE_SETEVENT @TraceID, 164, 39, @on; -- TargetUserName
EXEC SP_TRACE_SETEVENT @TraceID, 164, 40, @on; -- DBUserName
EXEC SP_TRACE_SETEVENT @TraceID, 164, 41, @on; -- LoginSid
EXEC SP_TRACE_SETEVENT @TraceID, 164, 42, @on; -- TargetLoginName
EXEC SP_TRACE_SETEVENT @TraceID, 164, 43, @on; -- TargetLoginSid
EXEC SP_TRACE_SETEVENT @TraceID, 164, 44, @on; -- ColumnPermissions
EXEC SP_TRACE_SETEVENT @TraceID, 164, 45, @on; -- LinkedServerName
EXEC SP_TRACE_SETEVENT @TraceID, 164, 46, @on; -- ProviderName
EXEC SP_TRACE_SETEVENT @TraceID, 164, 51, @on; -- EventSequence
EXEC SP_TRACE_SETEVENT @TraceID, 164, 59, @on; -- ParentName
EXEC SP_TRACE_SETEVENT @TraceID, 164, 60, @on; -- IsSystem
EXEC SP_TRACE_SETEVENT @TraceID, 164, 64, @on; -- SessionLoginName
-- Audit Server Scope GDR Event
-- Indicates that a grant, deny, or revoke event for permissions in
-- server scope occurred, such as creating a login.
EXEC SP_TRACE_SETEVENT @TraceID, 170, 1,  @on; -- TextData
EXEC SP_TRACE_SETEVENT @TraceID, 170, 6,  @on; -- NTUserName
EXEC SP_TRACE_SETEVENT @TraceID, 170, 7,  @on; -- NTDomainName
EXEC SP_TRACE_SETEVENT @TraceID, 170, 8,  @on; -- HostName
EXEC SP_TRACE_SETEVENT @TraceID, 170, 9,  @on; -- ClientProcessID
EXEC SP_TRACE_SETEVENT @TraceID, 170, 10, @on; -- ApplicationName
EXEC SP_TRACE_SETEVENT @TraceID, 170, 11, @on; -- LoginName
EXEC SP_TRACE_SETEVENT @TraceID, 170, 12, @on; -- SPID
EXEC SP_TRACE_SETEVENT @TraceID, 170, 13, @on; -- Duration
EXEC SP_TRACE_SETEVENT @TraceID, 170, 14, @on; -- StartTime
EXEC SP_TRACE_SETEVENT @TraceID, 170, 15, @on; -- EndTime
EXEC SP_TRACE_SETEVENT @TraceID, 170, 19, @on; -- Permissions
EXEC SP_TRACE_SETEVENT @TraceID, 170, 21, @on; -- EventSubClass
EXEC SP_TRACE_SETEVENT @TraceID, 170, 23, @on; -- Success (successful use of permissions)
EXEC SP_TRACE_SETEVENT @TraceID, 170, 26, @on; -- ServerName
EXEC SP_TRACE_SETEVENT @TraceID, 170, 28, @on; -- ObjectType
EXEC SP_TRACE_SETEVENT @TraceID, 170, 30, @on; -- State
EXEC SP_TRACE_SETEVENT @TraceID, 170, 31, @on; -- Error
EXEC SP_TRACE_SETEVENT @TraceID, 170, 34, @on; -- ObjectName
EXEC SP_TRACE_SETEVENT @TraceID, 170, 35, @on; -- DatabaseName
EXEC SP_TRACE_SETEVENT @TraceID, 170, 37, @on; -- OwnerName
EXEC SP_TRACE_SETEVENT @TraceID, 170, 38, @on; -- RoleName
EXEC SP_TRACE_SETEVENT @TraceID, 170, 39, @on; -- TargetUserName
EXEC SP_TRACE_SETEVENT @TraceID, 170, 40, @on; -- DBUserName
EXEC SP_TRACE_SETEVENT @TraceID, 170, 41, @on; -- LoginSid
EXEC SP_TRACE_SETEVENT @TraceID, 170, 42, @on; -- TargetLoginName
EXEC SP_TRACE_SETEVENT @TraceID, 170, 43, @on; -- TargetLoginSid
EXEC SP_TRACE_SETEVENT @TraceID, 170, 44, @on; -- ColumnPermissions
EXEC SP_TRACE_SETEVENT @TraceID, 170, 45, @on; -- LinkedServerName
EXEC SP_TRACE_SETEVENT @TraceID, 170, 46, @on; -- ProviderName
EXEC SP_TRACE_SETEVENT @TraceID, 170, 51, @on; -- EventSequence
EXEC SP_TRACE_SETEVENT @TraceID, 170, 59, @on; -- ParentName
EXEC SP_TRACE_SETEVENT @TraceID, 170, 60, @on; -- IsSystem
EXEC SP_TRACE_SETEVENT @TraceID, 170, 64, @on; -- SessionLoginName
-- Audit Server Object GDR Event
-- Indicates that a grant, deny, or revoke event for a schema object,
-- such as a table or function, occurred.
EXEC SP_TRACE_SETEVENT @TraceID, 171, 1,  @on; -- TextData
EXEC SP_TRACE_SETEVENT @TraceID, 171, 6,  @on; -- NTUserName
EXEC SP_TRACE_SETEVENT @TraceID, 171, 7,  @on; -- NTDomainName
EXEC SP_TRACE_SETEVENT @TraceID, 171, 8,  @on; -- HostName
EXEC SP_TRACE_SETEVENT @TraceID, 171, 9,  @on; -- ClientProcessID
EXEC SP_TRACE_SETEVENT @TraceID, 171, 10, @on; -- ApplicationName
EXEC SP_TRACE_SETEVENT @TraceID, 171, 11, @on; -- LoginName
EXEC SP_TRACE_SETEVENT @TraceID, 171, 12, @on; -- SPID
EXEC SP_TRACE_SETEVENT @TraceID, 171, 13, @on; -- Duration
EXEC SP_TRACE_SETEVENT @TraceID, 171, 14, @on; -- StartTime
EXEC SP_TRACE_SETEVENT @TraceID, 171, 15, @on; -- EndTime
EXEC SP_TRACE_SETEVENT @TraceID, 171, 19, @on; -- Permissions
EXEC SP_TRACE_SETEVENT @TraceID, 171, 21, @on; -- EventSubClass
EXEC SP_TRACE_SETEVENT @TraceID, 171, 23, @on; -- Success (successful use of permissions)
EXEC SP_TRACE_SETEVENT @TraceID, 171, 26, @on; -- ServerName
EXEC SP_TRACE_SETEVENT @TraceID, 171, 28, @on; -- ObjectType
EXEC SP_TRACE_SETEVENT @TraceID, 171, 30, @on; -- State
EXEC SP_TRACE_SETEVENT @TraceID, 171, 31, @on; -- Error
EXEC SP_TRACE_SETEVENT @TraceID, 171, 34, @on; -- ObjectName
EXEC SP_TRACE_SETEVENT @TraceID, 171, 35, @on; -- DatabaseName
EXEC SP_TRACE_SETEVENT @TraceID, 171, 37, @on; -- OwnerName
EXEC SP_TRACE_SETEVENT @TraceID, 171, 38, @on; -- RoleName
EXEC SP_TRACE_SETEVENT @TraceID, 171, 39, @on; -- TargetUserName
EXEC SP_TRACE_SETEVENT @TraceID, 171, 40, @on; -- DBUserName
EXEC SP_TRACE_SETEVENT @TraceID, 171, 41, @on; -- LoginSid
EXEC SP_TRACE_SETEVENT @TraceID, 171, 42, @on; -- TargetLoginName
EXEC SP_TRACE_SETEVENT @TraceID, 171, 43, @on; -- TargetLoginSid
EXEC SP_TRACE_SETEVENT @TraceID, 171, 44, @on; -- ColumnPermissions
EXEC SP_TRACE_SETEVENT @TraceID, 171, 45, @on; -- LinkedServerName
EXEC SP_TRACE_SETEVENT @TraceID, 171, 46, @on; -- ProviderName
EXEC SP_TRACE_SETEVENT @TraceID, 171, 51, @on; -- EventSequence
EXEC SP_TRACE_SETEVENT @TraceID, 171, 59, @on; -- ParentName
EXEC SP_TRACE_SETEVENT @TraceID, 171, 60, @on; -- IsSystem
EXEC SP_TRACE_SETEVENT @TraceID, 171, 64, @on; -- SessionLoginName
-- Audit Database Object GDR Event
-- Indicates that a grant, deny, or revoke event for database
-- objects, such as assemblies and schemas, occurred.
EXEC SP_TRACE_SETEVENT @TraceID, 172, 1,  @on; -- TextData
EXEC SP_TRACE_SETEVENT @TraceID, 172, 6,  @on; -- NTUserName
EXEC SP_TRACE_SETEVENT @TraceID, 172, 7,  @on; -- NTDomainName
EXEC SP_TRACE_SETEVENT @TraceID, 172, 8,  @on; -- HostName
EXEC SP_TRACE_SETEVENT @TraceID, 172, 9,  @on; -- ClientProcessID
EXEC SP_TRACE_SETEVENT @TraceID, 172, 10, @on; -- ApplicationName
EXEC SP_TRACE_SETEVENT @TraceID, 172, 11, @on; -- LoginName
EXEC SP_TRACE_SETEVENT @TraceID, 172, 12, @on; -- SPID
EXEC SP_TRACE_SETEVENT @TraceID, 172, 13, @on; -- Duration
EXEC SP_TRACE_SETEVENT @TraceID, 172, 14, @on; -- StartTime
EXEC SP_TRACE_SETEVENT @TraceID, 172, 15, @on; -- EndTime
EXEC SP_TRACE_SETEVENT @TraceID, 172, 19, @on; -- Permissions
EXEC SP_TRACE_SETEVENT @TraceID, 172, 21, @on; -- EventSubClass
EXEC SP_TRACE_SETEVENT @TraceID, 172, 23, @on; -- Success (successful use of permissions)
EXEC SP_TRACE_SETEVENT @TraceID, 172, 26, @on; -- ServerName
EXEC SP_TRACE_SETEVENT @TraceID, 172, 28, @on; -- ObjectType
EXEC SP_TRACE_SETEVENT @TraceID, 172, 30, @on; -- State
EXEC SP_TRACE_SETEVENT @TraceID, 172, 31, @on; -- Error
EXEC SP_TRACE_SETEVENT @TraceID, 172, 34, @on; -- ObjectName
EXEC SP_TRACE_SETEVENT @TraceID, 172, 35, @on; -- DatabaseName
EXEC SP_TRACE_SETEVENT @TraceID, 172, 37, @on; -- OwnerName
EXEC SP_TRACE_SETEVENT @TraceID, 172, 38, @on; -- RoleName
EXEC SP_TRACE_SETEVENT @TraceID, 172, 39, @on; -- TargetUserName
EXEC SP_TRACE_SETEVENT @TraceID, 172, 40, @on; -- DBUserName
EXEC SP_TRACE_SETEVENT @TraceID, 172, 41, @on; -- LoginSid
EXEC SP_TRACE_SETEVENT @TraceID, 172, 42, @on; -- TargetLoginName
EXEC SP_TRACE_SETEVENT @TraceID, 172, 43, @on; -- TargetLoginSid
EXEC SP_TRACE_SETEVENT @TraceID, 172, 44, @on; -- ColumnPermissions
EXEC SP_TRACE_SETEVENT @TraceID, 172, 45, @on; -- LinkedServerName
EXEC SP_TRACE_SETEVENT @TraceID, 172, 46, @on; -- ProviderName
EXEC SP_TRACE_SETEVENT @TraceID, 172, 51, @on; -- EventSequence
EXEC SP_TRACE_SETEVENT @TraceID, 172, 59, @on; -- ParentName
EXEC SP_TRACE_SETEVENT @TraceID, 172, 60, @on; -- IsSystem
EXEC SP_TRACE_SETEVENT @TraceID, 172, 64, @on; -- SessionLoginName
-- Audit Server Operation Event
-- Occurs when Security Audit operations such as altering settings,
-- resources, external access, or authorization are used.
EXEC SP_TRACE_SETEVENT @TraceID, 173, 1,  @on; -- TextData
EXEC SP_TRACE_SETEVENT @TraceID, 173, 6,  @on; -- NTUserName
EXEC SP_TRACE_SETEVENT @TraceID, 173, 7,  @on; -- NTDomainName
EXEC SP_TRACE_SETEVENT @TraceID, 173, 8,  @on; -- HostName
EXEC SP_TRACE_SETEVENT @TraceID, 173, 9,  @on; -- ClientProcessID
EXEC SP_TRACE_SETEVENT @TraceID, 173, 10, @on; -- ApplicationName
EXEC SP_TRACE_SETEVENT @TraceID, 173, 11, @on; -- LoginName
EXEC SP_TRACE_SETEVENT @TraceID, 173, 12, @on; -- SPID
EXEC SP_TRACE_SETEVENT @TraceID, 173, 13, @on; -- Duration
EXEC SP_TRACE_SETEVENT @TraceID, 173, 14, @on; -- StartTime
EXEC SP_TRACE_SETEVENT @TraceID, 173, 15, @on; -- EndTime
EXEC SP_TRACE_SETEVENT @TraceID, 173, 19, @on; -- Permissions
EXEC SP_TRACE_SETEVENT @TraceID, 173, 21, @on; -- EventSubClass
EXEC SP_TRACE_SETEVENT @TraceID, 173, 23, @on; -- Success (successful use of permissions)
EXEC SP_TRACE_SETEVENT @TraceID, 173, 26, @on; -- ServerName
EXEC SP_TRACE_SETEVENT @TraceID, 173, 28, @on; -- ObjectType
EXEC SP_TRACE_SETEVENT @TraceID, 173, 30, @on; -- State
EXEC SP_TRACE_SETEVENT @TraceID, 173, 31, @on; -- Error
EXEC SP_TRACE_SETEVENT @TraceID, 173, 34, @on; -- ObjectName
EXEC SP_TRACE_SETEVENT @TraceID, 173, 35, @on; -- DatabaseName
EXEC SP_TRACE_SETEVENT @TraceID, 173, 37, @on; -- OwnerName
EXEC SP_TRACE_SETEVENT @TraceID, 173, 38, @on; -- RoleName
EXEC SP_TRACE_SETEVENT @TraceID, 173, 39, @on; -- TargetUserName
EXEC SP_TRACE_SETEVENT @TraceID, 173, 40, @on; -- DBUserName
EXEC SP_TRACE_SETEVENT @TraceID, 173, 41, @on; -- LoginSid
EXEC SP_TRACE_SETEVENT @TraceID, 173, 42, @on; -- TargetLoginName
EXEC SP_TRACE_SETEVENT @TraceID, 173, 43, @on; -- TargetLoginSid
EXEC SP_TRACE_SETEVENT @TraceID, 173, 44, @on; -- ColumnPermissions
EXEC SP_TRACE_SETEVENT @TraceID, 173, 45, @on; -- LinkedServerName
EXEC SP_TRACE_SETEVENT @TraceID, 173, 46, @on; -- ProviderName
EXEC SP_TRACE_SETEVENT @TraceID, 173, 51, @on; -- EventSequence
EXEC SP_TRACE_SETEVENT @TraceID, 173, 59, @on; -- ParentName
EXEC SP_TRACE_SETEVENT @TraceID, 173, 60, @on; -- IsSystem
EXEC SP_TRACE_SETEVENT @TraceID, 173, 64, @on; -- SessionLoginName
-- Audit Server Alter Trace Event
-- Occurs when a statement checks for the ALTER TRACE permission.
EXEC SP_TRACE_SETEVENT @TraceID, 175, 1,  @on; -- TextData
EXEC SP_TRACE_SETEVENT @TraceID, 175, 6,  @on; -- NTUserName
EXEC SP_TRACE_SETEVENT @TraceID, 175, 7,  @on; -- NTDomainName
EXEC SP_TRACE_SETEVENT @TraceID, 175, 8,  @on; -- HostName
EXEC SP_TRACE_SETEVENT @TraceID, 175, 9,  @on; -- ClientProcessID
EXEC SP_TRACE_SETEVENT @TraceID, 175, 10, @on; -- ApplicationName
EXEC SP_TRACE_SETEVENT @TraceID, 175, 11, @on; -- LoginName
EXEC SP_TRACE_SETEVENT @TraceID, 175, 12, @on; -- SPID
EXEC SP_TRACE_SETEVENT @TraceID, 175, 13, @on; -- Duration
EXEC SP_TRACE_SETEVENT @TraceID, 175, 14, @on; -- StartTime
EXEC SP_TRACE_SETEVENT @TraceID, 175, 15, @on; -- EndTime
EXEC SP_TRACE_SETEVENT @TraceID, 175, 19, @on; -- Permissions
EXEC SP_TRACE_SETEVENT @TraceID, 175, 21, @on; -- EventSubClass
EXEC SP_TRACE_SETEVENT @TraceID, 175, 23, @on; -- Success (successful use of permissions)
EXEC SP_TRACE_SETEVENT @TraceID, 175, 26, @on; -- ServerName
EXEC SP_TRACE_SETEVENT @TraceID, 175, 28, @on; -- ObjectType
EXEC SP_TRACE_SETEVENT @TraceID, 175, 30, @on; -- State
EXEC SP_TRACE_SETEVENT @TraceID, 175, 31, @on; -- Error
EXEC SP_TRACE_SETEVENT @TraceID, 175, 34, @on; -- ObjectName
EXEC SP_TRACE_SETEVENT @TraceID, 175, 35, @on; -- DatabaseName
EXEC SP_TRACE_SETEVENT @TraceID, 175, 37, @on; -- OwnerName
EXEC SP_TRACE_SETEVENT @TraceID, 175, 38, @on; -- RoleName
EXEC SP_TRACE_SETEVENT @TraceID, 175, 39, @on; -- TargetUserName
EXEC SP_TRACE_SETEVENT @TraceID, 175, 40, @on; -- DBUserName
EXEC SP_TRACE_SETEVENT @TraceID, 175, 41, @on; -- LoginSid
EXEC SP_TRACE_SETEVENT @TraceID, 175, 42, @on; -- TargetLoginName
EXEC SP_TRACE_SETEVENT @TraceID, 175, 43, @on; -- TargetLoginSid
EXEC SP_TRACE_SETEVENT @TraceID, 175, 44, @on; -- ColumnPermissions
EXEC SP_TRACE_SETEVENT @TraceID, 175, 45, @on; -- LinkedServerName
EXEC SP_TRACE_SETEVENT @TraceID, 175, 46, @on; -- ProviderName
EXEC SP_TRACE_SETEVENT @TraceID, 175, 51, @on; -- EventSequence
EXEC SP_TRACE_SETEVENT @TraceID, 175, 59, @on; -- ParentName
EXEC SP_TRACE_SETEVENT @TraceID, 175, 60, @on; -- IsSystem
EXEC SP_TRACE_SETEVENT @TraceID, 175, 64, @on; -- SessionLoginName
-- Audit Server Object Management Event
-- Occurs when server objects are created, altered, or dropped.
EXEC SP_TRACE_SETEVENT @TraceID, 176, 1,  @on; -- TextData
EXEC SP_TRACE_SETEVENT @TraceID, 176, 6,  @on; -- NTUserName
EXEC SP_TRACE_SETEVENT @TraceID, 176, 7,  @on; -- NTDomainName
EXEC SP_TRACE_SETEVENT @TraceID, 176, 8,  @on; -- HostName
EXEC SP_TRACE_SETEVENT @TraceID, 176, 9,  @on; -- ClientProcessID
EXEC SP_TRACE_SETEVENT @TraceID, 176, 10, @on; -- ApplicationName
EXEC SP_TRACE_SETEVENT @TraceID, 176, 11, @on; -- LoginName
EXEC SP_TRACE_SETEVENT @TraceID, 176, 12, @on; -- SPID
EXEC SP_TRACE_SETEVENT @TraceID, 176, 13, @on; -- Duration
EXEC SP_TRACE_SETEVENT @TraceID, 176, 14, @on; -- StartTime
EXEC SP_TRACE_SETEVENT @TraceID, 176, 15, @on; -- EndTime
EXEC SP_TRACE_SETEVENT @TraceID, 176, 19, @on; -- Permissions
EXEC SP_TRACE_SETEVENT @TraceID, 176, 21, @on; -- EventSubClass
EXEC SP_TRACE_SETEVENT @TraceID, 176, 23, @on; -- Success (successful use of permissions)
EXEC SP_TRACE_SETEVENT @TraceID, 176, 26, @on; -- ServerName
EXEC SP_TRACE_SETEVENT @TraceID, 176, 28, @on; -- ObjectType
EXEC SP_TRACE_SETEVENT @TraceID, 176, 30, @on; -- State
EXEC SP_TRACE_SETEVENT @TraceID, 176, 31, @on; -- Error
EXEC SP_TRACE_SETEVENT @TraceID, 176, 34, @on; -- ObjectName
EXEC SP_TRACE_SETEVENT @TraceID, 176, 35, @on; -- DatabaseName
EXEC SP_TRACE_SETEVENT @TraceID, 176, 37, @on; -- OwnerName
EXEC SP_TRACE_SETEVENT @TraceID, 176, 38, @on; -- RoleName
EXEC SP_TRACE_SETEVENT @TraceID, 176, 39, @on; -- TargetUserName
EXEC SP_TRACE_SETEVENT @TraceID, 176, 40, @on; -- DBUserName
EXEC SP_TRACE_SETEVENT @TraceID, 176, 41, @on; -- LoginSid
EXEC SP_TRACE_SETEVENT @TraceID, 176, 42, @on; -- TargetLoginName
EXEC SP_TRACE_SETEVENT @TraceID, 176, 43, @on; -- TargetLoginSid
EXEC SP_TRACE_SETEVENT @TraceID, 176, 44, @on; -- ColumnPermissions
EXEC SP_TRACE_SETEVENT @TraceID, 176, 45, @on; -- LinkedServerName
EXEC SP_TRACE_SETEVENT @TraceID, 176, 46, @on; -- ProviderName
EXEC SP_TRACE_SETEVENT @TraceID, 176, 51, @on; -- EventSequence
EXEC SP_TRACE_SETEVENT @TraceID, 176, 59, @on; -- ParentName
EXEC SP_TRACE_SETEVENT @TraceID, 176, 60, @on; -- IsSystem
EXEC SP_TRACE_SETEVENT @TraceID, 176, 64, @on; -- SessionLoginName
-- Audit Server Principal Management Event
-- Occurs when server principals are created, altered, or dropped.
EXEC SP_TRACE_SETEVENT @TraceID, 177, 1,  @on; -- TextData
EXEC SP_TRACE_SETEVENT @TraceID, 177, 6,  @on; -- NTUserName
EXEC SP_TRACE_SETEVENT @TraceID, 177, 7,  @on; -- NTDomainName
EXEC SP_TRACE_SETEVENT @TraceID, 177, 8,  @on; -- HostName
EXEC SP_TRACE_SETEVENT @TraceID, 177, 9,  @on; -- ClientProcessID
EXEC SP_TRACE_SETEVENT @TraceID, 177, 10, @on; -- ApplicationName
EXEC SP_TRACE_SETEVENT @TraceID, 177, 11, @on; -- LoginName
EXEC SP_TRACE_SETEVENT @TraceID, 177, 12, @on; -- SPID
EXEC SP_TRACE_SETEVENT @TraceID, 177, 13, @on; -- Duration
EXEC SP_TRACE_SETEVENT @TraceID, 177, 14, @on; -- StartTime
EXEC SP_TRACE_SETEVENT @TraceID, 177, 15, @on; -- EndTime
EXEC SP_TRACE_SETEVENT @TraceID, 177, 19, @on; -- Permissions
EXEC SP_TRACE_SETEVENT @TraceID, 177, 21, @on; -- EventSubClass
EXEC SP_TRACE_SETEVENT @TraceID, 177, 23, @on; -- Success (successful use of permissions)
EXEC SP_TRACE_SETEVENT @TraceID, 177, 26, @on; -- ServerName
EXEC SP_TRACE_SETEVENT @TraceID, 177, 28, @on; -- ObjectType
EXEC SP_TRACE_SETEVENT @TraceID, 177, 30, @on; -- State
EXEC SP_TRACE_SETEVENT @TraceID, 177, 31, @on; -- Error
EXEC SP_TRACE_SETEVENT @TraceID, 177, 34, @on; -- ObjectName
EXEC SP_TRACE_SETEVENT @TraceID, 177, 35, @on; -- DatabaseName
EXEC SP_TRACE_SETEVENT @TraceID, 177, 37, @on; -- OwnerName
EXEC SP_TRACE_SETEVENT @TraceID, 177, 38, @on; -- RoleName
EXEC SP_TRACE_SETEVENT @TraceID, 177, 39, @on; -- TargetUserName
EXEC SP_TRACE_SETEVENT @TraceID, 177, 40, @on; -- DBUserName
EXEC SP_TRACE_SETEVENT @TraceID, 177, 41, @on; -- LoginSid
EXEC SP_TRACE_SETEVENT @TraceID, 177, 42, @on; -- TargetLoginName
EXEC SP_TRACE_SETEVENT @TraceID, 177, 43, @on; -- TargetLoginSid
EXEC SP_TRACE_SETEVENT @TraceID, 177, 44, @on; -- ColumnPermissions
EXEC SP_TRACE_SETEVENT @TraceID, 177, 45, @on; -- LinkedServerName
EXEC SP_TRACE_SETEVENT @TraceID, 177, 46, @on; -- ProviderName
EXEC SP_TRACE_SETEVENT @TraceID, 177, 51, @on; -- EventSequence
EXEC SP_TRACE_SETEVENT @TraceID, 177, 59, @on; -- ParentName
EXEC SP_TRACE_SETEVENT @TraceID, 177, 60, @on; -- IsSystem
EXEC SP_TRACE_SETEVENT @TraceID, 177, 64, @on; -- SessionLoginName
-- Audit Database Operation Event
-- Occurs when database operations occur, such as checkpoint or
-- subscribe query notification.
EXEC SP_TRACE_SETEVENT @TraceID, 178, 1,  @on; -- TextData
EXEC SP_TRACE_SETEVENT @TraceID, 178, 6,  @on; -- NTUserName
EXEC SP_TRACE_SETEVENT @TraceID, 178, 7,  @on; -- NTDomainName
EXEC SP_TRACE_SETEVENT @TraceID, 178, 8,  @on; -- HostName
EXEC SP_TRACE_SETEVENT @TraceID, 178, 9,  @on; -- ClientProcessID
EXEC SP_TRACE_SETEVENT @TraceID, 178, 10, @on; -- ApplicationName
EXEC SP_TRACE_SETEVENT @TraceID, 178, 11, @on; -- LoginName
EXEC SP_TRACE_SETEVENT @TraceID, 178, 12, @on; -- SPID
EXEC SP_TRACE_SETEVENT @TraceID, 178, 13, @on; -- Duration
EXEC SP_TRACE_SETEVENT @TraceID, 178, 14, @on; -- StartTime
EXEC SP_TRACE_SETEVENT @TraceID, 178, 15, @on; -- EndTime
EXEC SP_TRACE_SETEVENT @TraceID, 178, 19, @on; -- Permissions
EXEC SP_TRACE_SETEVENT @TraceID, 178, 21, @on; -- EventSubClass
EXEC SP_TRACE_SETEVENT @TraceID, 178, 23, @on; -- Success (successful use of permissions)
EXEC SP_TRACE_SETEVENT @TraceID, 178, 26, @on; -- ServerName
EXEC SP_TRACE_SETEVENT @TraceID, 178, 28, @on; -- ObjectType
EXEC SP_TRACE_SETEVENT @TraceID, 178, 30, @on; -- State
EXEC SP_TRACE_SETEVENT @TraceID, 178, 31, @on; -- Error
EXEC SP_TRACE_SETEVENT @TraceID, 178, 34, @on; -- ObjectName
EXEC SP_TRACE_SETEVENT @TraceID, 178, 35, @on; -- DatabaseName
EXEC SP_TRACE_SETEVENT @TraceID, 178, 37, @on; -- OwnerName
EXEC SP_TRACE_SETEVENT @TraceID, 178, 38, @on; -- RoleName
EXEC SP_TRACE_SETEVENT @TraceID, 178, 39, @on; -- TargetUserName
EXEC SP_TRACE_SETEVENT @TraceID, 178, 40, @on; -- DBUserName
EXEC SP_TRACE_SETEVENT @TraceID, 178, 41, @on; -- LoginSid
EXEC SP_TRACE_SETEVENT @TraceID, 178, 42, @on; -- TargetLoginName
EXEC SP_TRACE_SETEVENT @TraceID, 178, 43, @on; -- TargetLoginSid
EXEC SP_TRACE_SETEVENT @TraceID, 178, 44, @on; -- ColumnPermissions
EXEC SP_TRACE_SETEVENT @TraceID, 178, 45, @on; -- LinkedServerName
EXEC SP_TRACE_SETEVENT @TraceID, 178, 46, @on; -- ProviderName
EXEC SP_TRACE_SETEVENT @TraceID, 178, 51, @on; -- EventSequence
EXEC SP_TRACE_SETEVENT @TraceID, 178, 59, @on; -- ParentName
EXEC SP_TRACE_SETEVENT @TraceID, 178, 60, @on; -- IsSystem
EXEC SP_TRACE_SETEVENT @TraceID, 178, 64, @on; -- SessionLoginName
-- Audit Database Object Access Event
-- Occurs when database objects, such as schemas, are accessed.
EXEC SP_TRACE_SETEVENT @TraceID, 180, 1,  @on; -- TextData
EXEC SP_TRACE_SETEVENT @TraceID, 180, 6,  @on; -- NTUserName
EXEC SP_TRACE_SETEVENT @TraceID, 180, 7,  @on; -- NTDomainName
EXEC SP_TRACE_SETEVENT @TraceID, 180, 8,  @on; -- HostName
EXEC SP_TRACE_SETEVENT @TraceID, 180, 9,  @on; -- ClientProcessID
EXEC SP_TRACE_SETEVENT @TraceID, 180, 10, @on; -- ApplicationName
EXEC SP_TRACE_SETEVENT @TraceID, 180, 11, @on; -- LoginName
EXEC SP_TRACE_SETEVENT @TraceID, 180, 12, @on; -- SPID
EXEC SP_TRACE_SETEVENT @TraceID, 180, 13, @on; -- Duration
EXEC SP_TRACE_SETEVENT @TraceID, 180, 14, @on; -- StartTime
EXEC SP_TRACE_SETEVENT @TraceID, 180, 15, @on; -- EndTime
EXEC SP_TRACE_SETEVENT @TraceID, 180, 19, @on; -- Permissions
EXEC SP_TRACE_SETEVENT @TraceID, 180, 21, @on; -- EventSubClass
EXEC SP_TRACE_SETEVENT @TraceID, 180, 23, @on; -- Success (successful use of permissions)
EXEC SP_TRACE_SETEVENT @TraceID, 180, 26, @on; -- ServerName
EXEC SP_TRACE_SETEVENT @TraceID, 180, 28, @on; -- ObjectType
EXEC SP_TRACE_SETEVENT @TraceID, 180, 30, @on; -- State
EXEC SP_TRACE_SETEVENT @TraceID, 180, 31, @on; -- Error
EXEC SP_TRACE_SETEVENT @TraceID, 180, 34, @on; -- ObjectName
EXEC SP_TRACE_SETEVENT @TraceID, 180, 35, @on; -- DatabaseName
EXEC SP_TRACE_SETEVENT @TraceID, 180, 37, @on; -- OwnerName
EXEC SP_TRACE_SETEVENT @TraceID, 180, 38, @on; -- RoleName
EXEC SP_TRACE_SETEVENT @TraceID, 180, 39, @on; -- TargetUserName
EXEC SP_TRACE_SETEVENT @TraceID, 180, 40, @on; -- DBUserName
EXEC SP_TRACE_SETEVENT @TraceID, 180, 41, @on; -- LoginSid
EXEC SP_TRACE_SETEVENT @TraceID, 180, 42, @on; -- TargetLoginName
EXEC SP_TRACE_SETEVENT @TraceID, 180, 43, @on; -- TargetLoginSid
EXEC SP_TRACE_SETEVENT @TraceID, 180, 44, @on; -- ColumnPermissions
EXEC SP_TRACE_SETEVENT @TraceID, 180, 45, @on; -- LinkedServerName
EXEC SP_TRACE_SETEVENT @TraceID, 180, 46, @on; -- ProviderName
EXEC SP_TRACE_SETEVENT @TraceID, 180, 51, @on; -- EventSequence
EXEC SP_TRACE_SETEVENT @TraceID, 180, 59, @on; -- ParentName
EXEC SP_TRACE_SETEVENT @TraceID, 180, 60, @on; -- IsSystem
EXEC SP_TRACE_SETEVENT @TraceID, 180, 64, @on; -- SessionLoginName


-- Set the trace status to start.
EXEC SP_TRACE_SETSTATUS @TraceID, 1;

-- Display trace ID for future reference.
SELECT @TraceID AS TraceID;

GOTO Finish;
Error:
SELECT @rc AS ErrorCode;
Finish:
GO

EXEC SP_PROCOPTION 'STIG_Trace', 'startup', 'true';
GO

--       Note:       Replace 'D:<path>\<filename>' with the path and file name to your audit file.
--                   Adjust the other parameters of SP_TRACE_CREATE to suit your system's circumstances.
