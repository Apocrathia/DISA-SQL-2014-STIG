
--  Example of triggers for tracing Insert-Update-Delete actions on tables.
--  In these examples, T is the name of the table being tracked, and 90 is the event ID 
--  used for this purpose.


BEGIN TRY DROP TRIGGER T_Insert_Audit_Trigger END TRY BEGIN CATCH END CATCH;
GO
CREATE TRIGGER T_Insert_Audit_Trigger ON T
FOR INSERT
AS BEGIN;
    DECLARE @K int = (SELECT count(*) FROM inserted);
    DECLARE @userinfo nvarchar(128) = cast(@K as nvarchar(12)) + ' row(s) inserted into T'
    EXECUTE master.sys.sp_trace_generateevent 
        @eventid = 90,
        @userinfo = @userinfo,
        @userdata = null
END;
GO


BEGIN TRY DROP TRIGGER T_Update_Audit_Trigger END TRY BEGIN CATCH END CATCH;
GO
CREATE TRIGGER T_Update_Audit_Trigger ON T
FOR UPDATE
AS BEGIN;
    DECLARE @K int = (SELECT count(*) FROM inserted);
    DECLARE @userinfo nvarchar(128) = cast(@K as nvarchar(12)) + ' row(s) updated in T'
    EXECUTE master.sys.sp_trace_generateevent 
        @eventid = 90,
        @userinfo = @userinfo,
        @userdata = null
END;
GO


BEGIN TRY DROP TRIGGER T_Delete_Audit_Trigger END TRY BEGIN CATCH END CATCH;
GO
CREATE TRIGGER T_Delete_Audit_Trigger ON T
FOR DELETE
AS BEGIN;
    DECLARE @K int = (SELECT count(*) FROM deleted);
    DECLARE @userinfo nvarchar(128) = cast(@K as nvarchar(12)) + ' row(s) deleted from T'
    EXECUTE master.sys.sp_trace_generateevent 
        @eventid = 90,
        @userinfo = @userinfo,
        @userdata = null
END;
GO
