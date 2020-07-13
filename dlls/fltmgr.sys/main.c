/*
 * fltmgr.sys
 *
 * Copyright 2015 Austin English
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

#include <stdarg.h>

#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "windef.h"
#include "winbase.h"
#include "winternl.h"
#include "ddk/fltkernel.h"

#include "wine/debug.h"

WINE_DEFAULT_DEBUG_CHANNEL(fltmgr);

static inline LPCSTR debugstr_us( const UNICODE_STRING *us )
{
    if (!us) return "<null>";
    return debugstr_wn( us->Buffer, us->Length / sizeof(WCHAR) );
}

NTSTATUS WINAPI DriverEntry( DRIVER_OBJECT *driver, UNICODE_STRING *path )
{
    TRACE( "(%p, %s)\n", driver, debugstr_w(path->Buffer) );

    return STATUS_SUCCESS;
}

void WINAPI FltInitializePushLock( EX_PUSH_LOCK *lock )
{
    FIXME( "(%p): stub\n", lock );
}

void WINAPI FltDeletePushLock( EX_PUSH_LOCK *lock )
{
    FIXME( "(%p): stub\n", lock );
}

void WINAPI FltAcquirePushLockExclusive( EX_PUSH_LOCK *lock )
{
    FIXME( "(%p): stub\n", lock );
}

void WINAPI FltReleasePushLock( EX_PUSH_LOCK *lock )
{
    FIXME( "(%p): stub\n", lock );
}

NTSTATUS WINAPI FltRegisterFilter( PDRIVER_OBJECT driver, const FLT_REGISTRATION *reg, PFLT_FILTER *filter )
{
    FIXME( "(%p,%p,%p): stub\n", driver, reg, filter );

    if(filter)
        *filter = UlongToHandle(0xdeadbeaf);

    return STATUS_SUCCESS;
}

NTSTATUS WINAPI FltStartFiltering( PFLT_FILTER filter )
{
    FIXME( "(%p): stub\n", filter );

    return STATUS_SUCCESS;
}

void WINAPI FltUnregisterFilter( PFLT_FILTER filter )
{
    FIXME( "(%p): stub\n", filter );
}

static POBJECT_TYPE IoFileObjectType(void)
{
    HMODULE ntoskrnl_mod = GetModuleHandleA("ntoskrnl.exe");

    return *((POBJECT_TYPE *)GetProcAddress(ntoskrnl_mod, "IoFileObjectType"));
}

static NTSTATUS p_ObOpenObjectByPointer( void *obj, ULONG attr, ACCESS_STATE *access_state,
                                       ACCESS_MASK access, POBJECT_TYPE type,
                                       KPROCESSOR_MODE mode, HANDLE *handle )
{
    HMODULE ntoskrnl_mod = GetModuleHandleA("ntoskrnl.exe");

    NTSTATUS WINAPI (*func)(void*,ULONG,ACCESS_STATE*,ACCESS_MASK,POBJECT_TYPE,KPROCESSOR_MODE,HANDLE)
        = GetProcAddress(ntoskrnl_mod, "ObOpenObjectByPointer");

    return func(obj, attr, access_state, access, type, mode, handle);
}

NTSTATUS WINAPI FltGetFileNameInformationUnsafe( PFILE_OBJECT file_object, PFLT_INSTANCE instance, FLT_FILE_NAME_OPTIONS options, PFLT_FILE_NAME_INFORMATION *info)
{
    NTSTATUS stat;
    HANDLE file;
    DWORD path_length;
    WCHAR *path_buffer;
    PFLT_FILE_NAME_INFORMATION ret;

    TRACE("%p %p %x %p\n", file_object, instance, options, info);

    if (instance)
        FIXME("ignoring instance.\n");

    if ((stat = p_ObOpenObjectByPointer(file_object, OBJ_KERNEL_HANDLE, NULL, 0, IoFileObjectType(), KernelMode, &file)))
    {
        ERR("Failed to open file, stat = %x\n", stat);
        return stat;
    }

    if (!(path_length = GetFinalPathNameByHandleW(file, NULL, 0, VOLUME_NAME_NT)))
    {
        CloseHandle(file);
        ERR("Failed to get path %x\n", GetLastError());
        return STATUS_UNSUCCESSFUL;
    }

    /* terminator */
    path_length++;

    path_buffer = HeapAlloc( GetProcessHeap(), HEAP_ZERO_MEMORY, path_length * sizeof(WCHAR));
    if (!(GetFinalPathNameByHandleW(file, path_buffer, path_length, VOLUME_NAME_NT)))
    {
        CloseHandle(file);
        HeapFree(GetProcessHeap(), 0, path_buffer);
        ERR("Failed to get path %x\n", GetLastError());
        return STATUS_UNSUCCESSFUL;
    }

    ret = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*ret));
    ret->Size = sizeof(*ret);
    ret->Format = options;
    RtlInitUnicodeString(&ret->Name, path_buffer);

    *info = ret;

    CloseHandle(file);
    return STATUS_SUCCESS;
}

void WINAPI FltReleaseFileNameInformation(PFLT_FILE_NAME_INFORMATION info)
{
    TRACE("%p\n", info);

    if (info)
    {
        RtlFreeUnicodeString(&info->Name);
        HeapFree( GetProcessHeap(), 0, info );
    }
}

void* WINAPI FltGetRoutineAddress(LPCSTR name)
{
    HMODULE mod = GetModuleHandleW(L"fltmgr.sys");
    void *func;

    func = GetProcAddress(mod, name);
    if (func)
        TRACE( "%s -> %p\n", debugstr_a(name), func );
    else
        FIXME( "%s not found\n", debugstr_a(name) );

    return func;
}
