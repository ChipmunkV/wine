#include <stdarg.h>

#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "windef.h"
#include "winternl.h"
#include "ddk/wdm.h"
#include "ddk/ntifs.h"

#include "wine/debug.h"

#include "ntoskrnl_private.h"

WINE_DEFAULT_DEBUG_CHANNEL(ntoskrnl);

static HMODULE ntdll_mod;

static NTSTATUS (WINAPI *pNtCreateFile)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK, PLARGE_INTEGER, ULONG, ULONG, ULONG, ULONG, PVOID, ULONG);

static void resolve_funcs(void)
{
    if (!ntdll_mod)
    {
        ntdll_mod = GetModuleHandleA("ntdll");
        if (!pNtCreateFile)
            pNtCreateFile = (void*) GetProcAddress(ntdll_mod, "NtCreateFile");
    }
}

NTSTATUS WINAPI NtCreateFile( PHANDLE handle, ACCESS_MASK access, POBJECT_ATTRIBUTES attr,
                              PIO_STATUS_BLOCK io, PLARGE_INTEGER alloc_size,
                              ULONG attributes, ULONG sharing, ULONG disposition,
                              ULONG options, PVOID ea_buffer, ULONG ea_length )
{
    resolve_funcs();

    TRACE("\n");

    if (attr)
        attr->Attributes |= OBJ_FROM_KERNEL;

    return pNtCreateFile(handle, access, attr, io, alloc_size, attributes, sharing,
                         disposition, options, ea_buffer, ea_length);
}