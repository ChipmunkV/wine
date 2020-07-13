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
static NTSTATUS (WINAPI *pNtAllocateVirtualMemory)(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);
static NTSTATUS (WINAPI *pNtFreeVirtualMemory)(HANDLE, PVOID*, PSIZE_T, ULONG);
static NTSTATUS (WINAPI *pNtProtectVirtualMemory)(HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);
static NTSTATUS (WINAPI *pNtQueryVirtualMemory)(HANDLE, LPCVOID, MEMORY_INFORMATION_CLASS, PVOID, SIZE_T, PSIZE_T);

static void resolve_funcs(void)
{
    if (!ntdll_mod)
    {
        ntdll_mod = GetModuleHandleA("ntdll");
        if (!pNtAllocateVirtualMemory)
            pNtAllocateVirtualMemory = (void*) GetProcAddress(ntdll_mod, "NtAllocateVirtualMemory");
        if (!pNtFreeVirtualMemory)
            pNtFreeVirtualMemory = (void*) GetProcAddress(ntdll_mod, "NtFreeVirtualMemory");
        if (!pNtProtectVirtualMemory)
            pNtProtectVirtualMemory = (void*) GetProcAddress(ntdll_mod, "NtProtectVirtualMemory");
        if (!pNtQueryVirtualMemory)
            pNtQueryVirtualMemory = (void*) GetProcAddress(ntdll_mod, "NtQueryVirtualMemory");
    }
}

/* returns TRUE if swapped */
static BOOL get_real_process(HANDLE *process)
{
    if (*process == GetCurrentProcess() && KeGetCurrentThread()->process->info.UniqueProcessId != GetCurrentProcessId())
    {
        if (!(ObOpenObjectByPointer(KeGetCurrentThread()->process, OBJ_KERNEL_HANDLE, NULL, PROCESS_VM_OPERATION|PROCESS_QUERY_INFORMATION, PsProcessType, KernelMode, process)))
            return TRUE;
    }
    return FALSE;
}

NTSTATUS WINAPI NtAllocateVirtualMemory( HANDLE process, PVOID *ret, ULONG_PTR zero_bits,
                                         SIZE_T *size_ptr, ULONG type, ULONG protect )
{
    NTSTATUS stat;
    BOOL swapped;

    TRACE("%p %p %08lx %x %08x\n", process, *ret, *size_ptr, type, protect);

    resolve_funcs();

    swapped = get_real_process(&process);
    if (process == GetCurrentProcess())
    {
        ERR("Failed to get real process\n");
        return STATUS_INVALID_PARAMETER;
    }

    stat = pNtAllocateVirtualMemory(process, ret, zero_bits, size_ptr, type, protect);

    if (swapped)
        CloseHandle(process);
    return stat;
}

NTSTATUS WINAPI NtFreeVirtualMemory( HANDLE process, PVOID *addr_ptr, SIZE_T *size_ptr, ULONG type)
{
    NTSTATUS stat;
    BOOL swapped;

    TRACE("%p %p %08lx %x\n", process, *addr_ptr, *size_ptr, type);

    resolve_funcs();

    swapped = get_real_process(&process);
    if (process == GetCurrentProcess())
    {
        ERR("Failed to get real process\n");
        return STATUS_INVALID_PARAMETER;
    }

    stat = pNtFreeVirtualMemory(process, addr_ptr, size_ptr, type);

    if (swapped)
        CloseHandle(process);
    return stat;
}

/* NtProtectVirtualMemory isn't exported from ntoskrnl */
NTSTATUS WINAPI ZwProtectVirtualMemory( HANDLE process, PVOID *addr_ptr, SIZE_T *size_ptr, ULONG new_prot, ULONG *old_prot )
{
    NTSTATUS stat;
    BOOL swapped;

    TRACE("%p %p %08lx %x %p\n", process, *addr_ptr, *size_ptr, new_prot, old_prot);

    resolve_funcs();

    swapped = get_real_process(&process);
    if (process == GetCurrentProcess())
    {
        ERR("Failed to get real process\n");
        return STATUS_INVALID_PARAMETER;
    }

    stat = pNtProtectVirtualMemory(process, addr_ptr, size_ptr, new_prot, old_prot);

    if (swapped)
        CloseHandle(process);
    return stat;
}

NTSTATUS WINAPI NtQueryVirtualMemory( HANDLE process, LPCVOID addr, MEMORY_INFORMATION_CLASS info_class, PVOID buffer, SIZE_T len, SIZE_T *res_len )
{
    NTSTATUS stat;
    BOOL swapped;

    TRACE("%p %p %08lx %p %llu %p\n", process, addr, info_class, buffer, len, res_len);

    resolve_funcs();

    swapped = get_real_process(&process);
    if (process == GetCurrentProcess())
    {
        ERR("Failed to get real process\n");
        return STATUS_INVALID_PARAMETER;
    }

    stat = pNtQueryVirtualMemory(process, addr, info_class, buffer, len, res_len);

    if (stat == STATUS_ACCESS_DENIED && !swapped)
    {
        HANDLE accessable_proc;
        DuplicateHandle(GetCurrentProcess(), process, GetCurrentProcess(), &accessable_proc, PROCESS_QUERY_INFORMATION, FALSE, 0);
        stat = pNtQueryVirtualMemory(accessable_proc, addr, info_class, buffer, len, res_len);
        CloseHandle(accessable_proc);
    }
    if (swapped)
    {
        CloseHandle(process);
    }
    return stat;
}