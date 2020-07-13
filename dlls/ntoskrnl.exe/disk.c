#include <stdarg.h>

#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "windef.h"
#include "winternl.h"
#include "ddk/wdm.h"
#include "wine/debug.h"

#include "ntoskrnl_private.h"

WINE_DEFAULT_DEBUG_CHANNEL(ntoskrnl);

static DRIVER_OBJECT *disk_driver;

static NTSTATUS WINAPI disk_driver_entry( DRIVER_OBJECT *driver, UNICODE_STRING *keypath )
{
    disk_driver = driver;
    return STATUS_SUCCESS;
}

void disk_driver_start(void)
{
    static const WCHAR driver_nameW[] = L"\\Driver\\disk";
    UNICODE_STRING driver_nameU;
    NTSTATUS status;

    RtlInitUnicodeString( &driver_nameU, driver_nameW );
    if ((status = IoCreateDriver( &driver_nameU, disk_driver_entry )))
        ERR("Failed to create disk driver, status %#x.\n", status);
}

void disk_driver_stop(void)
{
    IoDeleteDriver( disk_driver );
}