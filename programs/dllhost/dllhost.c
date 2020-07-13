#include "wine/debug.h"

#include "windef.h"

WINE_DEFAULT_DEBUG_CHANNEL(dllhost);

int __cdecl wmain(int argc, WCHAR *argv[])
{
    int i;

    WINE_FIXME("stub:");
    for (i = 0; i < argc; i++)
        WINE_FIXME(" %s", wine_dbgstr_w(argv[i]));
    WINE_FIXME("\n");

    return 0;
}