#ifndef __WINE_SERVER_DEVICE_H
#define __WINE_SERVER_DEVICE_H

#include "wine/server_protocol.h"
#include "object.h"

struct device_manager;

void queue_callback(krnl_cbdata_t *cb, struct unicode_str *string_param, struct object **done_event);

#endif