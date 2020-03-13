/*
 * GStreamer splitter + decoder, adapted from parser.c
 *
 * Copyright 2010 Maarten Lankhorst for CodeWeavers
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

#ifndef __GST_PRIVATE_INCLUDED__
#define __GST_PRIVATE_INCLUDED__

#include <stdarg.h>

#define COBJMACROS
#include "windef.h"
#include "winbase.h"
#include "wtypes.h"
#include "winuser.h"
#include "dshow.h"
#include "strmif.h"
#include "mfidl.h"
#include "mfobjects.h"
#include "wine/heap.h"
#include "wine/strmbase.h"

#define MEDIATIME_FROM_BYTES(x) ((LONGLONG)(x) * 10000000)

IUnknown * CALLBACK avi_splitter_create(IUnknown *outer, HRESULT *phr) DECLSPEC_HIDDEN;
IUnknown * CALLBACK mpeg_splitter_create(IUnknown *outer, HRESULT *phr) DECLSPEC_HIDDEN;
IUnknown * CALLBACK Gstreamer_Splitter_create(IUnknown *pUnkOuter, HRESULT *phr);
IUnknown * CALLBACK wave_parser_create(IUnknown *outer, HRESULT *phr) DECLSPEC_HIDDEN;

BOOL init_gstreamer(void) DECLSPEC_HIDDEN;

void start_dispatch_thread(void) DECLSPEC_HIDDEN;

extern HRESULT mfplat_DllRegisterServer(void) DECLSPEC_HIDDEN;
extern HRESULT mfplat_get_class_object(REFCLSID rclsid, REFIID riid, void **obj) DECLSPEC_HIDDEN;
extern HRESULT mfplat_can_unload_now(void) DECLSPEC_HIDDEN;

IMFMediaType* mfplat_media_type_from_caps(GstCaps *caps);
GstCaps *caps_from_media_type(IMFMediaType *type);
IMFSample* mf_sample_from_gst_buffer(GstBuffer *in, IMFMediaType *buffer_type);
GstBuffer* gst_buffer_from_mf_sample(IMFSample *in);

enum decoder_type
{
    DECODER_TYPE_H264,
    DECODER_TYPE_AAC,
};
HRESULT generic_decoder_construct(REFIID riid, void **obj, enum decoder_type);
enum source_type
{
    SOURCE_TYPE_MPEG_4,
};
HRESULT container_stream_handler_construct(REFIID riid, void **obj, enum source_type);

#endif /* __GST_PRIVATE_INCLUDED__ */
