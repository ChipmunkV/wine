#include "config.h"
#include <gst/gst.h>

#include "gst_private.h"

#include "mfapi.h"
#include "mferror.h"
#include "mfidl.h"

#include "wine/debug.h"
#include "wine/heap.h"

WINE_DEFAULT_DEBUG_CHANNEL(mfplat);

static const GUID *raw_types[] = {
    &MFAudioFormat_PCM,
    &MFAudioFormat_Float,
};

struct audio_converter
{
    IMFTransform IMFTransform_iface;
    LONG refcount;
    IMFMediaType *input_type;
    IMFMediaType *output_type;
    CRITICAL_SECTION cs;
    BOOL valid_state;
};

static struct audio_converter *impl_audio_converter_from_IMFTransform(IMFTransform *iface)
{
    return CONTAINING_RECORD(iface, struct audio_converter, IMFTransform_iface);
}

static HRESULT WINAPI audio_converter_QueryInterface(IMFTransform *iface, REFIID riid, void **obj)
{
    TRACE("%p, %s, %p.\n", iface, debugstr_guid(riid), obj);

    if (IsEqualIID(riid, &IID_IMFTransform) ||
            IsEqualIID(riid, &IID_IUnknown))
    {
        *obj = iface;
        IMFTransform_AddRef(iface);
        return S_OK;
    }

    WARN("Unsupported %s.\n", debugstr_guid(riid));
    *obj = NULL;
    return E_NOINTERFACE;
}

static ULONG WINAPI audio_converter_AddRef(IMFTransform *iface)
{
    struct audio_converter *transform = impl_audio_converter_from_IMFTransform(iface);
    ULONG refcount = InterlockedIncrement(&transform->refcount);

    TRACE("%p, refcount %u.\n", iface, refcount);

    return refcount;
}

static ULONG WINAPI audio_converter_Release(IMFTransform *iface)
{
    struct audio_converter *transform = impl_audio_converter_from_IMFTransform(iface);
    ULONG refcount = InterlockedDecrement(&transform->refcount);

    TRACE("%p, refcount %u.\n", iface, refcount);

    if (!refcount)
    {
        DeleteCriticalSection(&transform->cs);
        heap_free(transform);
    }

    return refcount;
}

static HRESULT WINAPI audio_converter_GetStreamLimits(IMFTransform *iface, DWORD *input_minimum, DWORD *input_maximum,
        DWORD *output_minimum, DWORD *output_maximum)
{
    TRACE("%p, %p, %p, %p, %p.\n", iface, input_minimum, input_maximum, output_minimum, output_maximum);

    *input_minimum = *input_maximum = *output_minimum = *output_maximum = 1;

    return S_OK;
}

static HRESULT WINAPI audio_converter_GetStreamCount(IMFTransform *iface, DWORD *inputs, DWORD *outputs)
{
    TRACE("%p, %p, %p.\n", iface, inputs, outputs);

    *inputs = *outputs = 1;

    return S_OK;
}

static HRESULT WINAPI audio_converter_GetStreamIDs(IMFTransform *iface, DWORD input_size, DWORD *inputs,
        DWORD output_size, DWORD *outputs)
{
    TRACE("%p %u %p %u %p.\n", iface, input_size, inputs, output_size, outputs);

    return E_NOTIMPL;
}

static HRESULT WINAPI audio_converter_GetInputStreamInfo(IMFTransform *iface, DWORD id, MFT_INPUT_STREAM_INFO *info)
{
    FIXME("%p %u %p.\n", iface, id, info);

    return E_NOTIMPL;
}

static HRESULT WINAPI audio_converter_GetOutputStreamInfo(IMFTransform *iface, DWORD id, MFT_OUTPUT_STREAM_INFO *info)
{
    FIXME("%p %u %p.\n", iface, id, info);

    return E_NOTIMPL;
}

static HRESULT WINAPI audio_converter_GetAttributes(IMFTransform *iface, IMFAttributes **attributes)
{
    FIXME("%p, %p.\n", iface, attributes);

    return E_NOTIMPL;
}

static HRESULT WINAPI audio_converter_GetInputStreamAttributes(IMFTransform *iface, DWORD id,
        IMFAttributes **attributes)
{
    FIXME("%p, %u, %p.\n", iface, id, attributes);

    return E_NOTIMPL;
}

static HRESULT WINAPI audio_converter_GetOutputStreamAttributes(IMFTransform *iface, DWORD id,
        IMFAttributes **attributes)
{
    FIXME("%p, %u, %p.\n", iface, id, attributes);

    return E_NOTIMPL;
}

static HRESULT WINAPI audio_converter_DeleteInputStream(IMFTransform *iface, DWORD id)
{
    TRACE("%p, %u.\n", iface, id);

    return E_NOTIMPL;
}

static HRESULT WINAPI audio_converter_AddInputStreams(IMFTransform *iface, DWORD streams, DWORD *ids)
{
    TRACE("%p, %u, %p.\n", iface, streams, ids);

    return E_NOTIMPL;
}

static HRESULT WINAPI audio_converter_GetInputAvailableType(IMFTransform *iface, DWORD id, DWORD index,
        IMFMediaType **type)
{
    IMFMediaType *ret;
    HRESULT hr;

    TRACE("%p, %u, %u, %p.\n", iface, id, index, type);

    if (id != 0)
        return MF_E_INVALIDSTREAMNUMBER;

    if (index >= ARRAY_SIZE(raw_types))
        return MF_E_NO_MORE_TYPES;

    if (FAILED(hr = MFCreateMediaType(&ret)))
        return hr;

    if (FAILED(hr = IMFMediaType_SetGUID(ret, &MF_MT_MAJOR_TYPE, &MFMediaType_Audio)))
    {
        IMFMediaType_Release(ret);
        return hr;
    }

    if (FAILED(hr = IMFMediaType_SetGUID(ret, &MF_MT_SUBTYPE, raw_types[index])))
    {
        IMFMediaType_Release(ret);
        return hr;
    }

    *type = ret;

    return S_OK;
}

static HRESULT WINAPI audio_converter_GetOutputAvailableType(IMFTransform *iface, DWORD id, DWORD index,
        IMFMediaType **type)
{
    IMFMediaType *output_type;
    HRESULT hr;

    static const DWORD rates[] = {44100, 48000};
    static const DWORD channel_cnts[] = {1, 2, 6};
    static const DWORD sizes[] = {16, 24, 32};
    const GUID *subtype;
    DWORD rate, channels, bps;

    TRACE("%p, %u, %u, %p.\n", iface, id, index, type);

    if (id != 0)
        return MF_E_INVALIDSTREAMNUMBER;

    if (index >= (2/*rates*/ * 3/*layouts*/ * 3/*bps PCM*/) + (2 * 3))
        return MF_E_NO_MORE_TYPES;

    if (FAILED(hr = MFCreateMediaType(&output_type)))
        return hr;

    if (index < 2 * 3 * 3)
    {
        subtype = &MFAudioFormat_PCM;
        rate = rates[index % 2];
        channels = channel_cnts[(index / 2) % 3];
        bps = sizes[(index / (2*3)) % 3];
    }
    else
    {
        index -= (2 * 3 * 3);
        subtype = &MFAudioFormat_Float;
        bps = 32;
        rate = rates[index % 2];
        channels = channel_cnts[(index / 2) % 3];
    }


    if (FAILED(hr = IMFMediaType_SetGUID(output_type, &MF_MT_MAJOR_TYPE, &MFMediaType_Audio)))
        goto fail;
    if (FAILED(hr = IMFMediaType_SetGUID(output_type, &MF_MT_SUBTYPE, subtype)))
        goto fail;
    if (FAILED(hr = IMFMediaType_SetUINT32(output_type, &MF_MT_AUDIO_SAMPLES_PER_SECOND, rate)))
        goto fail;
    if (FAILED(hr = IMFMediaType_SetUINT32(output_type, &MF_MT_AUDIO_NUM_CHANNELS, channels)))
        goto fail;
    if (FAILED(hr = IMFMediaType_SetUINT32(output_type, &MF_MT_AUDIO_BITS_PER_SAMPLE, bps)))
        goto fail;

    if (FAILED(hr = IMFMediaType_SetUINT32(output_type, &MF_MT_AUDIO_BLOCK_ALIGNMENT, channels * bps / 8)))
        goto fail;
    if (FAILED(hr = IMFMediaType_SetUINT32(output_type, &MF_MT_AUDIO_AVG_BYTES_PER_SECOND, rate * channels * bps / 8)))
        goto fail;
    if (FAILED(hr = IMFMediaType_SetUINT32(output_type, &MF_MT_AUDIO_CHANNEL_MASK,
            channels == 1 ? SPEAKER_FRONT_CENTER :
            channels == 2 ? SPEAKER_FRONT_LEFT | SPEAKER_FRONT_RIGHT :
          /*channels == 6*/ 0x3F)))
        goto fail;
    if (FAILED(hr = IMFMediaType_SetUINT32(output_type, &MF_MT_ALL_SAMPLES_INDEPENDENT, TRUE)))
        goto fail;

    *type = output_type;

    return S_OK;
    fail:
    IMFMediaType_Release(output_type);
    return hr;
}

static void audio_converter_update_pipeline_state(struct audio_converter *converter)
{
    GstCaps *input_caps, *output_caps;

    if (!(converter->valid_state = converter->input_type && converter->output_type))
        return;

    if (!(input_caps = caps_from_mf_media_type(converter->input_type)))
    {
        converter->valid_state = FALSE;
        return;
    }
    if (!(output_caps = caps_from_mf_media_type(converter->output_type)))
    {
        converter->valid_state = FALSE;
        gst_caps_unref(input_caps);
        return;
    }

    if (TRACE_ON(mfplat))
    {
        gchar *input_caps_str, *output_caps_str;

        input_caps_str = gst_caps_to_string(input_caps);
        output_caps_str = gst_caps_to_string(output_caps);

        TRACE("Audio converter MFT configured to transform caps %s to caps %s\n",
            debugstr_a(input_caps_str), debugstr_a(output_caps_str));

        g_free(input_caps_str);
        g_free(output_caps_str);
    }

    gst_caps_unref(input_caps);
    gst_caps_unref(output_caps);

    return;
}

static HRESULT WINAPI audio_converter_SetInputType(IMFTransform *iface, DWORD id, IMFMediaType *type, DWORD flags)
{
    unsigned int i;
    HRESULT hr;

    struct audio_converter *converter = impl_audio_converter_from_IMFTransform(iface);

    TRACE("%p, %u, %p, %#x.\n", iface, id, type, flags);

    if (id != 0)
        return MF_E_INVALIDSTREAMNUMBER;

    if (type)
    {
        GUID major_type, subtype;
        BOOL found = FALSE;
        DWORD unused;

        if (FAILED(IMFMediaType_GetGUID(type, &MF_MT_MAJOR_TYPE, &major_type)))
            return MF_E_INVALIDTYPE;
        if (FAILED(IMFMediaType_GetGUID(type, &MF_MT_SUBTYPE, &subtype)))
            return MF_E_INVALIDTYPE;
        if (FAILED(IMFMediaType_GetUINT32(type, &MF_MT_AUDIO_SAMPLES_PER_SECOND, &unused)))
            return MF_E_INVALIDTYPE;
        if (FAILED(IMFMediaType_GetUINT32(type, &MF_MT_AUDIO_NUM_CHANNELS, &unused)))
            return MF_E_INVALIDTYPE;
        if (IsEqualGUID(&subtype, &MFAudioFormat_PCM) && FAILED(IMFMediaType_GetUINT32(type, &MF_MT_AUDIO_BITS_PER_SAMPLE, &unused)))
            return MF_E_INVALIDTYPE;

        if (!(IsEqualGUID(&major_type, &MFMediaType_Audio)))
            return MF_E_INVALIDTYPE;

        for (i = 0; i < ARRAY_SIZE(raw_types); i++)
        {
            if (IsEqualGUID(&subtype, raw_types[i]))
            {
                found = TRUE;
                break;
            }
        }

        if (!found)
            return MF_E_INVALIDTYPE;
    }

    if (flags & MFT_SET_TYPE_TEST_ONLY)
        return S_OK;

    hr = S_OK;

    EnterCriticalSection(&converter->cs);

    if (type)
    {
        if (!converter->input_type)
            if (FAILED(hr = MFCreateMediaType(&converter->input_type)))
                goto done;

        if (FAILED(hr = IMFMediaType_CopyAllItems(type, (IMFAttributes *) converter->input_type)))
            goto done;
    }
    else if (converter->input_type)
    {
        IMFMediaType_Release(converter->input_type);
        converter->input_type = NULL;
    }

    done:
    if (hr == S_OK)
        audio_converter_update_pipeline_state(converter);
    LeaveCriticalSection(&converter->cs);

    return S_OK;
}

static HRESULT WINAPI audio_converter_SetOutputType(IMFTransform *iface, DWORD id, IMFMediaType *type, DWORD flags)
{
    struct audio_converter *converter = impl_audio_converter_from_IMFTransform(iface);
    GUID major_type, subtype;
    unsigned int i;
    DWORD unused;
    HRESULT hr;

    TRACE("%p, %u, %p, %#x.\n", iface, id, type, flags);

    if (id != 0)
        return MF_E_INVALIDSTREAMNUMBER;

    if (!converter->input_type)
        return MF_E_TRANSFORM_TYPE_NOT_SET;

    if (type)
    {
        /* validate the type */

        if (FAILED(IMFMediaType_GetGUID(type, &MF_MT_MAJOR_TYPE, &major_type)))
            return MF_E_INVALIDTYPE;
        if (FAILED(IMFMediaType_GetGUID(type, &MF_MT_SUBTYPE, &subtype)))
            return MF_E_INVALIDTYPE;
        if (FAILED(IMFMediaType_GetUINT32(type, &MF_MT_AUDIO_NUM_CHANNELS, &unused)))
            return MF_E_INVALIDTYPE;
        if (IsEqualGUID(&subtype, &MFAudioFormat_PCM) && FAILED(IMFMediaType_GetUINT32(type, &MF_MT_AUDIO_BITS_PER_SAMPLE, &unused)))
            return MF_E_INVALIDTYPE;
        if (FAILED(IMFMediaType_GetUINT32(type, &MF_MT_AUDIO_SAMPLES_PER_SECOND, &unused)))
            return MF_E_INVALIDTYPE;

        if (!(IsEqualGUID(&major_type, &MFMediaType_Audio)))
            return MF_E_INVALIDTYPE;

        for (i = 0; i < ARRAY_SIZE(raw_types); i++)
        {
            if (IsEqualGUID(&subtype, raw_types[i]))
                break;
            if (i == ARRAY_SIZE(raw_types))
                return MF_E_INVALIDTYPE;
        }
    }

    if (flags & MFT_SET_TYPE_TEST_ONLY)
        return S_OK;

    EnterCriticalSection(&converter->cs);

    hr = S_OK;

    if (type)
    {
        if (!converter->output_type)
            if (FAILED(hr = MFCreateMediaType(&converter->output_type)))
                goto done;

        if (FAILED(hr = IMFMediaType_CopyAllItems(type, (IMFAttributes *) converter->output_type)))
            goto done;
    }
    else if (converter->output_type)
    {
        IMFMediaType_Release(converter->output_type);
        converter->output_type = NULL;
    }

    done:
    if (hr == S_OK)
        audio_converter_update_pipeline_state(converter);
    LeaveCriticalSection(&converter->cs);

    return hr;
}

static HRESULT WINAPI audio_converter_GetInputCurrentType(IMFTransform *iface, DWORD id, IMFMediaType **type)
{
    FIXME("%p, %u, %p.\n", iface, id, type);

    return E_NOTIMPL;
}

static HRESULT WINAPI audio_converter_GetOutputCurrentType(IMFTransform *iface, DWORD id, IMFMediaType **type)
{
    FIXME("%p, %u, %p.\n", iface, id, type);

    return E_NOTIMPL;
}

static HRESULT WINAPI audio_converter_GetInputStatus(IMFTransform *iface, DWORD id, DWORD *flags)
{
    FIXME("%p, %u, %p.\n", iface, id, flags);

    return E_NOTIMPL;
}

static HRESULT WINAPI audio_converter_GetOutputStatus(IMFTransform *iface, DWORD *flags)
{
    FIXME("%p, %p.\n", iface, flags);

    return E_NOTIMPL;
}

static HRESULT WINAPI audio_converter_SetOutputBounds(IMFTransform *iface, LONGLONG lower, LONGLONG upper)
{
    FIXME("%p, %s, %s.\n", iface, wine_dbgstr_longlong(lower), wine_dbgstr_longlong(upper));

    return E_NOTIMPL;
}

static HRESULT WINAPI audio_converter_ProcessEvent(IMFTransform *iface, DWORD id, IMFMediaEvent *event)
{
    TRACE("%p, %u, %p.\n", iface, id, event);

    return E_NOTIMPL;
}

static HRESULT WINAPI audio_converter_ProcessMessage(IMFTransform *iface, MFT_MESSAGE_TYPE message, ULONG_PTR param)
{
    FIXME("%p, %u.\n", iface, message);

    return S_OK;
}

static HRESULT WINAPI audio_converter_ProcessInput(IMFTransform *iface, DWORD id, IMFSample *sample, DWORD flags)
{
    FIXME("%p, %u, %p, %#x.\n", iface, id, sample, flags);

    return E_NOTIMPL;
}

static HRESULT WINAPI audio_converter_ProcessOutput(IMFTransform *iface, DWORD flags, DWORD count,
        MFT_OUTPUT_DATA_BUFFER *samples, DWORD *status)
{
    FIXME("%p, %#x, %u, %p, %p.\n", iface, flags, count, samples, status);

    return E_NOTIMPL;
}

static const IMFTransformVtbl audio_converter_vtbl =
{
    audio_converter_QueryInterface,
    audio_converter_AddRef,
    audio_converter_Release,
    audio_converter_GetStreamLimits,
    audio_converter_GetStreamCount,
    audio_converter_GetStreamIDs,
    audio_converter_GetInputStreamInfo,
    audio_converter_GetOutputStreamInfo,
    audio_converter_GetAttributes,
    audio_converter_GetInputStreamAttributes,
    audio_converter_GetOutputStreamAttributes,
    audio_converter_DeleteInputStream,
    audio_converter_AddInputStreams,
    audio_converter_GetInputAvailableType,
    audio_converter_GetOutputAvailableType,
    audio_converter_SetInputType,
    audio_converter_SetOutputType,
    audio_converter_GetInputCurrentType,
    audio_converter_GetOutputCurrentType,
    audio_converter_GetInputStatus,
    audio_converter_GetOutputStatus,
    audio_converter_SetOutputBounds,
    audio_converter_ProcessEvent,
    audio_converter_ProcessMessage,
    audio_converter_ProcessInput,
    audio_converter_ProcessOutput,
};

HRESULT audio_converter_create(REFIID riid, void **ret)
{
    struct audio_converter *object;

    TRACE("%s %p\n", debugstr_guid(riid), ret);

    if (!(object = heap_alloc_zero(sizeof(*object))))
        return E_OUTOFMEMORY;

    object->IMFTransform_iface.lpVtbl = &audio_converter_vtbl;
    object->refcount = 1;

    InitializeCriticalSection(&object->cs);

    *ret = &object->IMFTransform_iface;
    return S_OK;
}
