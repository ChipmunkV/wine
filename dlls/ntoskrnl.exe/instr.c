/*
 * Emulation of privileged instructions
 *
 * Copyright 1995 Alexandre Julliard
 * Copyright 2005 Ivan Leo Puoti
 * Copyright 2005 Laurent Pinchart
 * Copyright 2014-2015 Sebastian Lackner
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

#define NONAMELESSUNION
#define NONAMELESSSTRUCT
#include "windef.h"
#include "winbase.h"
#include "winternl.h"
#define WIN32_NO_STATUS
#include "ddk/wdm.h"
#include "excpt.h"
#include "wine/debug.h"
#include "wine/exception.h"
#include "wine/rbtree.h"

#include "ntoskrnl_private.h"

#define KSHARED_USER_DATA_PAGE_SIZE 0x1000

#define CR0_PE 0x00000001 /* Protected Mode */
#define CR0_ET 0x00000010 /* Extension Type */
#define CR0_NE 0x00000020 /* Numeric Error */
#define CR0_WP 0x00010000 /* Write Protect */
#define CR0_AM 0x00040000 /* Alignment Mask */
#define CR0_PG 0x80000000 /* Paging */

enum instr_op
{
    INSTR_OP_MOV,
    INSTR_OP_OR,
    INSTR_OP_XOR,
};

extern PVOID MmHighestUserAddress;

#ifdef __i386__

WINE_DEFAULT_DEBUG_CHANNEL(int);

#include "pshpack1.h"
struct idtr
{
    WORD  limit;
    BYTE *base;
};
#include "poppack.h"

static LDT_ENTRY idt[256];

static inline struct idtr get_idtr(void)
{
    struct idtr ret;
#ifdef __GNUC__
    __asm__( "sidtl %0" : "=m" (ret) );
#else
    ret.base = (BYTE *)idt;
    ret.limit = sizeof(idt) - 1;
#endif
    return ret;
}

/* store an operand into a register */
static void store_reg_word( CONTEXT *context, BYTE regmodrm, const BYTE *addr, int long_op )
{
    switch((regmodrm >> 3) & 7)
    {
    case 0:
        if (long_op) context->Eax = *(const DWORD *)addr;
        else context->Eax = (context->Eax & 0xffff0000) | *(const WORD *)addr;
        break;
    case 1:
        if (long_op) context->Ecx = *(const DWORD *)addr;
        else context->Ecx = (context->Ecx & 0xffff0000) | *(const WORD *)addr;
        break;
    case 2:
        if (long_op) context->Edx = *(const DWORD *)addr;
        else context->Edx = (context->Edx & 0xffff0000) | *(const WORD *)addr;
        break;
    case 3:
        if (long_op) context->Ebx = *(const DWORD *)addr;
        else context->Ebx = (context->Ebx & 0xffff0000) | *(const WORD *)addr;
        break;
    case 4:
        if (long_op) context->Esp = *(const DWORD *)addr;
        else context->Esp = (context->Esp & 0xffff0000) | *(const WORD *)addr;
        break;
    case 5:
        if (long_op) context->Ebp = *(const DWORD *)addr;
        else context->Ebp = (context->Ebp & 0xffff0000) | *(const WORD *)addr;
        break;
    case 6:
        if (long_op) context->Esi = *(const DWORD *)addr;
        else context->Esi = (context->Esi & 0xffff0000) | *(const WORD *)addr;
        break;
    case 7:
        if (long_op) context->Edi = *(const DWORD *)addr;
        else context->Edi = (context->Edi & 0xffff0000) | *(const WORD *)addr;
        break;
    }
}

/* store an operand into a byte register */
static void store_reg_byte( CONTEXT *context, BYTE regmodrm, const BYTE *addr )
{
    switch((regmodrm >> 3) & 7)
    {
    case 0: context->Eax = (context->Eax & 0xffffff00) | *addr; break;
    case 1: context->Ecx = (context->Ecx & 0xffffff00) | *addr; break;
    case 2: context->Edx = (context->Edx & 0xffffff00) | *addr; break;
    case 3: context->Ebx = (context->Ebx & 0xffffff00) | *addr; break;
    case 4: context->Eax = (context->Eax & 0xffff00ff) | (*addr << 8); break;
    case 5: context->Ecx = (context->Ecx & 0xffff00ff) | (*addr << 8); break;
    case 6: context->Edx = (context->Edx & 0xffff00ff) | (*addr << 8); break;
    case 7: context->Ebx = (context->Ebx & 0xffff00ff) | (*addr << 8); break;
    }
}

static DWORD *get_reg_address( CONTEXT *context, BYTE rm )
{
    switch (rm & 7)
    {
    case 0: return &context->Eax;
    case 1: return &context->Ecx;
    case 2: return &context->Edx;
    case 3: return &context->Ebx;
    case 4: return &context->Esp;
    case 5: return &context->Ebp;
    case 6: return &context->Esi;
    case 7: return &context->Edi;
    }
    return NULL;
}


/***********************************************************************
 *           INSTR_GetOperandAddr
 *
 * Return the address of an instruction operand (from the mod/rm byte).
 */
static void *INSTR_GetOperandAddr( CONTEXT *context, BYTE *instr,
                                   int long_addr, int segprefix, int *len )
{
    int mod, rm, base = 0, index = 0, ss = 0, off;

#define GET_VAL(val,type) \
    { *val = *(type *)instr; instr += sizeof(type); *len += sizeof(type); }

    *len = 0;
    GET_VAL( &mod, BYTE );
    rm = mod & 7;
    mod >>= 6;

    if (mod == 3) return get_reg_address( context, rm );

    if (long_addr)
    {
        if (rm == 4)
        {
            BYTE sib;
            GET_VAL( &sib, BYTE );
            rm = sib & 7;
            ss = sib >> 6;
            switch((sib >> 3) & 7)
            {
            case 0: index = context->Eax; break;
            case 1: index = context->Ecx; break;
            case 2: index = context->Edx; break;
            case 3: index = context->Ebx; break;
            case 4: index = 0; break;
            case 5: index = context->Ebp; break;
            case 6: index = context->Esi; break;
            case 7: index = context->Edi; break;
            }
        }

        switch(rm)
        {
        case 0: base = context->Eax; break;
        case 1: base = context->Ecx; break;
        case 2: base = context->Edx; break;
        case 3: base = context->Ebx; break;
        case 4: base = context->Esp; break;
        case 5: base = context->Ebp; break;
        case 6: base = context->Esi; break;
        case 7: base = context->Edi; break;
        }
        switch (mod)
        {
        case 0:
            if (rm == 5)  /* special case: ds:(disp32) */
            {
                GET_VAL( &base, DWORD );
            }
            break;

        case 1:  /* 8-bit disp */
            GET_VAL( &off, BYTE );
            base += (signed char)off;
            break;

        case 2:  /* 32-bit disp */
            GET_VAL( &off, DWORD );
            base += (signed long)off;
            break;
        }
    }
    else  /* short address */
    {
        switch(rm)
        {
        case 0:  /* ds:(bx,si) */
            base = LOWORD(context->Ebx) + LOWORD(context->Esi);
            break;
        case 1:  /* ds:(bx,di) */
            base = LOWORD(context->Ebx) + LOWORD(context->Edi);
            break;
        case 2:  /* ss:(bp,si) */
            base = LOWORD(context->Ebp) + LOWORD(context->Esi);
            break;
        case 3:  /* ss:(bp,di) */
            base = LOWORD(context->Ebp) + LOWORD(context->Edi);
            break;
        case 4:  /* ds:(si) */
            base = LOWORD(context->Esi);
            break;
        case 5:  /* ds:(di) */
            base = LOWORD(context->Edi);
            break;
        case 6:  /* ss:(bp) */
            base = LOWORD(context->Ebp);
            break;
        case 7:  /* ds:(bx) */
            base = LOWORD(context->Ebx);
            break;
        }

        switch(mod)
        {
        case 0:
            if (rm == 6)  /* special case: ds:(disp16) */
            {
                GET_VAL( &base, WORD );
            }
            break;

        case 1:  /* 8-bit disp */
            GET_VAL( &off, BYTE );
            base += (signed char)off;
            break;

        case 2:  /* 16-bit disp */
            GET_VAL( &off, WORD );
            base += (signed short)off;
            break;
        }
        base &= 0xffff;
    }
    /* FIXME: we assume that all segments have a base of 0 */
    return (void *)(base + (index << ss));
#undef GET_VAL
}


/***********************************************************************
 *           emulate_instruction
 *
 * Emulate a privileged instruction.
 * Returns exception continuation status.
 */
static DWORD emulate_instruction( EXCEPTION_RECORD *rec, CONTEXT *context )
{
    static const char *reg_names[8] = { "eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi" };
    int prefix, segprefix, prefixlen, len, long_op, long_addr;
    BYTE *instr;

    long_op = long_addr = 1;
    instr = (BYTE *)context->Eip;
    if (!instr) return ExceptionContinueSearch;

    /* First handle any possible prefix */

    segprefix = -1;  /* no prefix */
    prefix = 1;
    prefixlen = 0;
    while(prefix)
    {
        switch(*instr)
        {
        case 0x2e:
            segprefix = context->SegCs;
            break;
        case 0x36:
            segprefix = context->SegSs;
            break;
        case 0x3e:
            segprefix = context->SegDs;
            break;
        case 0x26:
            segprefix = context->SegEs;
            break;
        case 0x64:
            segprefix = context->SegFs;
            break;
        case 0x65:
            segprefix = context->SegGs;
            break;
        case 0x66:
            long_op = !long_op;  /* opcode size prefix */
            break;
        case 0x67:
            long_addr = !long_addr;  /* addr size prefix */
            break;
        case 0xf0:  /* lock */
	    break;
        case 0xf2:  /* repne */
	    break;
        case 0xf3:  /* repe */
            break;
        default:
            prefix = 0;  /* no more prefixes */
            break;
        }
        if (prefix)
        {
            instr++;
            prefixlen++;
        }
    }

    /* Now look at the actual instruction */

    switch(*instr)
    {
    case 0x0f: /* extended instruction */
        switch(instr[1])
        {
        case 0x20: /* mov crX, Rd */
            {
                int reg = (instr[2] >> 3) & 7;
                DWORD *data = get_reg_address( context, instr[2] );
                TRACE( "mov cr%u,%s at 0x%08x\n", reg, reg_names[instr[2] & 7], context->Eip );
                switch (reg)
                {
                case 0: *data = CR0_PE|CR0_ET|CR0_NE|CR0_WP|CR0_AM|CR0_PG; break;
                case 2: *data = 0; break;
                case 3: *data = 0; break;
                case 4: *data = 0; break;
                default: return ExceptionContinueSearch;
                }
                context->Eip += prefixlen + 3;
                return ExceptionContinueExecution;
            }
        case 0x21: /* mov drX, Rd */
            {
                int reg = (instr[2] >> 3) & 7;
                DWORD *data = get_reg_address( context, instr[2] );
                TRACE( "mov dr%u,%s at 0x%08x\n", reg, reg_names[instr[2] & 7], context->Eip );
                switch (reg)
                {
                case 0: *data = context->Dr0; break;
                case 1: *data = context->Dr1; break;
                case 2: *data = context->Dr2; break;
                case 3: *data = context->Dr3; break;
                case 6: *data = context->Dr6; break;
                case 7: *data = 0x400; break;
                default: return ExceptionContinueSearch;
                }
                context->Eip += prefixlen + 3;
                return ExceptionContinueExecution;
            }
        case 0x22: /* mov Rd, crX */
            {
                int reg = (instr[2] >> 3) & 7;
                DWORD *data = get_reg_address( context, instr[2] );
                TRACE( "mov %s,cr%u at 0x%08x, %s=%08x\n", reg_names[instr[2] & 7],
                       reg, context->Eip, reg_names[instr[2] & 7], *data );
                switch (reg)
                {
                case 0: break;
                case 2: break;
                case 3: break;
                case 4: break;
                default: return ExceptionContinueSearch;
                }
                context->Eip += prefixlen + 3;
                return ExceptionContinueExecution;
            }
        case 0x23: /* mov Rd, drX */
            {
                int reg = (instr[2] >> 3) & 7;
                DWORD *data = get_reg_address( context, instr[2] );
                TRACE( "mov %s,dr%u at 0x%08x %s=%08x\n", reg_names[instr[2] & 7],
                       reg, context->Eip, reg_names[instr[2] & 7], *data );
                switch (reg)
                {
                case 0: context->Dr0 = *data; break;
                case 1: context->Dr1 = *data; break;
                case 2: context->Dr2 = *data; break;
                case 3: context->Dr3 = *data; break;
                case 6: context->Dr6 = *data; break;
                case 7: context->Dr7 = *data; break;
                default: return ExceptionContinueSearch;
                }
                context->Eip += prefixlen + 3;
                return ExceptionContinueExecution;
            }
        }
        break;

    case 0x8a: /* mov Eb, Gb */
    case 0x8b: /* mov Ev, Gv */
    {
        BYTE *data = INSTR_GetOperandAddr(context, instr + 1, long_addr,
                                          segprefix, &len);
        unsigned int data_size = (*instr == 0x8b) ? (long_op ? 4 : 2) : 1;
        struct idtr idtr = get_idtr();
        unsigned int offset = data - idtr.base;

        if (offset <= idtr.limit + 1 - data_size)
        {
            idt[1].LimitLow = 0x100; /* FIXME */
            idt[2].LimitLow = 0x11E; /* FIXME */
            idt[3].LimitLow = 0x500; /* FIXME */

            switch (*instr)
            {
            case 0x8a: store_reg_byte( context, instr[1], (BYTE *)idt + offset ); break;
            case 0x8b: store_reg_word( context, instr[1], (BYTE *)idt + offset, long_op ); break;
            }
            context->Eip += prefixlen + len + 1;
            return ExceptionContinueExecution;
        }
        break;  /* Unable to emulate it */
    }

    case 0xfa: /* cli */
    case 0xfb: /* sti */
        context->Eip += prefixlen + 1;
        return ExceptionContinueExecution;
    }
    return ExceptionContinueSearch;  /* Unable to emulate it */
}


/***********************************************************************
 *           vectored_handler
 *
 * Vectored exception handler used to emulate protected instructions
 * from 32-bit code.
 */
LONG CALLBACK vectored_handler( EXCEPTION_POINTERS *ptrs )
{
    EXCEPTION_RECORD *record = ptrs->ExceptionRecord;
    CONTEXT *context = ptrs->ContextRecord;

    if ((record->ExceptionCode == EXCEPTION_ACCESS_VIOLATION ||
         record->ExceptionCode == EXCEPTION_PRIV_INSTRUCTION))
    {
        if (emulate_instruction( record, context ) == ExceptionContinueExecution)
            return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

void *register_kernel_struct(void *obj, unsigned int size, kernel_struct_accessed callback)
{
    return obj;
}

void forget_kernel_struct(void *obj)
{
    return;
}

#elif defined(__x86_64__)  /* __i386__ */

WINE_DEFAULT_DEBUG_CHANNEL(int);

struct kernel_struct
{
    BYTE *base;
    unsigned int size;
    kernel_struct_accessed callback;
    struct wine_rb_entry entry;
};

static int compare_kernel_struct( const void *key, const struct wine_rb_entry *entry )
{
    const struct kernel_struct *kernel_struct = WINE_RB_ENTRY_VALUE( entry, const struct kernel_struct, entry );
    const BYTE *access_address = key;

    if (access_address < kernel_struct->base)
        return -1;
    else if (access_address < (kernel_struct->base + kernel_struct->size))
        return 0;
    else
        return 1;
}

static struct wine_rb_tree kernel_structs = {compare_kernel_struct};

static struct kernel_struct *get_kernel_struct (void *addr)
{
    struct wine_rb_entry *entry = wine_rb_get(&kernel_structs, addr);
    return entry ? WINE_RB_ENTRY_VALUE( entry, struct kernel_struct, entry ) : NULL;
}

void *register_kernel_struct(void *base, unsigned int size, kernel_struct_accessed callback)
{
    struct kernel_struct *new_struct;

    base = TO_KRNL(base);

    TRACE("(%p, %u)\n", base, size);

    if ((get_kernel_struct(base)))
        return NULL;

    new_struct = HeapAlloc(GetProcessHeap(), 0, (sizeof(*new_struct)));
    new_struct->base = base;
    new_struct->size = size;
    new_struct->callback = callback;

    wine_rb_put(&kernel_structs, new_struct->base, &new_struct->entry);

    return base;
}

void forget_kernel_struct(void *obj)
{
    struct kernel_struct *kernel_struct = get_kernel_struct(obj);

    if (obj != kernel_struct->base)
        return;

    wine_rb_remove(&kernel_structs, &kernel_struct->entry);
    HeapFree(GetProcessHeap(), 0, kernel_struct);
    return;
}

KSHARED_USER_DATA *wine_user_shared_data = (void *)0x7ffe0000;
static const BYTE *user_shared_data      = (BYTE *)0xfffff78000000000;

static DWORD64 current_rip;

int read_emulated_memory(void *buf, BYTE *addr, unsigned int length)
{
    SIZE_T offset;
    struct kernel_struct *kernel_struct;
    struct _KTHREAD *current_thread;
    struct _EPROCESS *current_process = NULL;

    TRACE("(%p, %u)\n", addr, length);

    if ((current_thread = TO_USER(NtCurrentTeb()->SystemReserved1[15])))
    {
        current_process = TO_USER(current_thread->process);

        if (current_thread->user_input_copy)
        {
            ULONG size = HeapSize( GetProcessHeap(), 0, current_thread->user_input_copy );
            offset = addr - current_thread->user_input;
            if (size != -1 && offset + length <= size)
            {
                memcpy(buf, (BYTE*)current_thread->user_input_copy + offset, length);
                goto done;
            }
        }
        if (current_thread->user_output_copy)
        {
            ULONG size = HeapSize( GetProcessHeap(), 0, current_thread->user_output_copy );
            offset = addr - current_thread->user_output;
            if (size != -1 && offset + length <= size)
            {
                memcpy(buf, (BYTE*)current_thread->user_output_copy + offset, length);
                goto done;
            }
        }
    }

    /* first check user shared data */
    offset = addr - user_shared_data;
    if (offset + length <= sizeof(KSHARED_USER_DATA))
    {
        WARN("user_shared_data accessed at offset %x @ %016llx\n", offset, current_rip);
        memcpy(buf, (BYTE *)wine_user_shared_data + offset, length);
        return 1;
    }

    /* Then look through struct mappings */
    if ((kernel_struct = get_kernel_struct(addr)))
    {
        offset = addr - kernel_struct->base;
        if (offset + length <= kernel_struct->size)
        {
            if (kernel_struct->callback)
                kernel_struct->callback(TO_USER(kernel_struct->base), offset, 0, (void *)current_rip);
            memcpy(buf, TO_USER(kernel_struct->base) + offset, length);
            return 1;
        }
    }

    if (current_process && addr <= (PBYTE)MmHighestUserAddress)
    {
        if (current_process->info.UniqueProcessId != GetCurrentProcessId())
        {
            HANDLE process;
            WARN("Emulating access to arbitrary user space process memory (%p, %u) from %016llx\n", addr, length, current_rip);
            if ((process = OpenProcess(PROCESS_VM_READ, FALSE, (DWORD)(ULONG_PTR) current_process->info.UniqueProcessId)))
            {
                BOOL ret = ReadProcessMemory(process, addr, buf, length, NULL);
                CloseHandle(process);
                if (!ret)
                    ERR("Failed to read memory from process. %u\n", GetLastError());
                return ret;
            }
            else
                goto fail;
        }
    }

    fail:
    ERR("Failed to emulate memory access to %p+%u from %016llx\n", addr, length, current_rip);
    return 0;
    done:
    return 1;
}

int write_emulated_memory(BYTE *addr, void *buf, unsigned int length)
{
    SIZE_T offset;
    struct _KTHREAD *current_thread;
    struct _EPROCESS *current_process = NULL;
    struct kernel_struct *kernel_struct;

    TRACE("(%p, %u)\n", addr, length);

    if ((current_thread = TO_USER(NtCurrentTeb()->SystemReserved1[15])))
    {
        current_process = TO_USER(current_thread->process);
        if (current_thread->user_output_copy)
        {
            ULONG size = HeapSize( GetProcessHeap(), 0, current_thread->user_output_copy );
            offset = addr - current_thread->user_output;
            if (length == -1 && buf == addr && addr == current_thread->user_output)
                length = size;
            if (size != -1 && offset + length <= size)
            {
                memcpy((BYTE*)current_thread->user_output_copy + offset, buf, length);
                goto done;
            }
        }
        if (current_thread->user_input_copy)
        {
            ULONG size = HeapSize( GetProcessHeap(), 0, current_thread->user_input_copy );
            offset = addr - current_thread->user_input;
            if (length == -1 && buf == addr && addr == current_thread->user_input)
                length = size;
            if (size != -1 && offset + length <= size)
            {
                FIXME("ignoring write to input IRP memory\n");
                memcpy((BYTE*)current_thread->user_input_copy + offset, buf, length);
                goto done;
            }
        }
    }

    offset = addr - user_shared_data;
    if (offset + length <= sizeof(KSHARED_USER_DATA))
    {
        FIXME("Writing to KSHARED_USER_DATA unsupported!\n");
        goto fail;
    }

    if ((kernel_struct = get_kernel_struct(addr)))
    {
        offset = addr - kernel_struct->base;
        if (offset + length <= kernel_struct->size)
        {
            if (kernel_struct->callback)
                kernel_struct->callback(TO_USER(kernel_struct->base), offset, 1, (void *)current_rip);
            memcpy(TO_USER(kernel_struct->base) + offset, buf, length);
            return 1;
        }
    }

    if (current_process && addr <= (PBYTE)MmHighestUserAddress)
    {
        if (current_process->info.UniqueProcessId != GetCurrentProcessId())
        {
            HANDLE process;
            WARN("arbitrary user space process memory access (%p, %u) from %016llx\n", addr, length, current_rip);
            if ((process = OpenProcess(PROCESS_VM_WRITE, FALSE, (DWORD)(ULONG_PTR) current_process->info.UniqueProcessId)))
            {
                BOOL ret = WriteProcessMemory(process, addr, buf, length, NULL);
                CloseHandle(process);
                return ret;
            }
            else
                goto fail;
        }
    }

    fail:
    ERR("Failed to emulate memory access to %p+%u\n", addr, length);
    return 0;
    done:
    return 1;
}

struct ex_prefix
{
    BOOL present;
    BOOL r, x, b, w, l;
    DWORD m, v;
    WORD p;
};

#define REX_B   1
#define REX_X   2
#define REX_R   4
#define REX_W   8

#define MSR_LSTAR   0xc0000082

#define REGMODRM_MOD( regmodrm, pfx )   ((regmodrm) >> 6)
#define REGMODRM_REG( regmodrm, pfx )   (((regmodrm) >> 3) & 7) | (pfx.r ? 8 : 0)
#define REGMODRM_RM( regmodrm, pfx )    (((regmodrm) & 7) | (pfx.b ? 8 : 0))

#define SIB_SS( sib, pfx )      ((sib) >> 6)
#define SIB_INDEX( sib, pfx )   (((sib) >> 3) & 7) | (pfx.x ? 8 : 0)
#define SIB_BASE( sib, pfx )    (((sib) & 7) | (pfx.b ? 8 : 0))

static inline DWORD64 *get_int_reg( CONTEXT *context, int index )
{
    return &context->Rax + index; /* index should be in range 0 .. 15 */
}

static inline M128A *get_xmm_reg ( CONTEXT *context, int index )
{
    return &context->u.s.Xmm0 + index;
}

static inline M128A *get_ymm_reg ( CONTEXT *context, int index )
{
    return &context->VectorRegister[index];
}

static inline int get_op_size( int long_op, struct ex_prefix pfx )
{
    if (pfx.w)
        return sizeof(DWORD64);
    else if (long_op)
        return sizeof(DWORD);
    else
        return sizeof(WORD);
}

/* store an operand into a register */
static void store_reg_word( CONTEXT *context, BYTE regmodrm, const BYTE *addr, int long_op, struct ex_prefix pfx, enum instr_op op )
{
    int index = REGMODRM_REG( regmodrm, pfx );
    BYTE *reg = (BYTE *)get_int_reg( context, index );
    int op_size = get_op_size( long_op, pfx );
    int i;

    if (op_size == 4)
        memset( reg, 0, 8 );

    switch (op)
    {
        case INSTR_OP_MOV:
            memcpy( reg, addr, op_size );
            break;
        case INSTR_OP_OR:
            for (i = 0; i < op_size; ++i)
                reg[i] |= addr[i];
            break;
        case INSTR_OP_XOR:
            for (i = 0; i < op_size; ++i)
                reg[i] ^= addr[i];
            break;
    }
}

/* store an operand into a byte register */
static void store_reg_byte( CONTEXT *context, BYTE regmodrm, const BYTE *addr, struct ex_prefix pfx, enum instr_op op )
{
    int index = REGMODRM_REG( regmodrm, pfx );
    BYTE *reg = (BYTE *)get_int_reg( context, index );
    if (!pfx.present && index >= 4 && index < 8) reg -= (4 * sizeof(DWORD64) - 1); /* special case: ah, ch, dh, bh */

    switch (op)
    {
        case INSTR_OP_MOV:
            *reg = *addr;
            break;
        case INSTR_OP_OR:
            *reg |= *addr;
            break;
        case INSTR_OP_XOR:
            *reg ^= *addr;
            break;
    }
}

/***********************************************************************
 *           INSTR_GetOperandAddr
 *
 * Return the address of an instruction operand (from the mod/rm byte).
 */
static BYTE *INSTR_GetOperandAddr( CONTEXT *context, BYTE *instr, int addl_instr_len,
                                   int long_addr, struct ex_prefix pfx, int segprefix, int *len )
{
    int mod, rm, ss = 0, off, have_sib = 0;
    DWORD64 base = 0, index = 0;

#define GET_VAL( val, type ) \
    { *val = *(type *)instr; instr += sizeof(type); *len += sizeof(type); }

    *len = 0;
    GET_VAL( &mod, BYTE );
    rm  = REGMODRM_RM( mod, pfx );
    mod = REGMODRM_MOD( mod, pfx );

    if (mod == 3)
        return (BYTE *)get_int_reg( context, rm );

    if ((rm & 7) == 4)
    {
        BYTE sib;
        int id;

        GET_VAL( &sib, BYTE );
        rm = SIB_BASE( sib, pfx );
        id = SIB_INDEX( sib, pfx );
        ss = SIB_SS( sib, pfx );

        index = (id != 4) ? *get_int_reg( context, id ) : 0;
        if (!long_addr) index &= 0xffffffff;
        have_sib = 1;
    }

    base = *get_int_reg( context, rm );
    if (!long_addr) base &= 0xffffffff;

    switch (mod)
    {
    case 0:
        if (rm == 5)  /* special case */
        {
            base = have_sib ? 0 : context->Rip;
            if (!long_addr) base &= 0xffffffff;
            GET_VAL( &off, DWORD );
            base += (signed long)off;
            base += (signed long)*len + (signed long)addl_instr_len;
        }
        break;

    case 1:  /* 8-bit disp */
        GET_VAL( &off, BYTE );
        base += (signed char)off;
        break;

    case 2:  /* 32-bit disp */
        GET_VAL( &off, DWORD );
        base += (signed long)off;
        break;
    }

    /* FIXME: we assume that all segments have a base of 0 */
    return (BYTE *)(base + (index << ss));
#undef GET_VAL
}

static struct ex_prefix get_ex_prefix(BYTE *instr, int *prefix_len)
{
    struct ex_prefix pfx = {0};

    /* REX */
    if ((*instr >> 4) == 0x4)
    {
        pfx.w = !!(*instr & REX_W);
        pfx.r = !!(*instr & REX_R);
        pfx.x = !!(*instr & REX_X);
        pfx.b = !!(*instr & REX_B);
        *prefix_len = 1;
        pfx.present = TRUE;
    }
    else if (*instr == 0xC4 || *instr == 0xC5)
    {
        BOOL three_byte_mode = *instr == 0xC4;
        instr += 1;

        pfx.r = !(*instr & 128);
        if (three_byte_mode)
        {
            pfx.x = !(*instr & 64);
            pfx.b = !(*instr & 32);
            pfx.m = *instr & 31;
            instr+=1;
            pfx.w = !!(*instr & 128);
        }
        else
            pfx.m = 1;

        pfx.v = ~((*instr >> 3) & 15);
        pfx.l = !!(*instr & 4);
        pfx.p = *instr & 3;

        *prefix_len = three_byte_mode ? 3 : 2;
        pfx.present = TRUE;
    }
    else
    {
        *prefix_len = 0;
    }
    return pfx;
}

#define SET_BIT(x, n, y) x = (x & (~(1 << n))) | (y << n)

static ULONGLONG INSTR_add(DWORD *flags, BYTE *op1, BYTE op1_len, BYTE *op2, BYTE op2_len)
{
    BYTE op2_val[8], result[8];
    BOOL carry = 0, overflow, zero = TRUE;

    if (op1_len > 8 || op2_len > op1_len)
    {
        ERR("Invalid instruction");
        return 0;
    }

    /* sign extend op2 to op1_len*/
    if (op1_len != op2_len)
    {
        memcpy(op2_val, op2, op2_len);
        op2 = op2_val;
        memset(&op2[op2_len], !!(op2[op2_len - 1] & 0x80), op1_len - op2_len);
    }

    for (unsigned int i = 0; i < op1_len; i++)
    {
        result[i] = op1[i] + (op2[i] + carry);
        carry = result[i] < op1[i];
        overflow = (!!(op1[i] & 0x80) != !!(result[i] & 0x80)) ^ carry;
        if (result[i])
            zero = FALSE;
    }

    SET_BIT(*flags, 0, carry);  /* CF */
    SET_BIT(*flags, 2, __builtin_parity(result[0])); /* PF */
    //SET_BIT(*flags, 4, ); /* AF */
    SET_BIT(*flags, 6, zero); /* ZF */
    SET_BIT(*flags, 7, !!(result[op1_len - 1] & 0x80));     /* SF */
    SET_BIT(*flags, 11, overflow); /* OF */

    return *(ULONGLONG*)result;
}

static ULONGLONG INSTR_sub(DWORD *flags, BYTE *op1, BYTE op1_len, BYTE *op2, BYTE op2_len)
{
    BYTE op2_val[8], result[8];
    BOOL carry = 0, overflow, zero = TRUE;

    if (op1_len > 8 || op2_len > op1_len)
    {
        ERR("Invalid instruction");
        return 0;
    }

    /* sign extend op2 to op1_len*/
    if (op1_len != op2_len)
    {
        memcpy(op2_val, op2, op2_len);
        op2 = op2_val;
        memset(&op2[op2_len], !!(op2[op2_len - 1] & 0x80), op1_len - op2_len);
    }

    for (unsigned int i = 0; i < op1_len; i++)
    {
        result[i] = op1[i] - (op2[i] + carry);
        carry = op1[i] < (op2[i] + carry);
        overflow = (!!(op1[i] & 0x80) != !!(result[i] & 0x80)) ^ carry;
        if (result[i])
            zero = FALSE;
    }

    TRACE("flags %x carry %u zero %u overflow %u\n", *flags, carry, zero, overflow);

    SET_BIT(*flags, 0, carry);  /* CF */
    SET_BIT(*flags, 2, __builtin_parity(result[0])); /* PF */
    //SET_BIT(*flags, 4, ); /* AF */
    SET_BIT(*flags, 6, zero); /* ZF */
    SET_BIT(*flags, 7, !!(result[op1_len - 1] & 0x80)); /* SF */
    SET_BIT(*flags, 11, overflow); /* OF */

    TRACE("flags %x\n", *flags);

    return *(ULONGLONG*)result;
}

static ULONGLONG INSTR_and(DWORD *flags, BYTE *op1, BYTE op1_len, BYTE *op2, BYTE op2_len)
{
    BYTE op2_val[8], result[8];
    BOOL zero = TRUE;

    if (op1_len > 8 || op2_len > op1_len)
        return 0;

    /* sign extend op2 to op1_len*/
    if (op1_len != op2_len)
    {
        memcpy(op2_val, op2, op2_len);
        op2 = op2_val;
        memset(&op2[op2_len], !!(op2[op2_len - 1] & 0x80), op1_len - op2_len);
    }

    for (unsigned int i = 0; i < op1_len; i++)
    {
        result[i] = op1[i] & op2[i];
        if (result[i])
            zero = FALSE;
    }

    SET_BIT(*flags, 0, 0); /* CF */
    SET_BIT(*flags, 2, __builtin_parity(result[0])); /* PF */
    SET_BIT(*flags, 6, zero); /* ZF */
    SET_BIT(*flags, 7, !!(result[op1_len - 1] & 0x80)); /* SF */
    SET_BIT(*flags, 11, 0); /* OF */

    return *(ULONGLONG*)result;
}

static ULONGLONG INSTR_or(DWORD *flags, BYTE *op1, BYTE op1_len, BYTE *op2, BYTE op2_len)
{
    BYTE op2_val[8], result[8];
    BOOL zero = TRUE;

    if (op1_len > 8 || op2_len > op1_len)
        return 0;

    /* sign extend op2 to op1_len*/
    if (op1_len != op2_len)
    {
        memcpy(op2_val, op2, op2_len);
        op2 = op2_val;
        memset(&op2[op2_len], !!(op2[op2_len - 1] & 0x80), op1_len - op2_len);
    }

    for (unsigned int i = 0; i < op1_len; i++)
    {
        result[i] = op1[i] | op2[i];
        if (result[i])
            zero = FALSE;
    }

    SET_BIT(*flags, 0, 0); /* CF */
    SET_BIT(*flags, 2, __builtin_parity(result[0])); /* PF */
    SET_BIT(*flags, 6, zero); /* ZF */
    SET_BIT(*flags, 7, !!(result[op1_len - 1] & 0x80)); /* SF */
    SET_BIT(*flags, 11, 0); /* OF */

    return *(ULONGLONG*)result;
}

static ULONGLONG INSTR_xor(DWORD *flags, BYTE *op1, BYTE op1_len, BYTE *op2, BYTE op2_len)
{
    BYTE op2_val[8], result[8];
    BOOL zero = TRUE;

    if (op1_len > 8 || op2_len > op1_len)
        return 0;

    /* sign extend op2 to op1_len*/
    if (op1_len != op2_len)
    {
        memcpy(op2_val, op2, op2_len);
        op2 = op2_val;
        memset(&op2[op2_len], !!(op2[op2_len - 1] & 0x80), op1_len - op2_len);
    }

    for (unsigned int i = 0; i < op1_len; i++)
    {
        result[i] = op1[i] ^ op2[i];
        if (result[i])
            zero = FALSE;
    }

    SET_BIT(*flags, 0, 0); /* CF */
    SET_BIT(*flags, 2, __builtin_parity(result[0])); /* PF */
    SET_BIT(*flags, 6, zero); /* ZF */
    SET_BIT(*flags, 7, !!(result[op1_len - 1] & 0x80)); /* SF */
    SET_BIT(*flags, 11, 0); /* OF */

    return *(ULONGLONG*)result;
}

#undef SET_BIT


static void fake_syscall_function(void)
{
    TRACE("() stub\n");
}


/***********************************************************************
 *           emulate_instruction
 *
 * Emulate a privileged instruction.
 * Returns exception continuation status.
 */
static DWORD emulate_instruction( EXCEPTION_RECORD *rec, CONTEXT *context )
{
    static const char *reg_names[16] = { "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
                                         "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15" };
    int prefix, segprefix, repprefix, prefixlen, len, long_op, long_addr;
    struct ex_prefix ex_pfx = {0};
    int ex_pfx_len;
    BYTE *instr;

    long_op = long_addr = 1;
    instr = (BYTE *)context->Rip;
    if (!instr) return ExceptionContinueSearch;

    TRACE("RIP %p %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n", instr, instr[0], instr[1], instr[2], instr[3], instr[4], instr[5], instr[6], instr[7], instr[8], instr[9], instr[10], instr[11]);
    current_rip = context->Rip;

    /* First handle any possible prefix */

    segprefix = -1;  /* no seg prefix */
    repprefix = 0;
    prefix = 1;
    prefixlen = 0;
    while(prefix)
    {
        switch(*instr)
        {
        case 0x2e:
            segprefix = context->SegCs;
            break;
        case 0x36:
            segprefix = context->SegSs;
            break;
        case 0x3e:
            segprefix = context->SegDs;
            break;
        case 0x26:
            segprefix = context->SegEs;
            break;
        case 0x64:
            segprefix = context->SegFs;
            break;
        case 0x65:
            segprefix = context->SegGs;
            break;
        case 0x66:
            long_op = !long_op;  /* opcode size prefix */
            break;
        case 0x67:
            long_addr = !long_addr;  /* addr size prefix */
            break;
        case 0x40:  /* rex */
        case 0x41:
        case 0x42:
        case 0x43:
        case 0x44:
        case 0x45:
        case 0x46:
        case 0x47:
        case 0x48:
        case 0x49:
        case 0x4a:
        case 0x4b:
        case 0x4c:
        case 0x4d:
        case 0x4e:
        case 0x4f:
        case 0xc4: /* vex */
        case 0xc5:
            ex_pfx = get_ex_prefix(instr, &ex_pfx_len);
            prefixlen += ex_pfx_len;
            instr += ex_pfx_len;
            continue;
        case 0xf0:  /* lock */
            break;
        case 0xf2:  /* repne */
            repprefix = 0xf2;
            break;
        case 0xf3:  /* repe */
            repprefix = 0xf3;
            break;
        default:
            prefix = 0;  /* no more prefixes */
            break;
        }
        if (prefix)
        {
            instr++;
            prefixlen++;
        }
    }

    if (ex_pfx.l && !(context->ContextFlags & CONTEXT_XSTATE))
    {
        ERR("ymm registers not supported\n");
        return ExceptionContinueSearch;
    }

    /* Now look at the actual instruction */
    if (ex_pfx.m == 1)
        goto extended;

    switch(*instr)
    {
    case 0x0f: /* extended instruction */
    instr++;
    prefixlen++;
    extended:
        switch(*instr)
        {
        case 0x11: /* movups */
        {
            BYTE *data = INSTR_GetOperandAddr( context, instr + 1, prefixlen + 1, long_addr,
                                               ex_pfx, segprefix, &len);
            int reg = REGMODRM_REG( instr[1], ex_pfx );

            if (!(write_emulated_memory(data, &get_xmm_reg(context, reg)->Low, 8)))
                break;
            data+=8;
            if (!(write_emulated_memory(data, &get_xmm_reg(context, reg)->High, 8)))
                break;
            data+=8;

            if (ex_pfx.l)
            {
                if (!(write_emulated_memory(data, &get_ymm_reg(context, reg)->Low, 8)))
                    break;
                data+=8;
                if (!(write_emulated_memory(data, &get_ymm_reg(context, reg)->High, 8)))
                    break;
                data+=8;
            }

            context->Rip += prefixlen + len + 1;
            return ExceptionContinueExecution;
        }
        case 0x20: /* mov crX, Rd */
        {
            int reg = REGMODRM_REG( instr[1], ex_pfx );
            int rm = REGMODRM_RM( instr[1], ex_pfx );
            DWORD64 *data = get_int_reg( context, rm );
            TRACE( "mov cr%u,%s at %lx\n", reg, reg_names[rm], context->Rip );
            switch (reg)
            {
            case 0: *data = 0x10; break; /* FIXME: set more bits ? */
            case 2: *data = 0; break;
            case 3: *data = 0; break;
            case 4: *data = 0; break;
            case 8: *data = 0; break;
            default: return ExceptionContinueSearch;
            }
            context->Rip += prefixlen + 2;
            return ExceptionContinueExecution;
        }
        case 0x21: /* mov drX, Rd */
        {
            int reg = REGMODRM_REG( instr[1], ex_pfx );
            int rm = REGMODRM_RM( instr[1], ex_pfx );
            DWORD64 *data = get_int_reg( context, rm );
            TRACE( "mov dr%u,%s at %lx\n", reg, reg_names[rm], context->Rip );
            switch (reg)
            {
            case 0: *data = context->Dr0; break;
            case 1: *data = context->Dr1; break;
            case 2: *data = context->Dr2; break;
            case 3: *data = context->Dr3; break;
            case 4:  /* dr4 and dr5 are obsolete aliases for dr6 and dr7 */
            case 6: *data = context->Dr6; break;
            case 5:
            case 7: *data = 0x400; break;
            default: return ExceptionContinueSearch;
            }
            context->Rip += prefixlen + 2;
            return ExceptionContinueExecution;
        }
        case 0x22: /* mov Rd, crX */
        {
            int reg = REGMODRM_REG( instr[1], ex_pfx );
            int rm = REGMODRM_RM( instr[1], ex_pfx );
            DWORD64 *data = get_int_reg( context, rm );
            TRACE( "mov %s,cr%u at %lx, %s=%lx\n", reg_names[rm], reg, context->Rip, reg_names[rm], *data );
            switch (reg)
            {
            case 0: break;
            case 2: break;
            case 3: break;
            case 4: break;
            case 8: break;
            default: return ExceptionContinueSearch;
            }
            context->Rip += prefixlen + 2;
            return ExceptionContinueExecution;
        }
        case 0x23: /* mov Rd, drX */
        {
            int reg = REGMODRM_REG( instr[1], ex_pfx );
            int rm = REGMODRM_RM( instr[1], ex_pfx );
            DWORD64 *data = get_int_reg( context, rm );
            TRACE( "mov %s,dr%u at %lx, %s=%lx\n", reg_names[rm], reg, context->Rip, reg_names[rm], *data );
            switch (reg)
            {
            case 0: context->Dr0 = *data; break;
            case 1: context->Dr1 = *data; break;
            case 2: context->Dr2 = *data; break;
            case 3: context->Dr3 = *data; break;
            case 4:  /* dr4 and dr5 are obsolete aliases for dr6 and dr7 */
            case 6: context->Dr6 = *data; break;
            case 5:
            case 7: context->Dr7 = *data; break;
            default: return ExceptionContinueSearch;
            }
            context->Rip += prefixlen + 2;
            return ExceptionContinueExecution;
        }
        case 0x32: /* rdmsr */
        {
            ULONG reg = context->Rcx;
            TRACE("rdmsr CR 0x%08x\n", reg);
            switch (reg)
            {
            case MSR_LSTAR:
            {
                ULONG_PTR syscall_address = (ULONG_PTR)fake_syscall_function;
                context->Rdx = (ULONG)(syscall_address >> 32);
                context->Rax = (ULONG)syscall_address;
                break;
            }
            default:
                FIXME("reg %#x, returning 0.\n", reg);
                context->Rdx = 0;
                context->Rax = 0;
                break;
            }
            context->Rip += prefixlen + 1;
            return ExceptionContinueExecution;
        }
        case 0x48: /* cmovs r, [r] */
        case 0x49: /* cmovns r, [r] */
        {
            BYTE *data = INSTR_GetOperandAddr( context, instr + 1, prefixlen + 1, long_addr,
                                               ex_pfx, segprefix, &len);
            unsigned int data_size = get_op_size(long_op, ex_pfx);

            if ((*instr == 0x48) == !!(context->EFlags & 0x0080)) /* SF */
            {
                BYTE buf[8];
                if (!(read_emulated_memory(buf, data, data_size)))
                    return ExceptionContinueSearch;
                store_reg_word( context, instr[1], buf, long_op, ex_pfx, INSTR_OP_MOV );
            }
            TRACE("cmov(n)s r, [r]\n");
            context->Rip += prefixlen + len + 1;
            return ExceptionContinueExecution;
        }
        case 0x6f: /* movdqu */
        {
            BYTE *data = INSTR_GetOperandAddr( context, instr + 1, prefixlen + 1, long_addr,
                                               ex_pfx, segprefix, &len );
            unsigned int data_size = 16;
            int reg = REGMODRM_REG( instr[1], ex_pfx );

            if (!(read_emulated_memory(get_xmm_reg(context, reg), data, data_size)))
                break;
            if (ex_pfx.l && !(read_emulated_memory(get_ymm_reg(context, reg), data + 16, data_size)))
                break;

            context->Rip += prefixlen + len + 1;
            return ExceptionContinueExecution;
        }
        case 0x74: /* VPCMPEQB */
        {
            BYTE *source2_addr = INSTR_GetOperandAddr( context, instr + 1, prefixlen + 1, long_addr,
                                              ex_pfx, segprefix, &len );
            unsigned int data_size = ex_pfx.l ? 32 : 16;
            int source1_reg = ex_pfx.v;
            int dest_reg = REGMODRM_REG( instr[1], ex_pfx );
            BYTE dest[32], source1[32], source2[32];

            /* non VEX variant unsupported */
            if (prefixlen < 2)
                break;

            memcpy(source1, get_xmm_reg(context, source1_reg), 16);
            if (data_size == 32)
                memcpy(source1 + 16, get_ymm_reg(context, source1_reg), 16);

            if (!(read_emulated_memory(source2, source2_addr, data_size)))
                break;

            for (unsigned int i = 0; i < data_size; i++)
                dest[i] = source1[i] == source2[i] ? 0xff : 0;

            memcpy(get_xmm_reg(context, dest_reg), dest, 16);
            if (data_size == 32)
                memcpy(get_ymm_reg(context, dest_reg), dest + 16, 16);

            context->Rip += prefixlen + len + 1;
            return ExceptionContinueExecution;
        }
        case 0x7f:
        {
            BYTE *data = INSTR_GetOperandAddr( context, instr + 1, prefixlen + 1, long_addr,
                                               ex_pfx, segprefix, &len );
            unsigned int data_size = ex_pfx.l ? 32 : 16;
            int reg = REGMODRM_REG (instr[1], ex_pfx);
            BYTE full_reg[32];

            memcpy(full_reg, get_xmm_reg(context, reg), 16);
            if (ex_pfx.l)
                memcpy(full_reg + 16, get_ymm_reg(context, reg), 16);

            if (!(write_emulated_memory(data, full_reg, data_size)))
                break;

            context->Rip += prefixlen + len + 1;
            return ExceptionContinueExecution;
        }
        case 0xb0:
        case 0xb1: /* cmpxchg*/
        {
            BYTE *data = INSTR_GetOperandAddr( context, instr + 1, prefixlen + 1, long_addr,
                                               ex_pfx, segprefix, &len );
            unsigned int data_size = (*instr == 0xb1) ? get_op_size(long_op, ex_pfx) : 1;
            int reg = REGMODRM_REG( instr[1], ex_pfx );
            BYTE op1[8];
            BYTE *op2 = (BYTE *)get_int_reg( context, reg );

            if (read_emulated_memory(op1, data, data_size))
            {
                if (!(INSTR_sub(&context->EFlags, op1, data_size, (BYTE*) &context->Rax, data_size)))
                {
                    /* accumulator == op1 */
                    if (!(write_emulated_memory(data, op2 + (8 - data_size), data_size)))
                        return ExceptionContinueSearch;
                }
                else
                {
                    memcpy(&context->Rax + (8 - data_size), op1, data_size);
                }
                context->Rip += prefixlen + len + 1;
                return ExceptionContinueExecution;
            }
            break;
        }
        case 0xb6: /* movzx Eb, Gv */
        case 0xb7: /* movzx Ew, Gv */
        {
            BYTE *data = INSTR_GetOperandAddr( context, instr + 1, prefixlen + 1, long_addr,
                                               ex_pfx, segprefix, &len );
            unsigned int data_size = (*instr == 0xb7) ? 2 : 1;
            BYTE temp[8] = {0};

            if (read_emulated_memory(temp, data, data_size))
            {
                store_reg_word( context, instr[1], temp, long_op, ex_pfx, INSTR_OP_MOV );
                context->Rip += prefixlen + len + 1;
                return ExceptionContinueExecution;
            }
            break;  /* Unable to emulate it */
        }
        case 0xbe:
        case 0xbf: /* movsx */
        {
            BYTE *data = INSTR_GetOperandAddr( context, instr + 1, prefixlen + 1, long_addr,
                                               ex_pfx, segprefix, &len );
            unsigned int data_size = (*instr == 0xbf) ?  2 : 1;
            BYTE buf[8];

            if (read_emulated_memory(buf, data, data_size))
            {
                memset(buf + data_size, buf[data_size - 1] & 0x80, get_op_size(long_op, ex_pfx) - data_size);
                store_reg_word( context, instr[1], buf, long_op, ex_pfx, INSTR_OP_MOV );
                context->Rip += prefixlen + len + 1;
                return ExceptionContinueExecution;
            }
            break;
        }
        case 0xc0:
        case 0xc1: /* xadd */
        {
            BYTE *data = INSTR_GetOperandAddr( context, instr + 1, prefixlen + 1, long_addr,
                                               ex_pfx, segprefix, &len );
            unsigned int data_size = (*instr == 0xc1) ? get_op_size(long_op, ex_pfx) : 1;
            int reg = REGMODRM_REG( instr[1], ex_pfx );
            BYTE op1[8];
            BYTE *op2 = (BYTE *)get_int_reg( context, reg );

            if (read_emulated_memory(op1, data, data_size))
            {
                ULONGLONG buf = INSTR_add(&context->EFlags, op1, data_size, op2, data_size);
                if (write_emulated_memory(data, (BYTE*)&buf, data_size))
                {
                    TRACE("xadd\n");
                    switch (*instr)
                    {
                    case 0xc0: store_reg_byte(context, instr[1], op1, ex_pfx, INSTR_OP_MOV); break;
                    case 0xc1: store_reg_word(context, instr[1], op1, long_op, ex_pfx, INSTR_OP_MOV); break;
                    }

                    context->Rip += prefixlen + len + 1;

                    return ExceptionContinueExecution;
                }
            }

            break;
        }
        case 0xc3: /* movnti */
        {
            BYTE *data = INSTR_GetOperandAddr( context, instr + 1, prefixlen + 1, long_addr,
                                               ex_pfx, segprefix, &len );

            unsigned int data_size = get_op_size(1, ex_pfx );
            DWORD64 *reg_pointer = get_int_reg(context, REGMODRM_REG( instr[1], ex_pfx));

            if (write_emulated_memory(data, reg_pointer, data_size))
            {
                context->Rip += prefixlen + 1 + len;
                return ExceptionContinueExecution;
            }
            break;
        }
        }
        break;  /* Unable to emulate it */

    case 0x01: /* add */
    {
        BYTE *data = INSTR_GetOperandAddr(context, &instr[1], prefixlen + 1, long_addr, ex_pfx, segprefix, &len);
        unsigned int data_size = get_op_size( long_op, ex_pfx);
        int reg = REGMODRM_REG( instr[1], ex_pfx );
        BYTE op1[8];
        BYTE *op2 = (BYTE *)get_int_reg( context, reg );

        if (read_emulated_memory(op1, data, data_size))
        {
            ULONGLONG buf = INSTR_add(&context->EFlags, op1, data_size, op2, data_size);

            if (write_emulated_memory(data, &buf, data_size))
            {
                TRACE("add r/ r\n");
                context->Rip += prefixlen + len + 1;
                return ExceptionContinueExecution;
            }
        }
        break;
    }
    case 0x02:
    case 0x03: /* add */
    {
        BYTE *data = INSTR_GetOperandAddr(context, &instr[1], prefixlen + 1, long_addr, ex_pfx, segprefix, &len);
        unsigned int data_size = (*instr == 0x03) ? get_op_size( long_op, ex_pfx ) : 1;
        int reg = REGMODRM_REG( instr[1], ex_pfx );
        BYTE *op1 = (BYTE *)get_int_reg( context, reg );
        BYTE op2[8];

        if (read_emulated_memory(op2, data, data_size))
        {
            ULONGLONG buf = INSTR_add(&context->EFlags, op1, data_size, op2, data_size);
            TRACE("add r [r]\n");
            switch (*instr)
            {
            case 0x02: store_reg_byte(context, instr[1], (BYTE *) &buf, ex_pfx, INSTR_OP_MOV); break;
            case 0x03: store_reg_word(context, instr[1], (BYTE *) &buf, long_op, ex_pfx, INSTR_OP_MOV); break;
            }
            context->Rip += prefixlen + len + 1;
            return ExceptionContinueExecution;
        }
        break;
    }

    case 0x08:
    case 0x09: /* or */
    {
        BYTE *data = INSTR_GetOperandAddr(context, &instr[1], prefixlen + 1, long_addr, ex_pfx, segprefix, &len);
        unsigned int data_size = (*instr == 0x09) ? get_op_size(long_op, ex_pfx) : 1;
        int reg = REGMODRM_REG( instr[1], ex_pfx );
        BYTE op1[8];
        BYTE *op2 = (BYTE *)get_int_reg( context, reg );

        if (read_emulated_memory(op1, data, data_size))
        {
            ULONGLONG buf = INSTR_or(&context->EFlags, op1, data_size, op2, data_size);

            if (write_emulated_memory(data, &buf, data_size))
            {
                TRACE("or r/ r\n");
                context->Rip += prefixlen + len + 1;
                return ExceptionContinueExecution;
            }
        }

        break;
    }

    case 0x28:
    case 0x29:
    {
        BYTE *data = INSTR_GetOperandAddr(context, &instr[1], prefixlen + 1, long_addr, ex_pfx, segprefix, &len);
        unsigned int data_size = (*instr == 0x29) ? get_op_size(long_op, ex_pfx) : 1;
        int reg = REGMODRM_REG( instr[1], ex_pfx );
        BYTE op1[8];
        BYTE *op2 = (BYTE*)get_int_reg( context, reg );

        if (read_emulated_memory(op1, data, data_size))
        {
            ULONGLONG buf = INSTR_sub(&context->EFlags, op1, data_size, op2, data_size);

            if (write_emulated_memory(data, &buf, data_size))
            {
                TRACE("sub r/ r, buf = %016lx\n", buf);
                context->Rip += prefixlen + len + 1;
                return ExceptionContinueExecution;
            }
        }

        break;
    }

    case 0x32:
    {
        BYTE *data = INSTR_GetOperandAddr(context, &instr[1], prefixlen + 1, long_addr, ex_pfx, segprefix, &len);
        unsigned int data_size = (*instr == 0x33) ? get_op_size( long_op, ex_pfx ) : 1;
        int reg = REGMODRM_REG( instr[1], ex_pfx );
        BYTE *op1 = (BYTE *)get_int_reg( context, reg );
        BYTE op2[8];

        if (read_emulated_memory(op2, data, data_size))
        {
            ULONGLONG buf = INSTR_xor(&context->EFlags, op1, data_size, op2, data_size);
            TRACE("xor r [r]\n");
            switch (*instr)
            {
            case 0x02: store_reg_byte(context, instr[1], (BYTE *) &buf, ex_pfx, INSTR_OP_MOV); break;
            case 0x03: store_reg_word(context, instr[1], (BYTE *) &buf, long_op, ex_pfx, INSTR_OP_MOV); break;
            }
            context->Rip += prefixlen + len + 1;
            return ExceptionContinueExecution;
        }
        break;
    }

    case 0x38:
    case 0x39: /* cmp */
    {
        BYTE *data = INSTR_GetOperandAddr(context, &instr[1], prefixlen + 1, long_addr, ex_pfx, segprefix, &len);
        unsigned int data_size = (*instr == 0x39) ? get_op_size( long_op, ex_pfx ) : 1;
        int reg = REGMODRM_REG( instr[1], ex_pfx );
        int rm = REGMODRM_RM( instr[1], ex_pfx );
        BYTE op1[8];
        BYTE *op2 = (BYTE *)get_int_reg( context, reg );

        if (read_emulated_memory(op1, data, data_size))
        {
            TRACE("cmp %u-byte PTR [%s], %s\n", data_size, reg_names[rm], reg_names[reg]);
            INSTR_sub(&context->EFlags, op1, data_size, op2, data_size);

            context->Rip += prefixlen + len + 1;
            return ExceptionContinueExecution;
        }
        break;  /* Unable to emulate it */
    }
    case 0x3b: /* cmp */
    {
        BYTE *data = INSTR_GetOperandAddr(context, &instr[1], prefixlen + 1, long_addr, ex_pfx, segprefix, &len);
        unsigned int data_size = get_op_size( long_op, ex_pfx );
        int reg = REGMODRM_REG( instr[1], ex_pfx );
        int rm = REGMODRM_RM( instr[1], ex_pfx );
        BYTE *op1 = (BYTE *)get_int_reg( context, reg );
        BYTE op2[8];

        if (read_emulated_memory(op2, data, data_size))
        {
            TRACE("cmp %s, %u-byte PTR[%s]\n", reg_names[reg], data_size, reg_names[rm]);
            INSTR_sub(&context->EFlags, op1, data_size, op2, data_size);

            context->Rip += prefixlen + len + 1;
            return ExceptionContinueExecution;
        }
        break;  /* Unable to emulate it */
    }
    case 0x63: /* movsxd */
    {
        BYTE *data = INSTR_GetOperandAddr( context, instr + 1, prefixlen +1, long_addr,
                                           ex_pfx, segprefix, &len );
        unsigned int data_size = long_op ? 4 : 2;
        BYTE buf[8];

        if (read_emulated_memory(buf, data, data_size))
        {
            memset(buf + data_size, buf[data_size - 1] & 0x80, get_op_size(long_op, ex_pfx) - data_size);
            store_reg_word( context, instr[1], buf, long_op, ex_pfx, INSTR_OP_MOV );
            context->Rip += prefixlen + len + 1;
            return ExceptionContinueExecution;
        }
        break;
    }
    case 0x80:
    case 0x81:
    case 0x83:
    {
        BYTE *data = INSTR_GetOperandAddr(context, &instr[1], prefixlen + 1, long_addr, ex_pfx, segprefix, &len);
        unsigned int data_size = (*instr == 0x80) ? 1 : get_op_size( long_op, ex_pfx );
        int reg = REGMODRM_REG( instr[1], ex_pfx );
        int rm = REGMODRM_RM( instr[1], ex_pfx );
        ULONG imm_size = (*instr == 0x81) ? (long_op ? 4 : 2) : 1;
        BYTE op1[8];

        if (read_emulated_memory(op1, data, data_size))
        {
            switch(reg)
            {
            case 0x00: /* add */
            {
                ULONGLONG buf = INSTR_add(&context->EFlags, op1, data_size, &instr[1 + len], imm_size);
                if (write_emulated_memory(data, &buf, data_size))
                {
                    TRACE("add %u-byte PTR [%s + ?], 0x%02x\n", data_size, reg_names[rm], instr[1 + len]);
                    context->Rip += prefixlen + 1 + len + imm_size;
                    return ExceptionContinueExecution;
                }
                break;
            }
            case 0x01: /* or */
            {
                ULONGLONG buf = INSTR_or(&context->EFlags, op1, data_size, &instr[1 + len], imm_size);
                if (write_emulated_memory(data, &buf, data_size))
                {
                    TRACE("or %u-byte PTR [%s + ?], 0x%02x\n", data_size, reg_names[rm], instr[1 + len]);
                    context->Rip += prefixlen + 1 + len + imm_size;
                    return ExceptionContinueExecution;
                }
                break;
            }
            case 0x04: /* and */
            {
                ULONGLONG buf = INSTR_and(&context->EFlags, op1, data_size, &instr[1 + len], imm_size);
                if (write_emulated_memory(data, &buf, data_size))
                {
                    TRACE("and %u-byte PTR [%s + ?], 0x%02x\n", data_size, reg_names[rm], instr[1 + len]);
                    context->Rip += prefixlen + 1 + len + imm_size;
                    return ExceptionContinueExecution;
                }
                break;  /* Unable to emulate it */
            }
            case 0x05: /* sub */
            {
                ULONGLONG buf = INSTR_sub(&context->EFlags, op1, data_size, &instr[1 + len], imm_size);
                if (write_emulated_memory(data, &buf, data_size))
                {
                    TRACE("sub %u-byte PTR [%s + ?], 0x%02x\n", data_size, reg_names[rm], instr[1 + len]);
                    context->Rip += prefixlen + 1 + len + imm_size;
                    return ExceptionContinueExecution;
                }
                break;
            }
            case 0x06: /* xor */
            {
                ULONGLONG buf = INSTR_xor(&context->EFlags, op1, data_size, &instr[1 + len], imm_size);
                if (write_emulated_memory(data, &buf, data_size))
                {
                    TRACE("xor %u-byte PTR [%s + ?], 0x%02x\n", data_size, reg_names[rm], instr[1 + len]);
                    context->Rip += prefixlen + 1 + len + imm_size;
                    return ExceptionContinueExecution;
                }
                break;
            }
            case 0x07: /* cmp */
            {
                TRACE("cmp %u-byte PTR [%s + ?], 0x%02x\n", data_size, reg_names[rm], instr[1 + len]);
                INSTR_sub(&context->EFlags, op1, data_size, &instr[1 + len], imm_size);

                context->Rip += prefixlen + 1 + len + imm_size;
                return ExceptionContinueExecution;
                break;  /* Unable to emulate it */
            }
            }
        }
        break;  /* Unable to emulate it */
    }
    case 0x86:
    case 0x87: /* xchg */
    {
        BYTE *data = INSTR_GetOperandAddr( context, instr + 1, prefixlen + 1, long_addr,
                                           ex_pfx, segprefix, &len);
        unsigned int data_size = (*instr == 0x87) ? get_op_size(long_op, ex_pfx) : 1;
        int reg = REGMODRM_REG( instr[1], ex_pfx );
        BYTE *arg2 = (BYTE *)get_int_reg( context, reg );
        DWORD64 temp;
        if (!(read_emulated_memory(&temp, data, data_size)))
            return ExceptionContinueSearch;
        if (!(write_emulated_memory(data, arg2 + (8 - data_size), data_size)))
            return ExceptionContinueSearch;
        memcpy(arg2 + (8 - data_size), &temp, data_size);

        context->Rip += prefixlen + len + 1;
        return ExceptionContinueExecution;
    }
    case 0x88:
    case 0x89: /* mov [r], r*/
    {
        BYTE *data = INSTR_GetOperandAddr( context, instr + 1, prefixlen + 1, long_addr,
                                           ex_pfx, segprefix, &len);
        unsigned int data_size = (*instr == 0x89) ? get_op_size( long_op, ex_pfx ) : 1;
        DWORD64 *reg_pointer = get_int_reg(context, REGMODRM_REG( instr[1], ex_pfx ));

        TRACE("mov [r], r\n");

        if (write_emulated_memory(data, reg_pointer, data_size))
        {
            context->Rip += prefixlen + 1 + len;
            return ExceptionContinueExecution;
        }

        break;  /* Unable to emulate it */
    }
    case 0x8a: /* mov Eb, Gb */
    case 0x8b: /* mov Ev, Gv */
    case 0x0b: /* or  Ev, Gv */
    case 0x33: /* xor Ev, Gv */
    {
        BYTE *data = INSTR_GetOperandAddr( context, instr + 1, prefixlen + 1, long_addr,
                                           ex_pfx, segprefix, &len );
        unsigned int data_size = (*instr == 0x8b) ? get_op_size( long_op, ex_pfx ) : 1;

        BYTE temp[8];
        if (read_emulated_memory(temp, data, data_size))
        {
            switch (*instr)
            {
                case 0x8a:
                    store_reg_byte( context, instr[1], temp, ex_pfx, INSTR_OP_MOV );
                    break;
                case 0x8b:
                    store_reg_word( context, instr[1], temp, long_op, ex_pfx, INSTR_OP_MOV );
                    break;
                case 0x0b:
                    store_reg_word( context, instr[1], temp, long_op, ex_pfx, INSTR_OP_OR );
                    break;
                case 0x33:
                    store_reg_word( context, instr[1], temp, long_op, ex_pfx, INSTR_OP_XOR );
                    break;
            }
            context->Rip += prefixlen + len + 1;
            return ExceptionContinueExecution;
        }
        break;  /* Unable to emulate it */
    }

    case 0xa0: /* mov Ob, AL */
    case 0xa1: /* mov Ovqp, rAX */
    {
        BYTE *data = (BYTE *)(long_addr ? *(DWORD64 *)(instr + 1) : *(DWORD *)(instr + 1));
        unsigned int data_size = (*instr == 0xa1) ? get_op_size( long_op, ex_pfx ) : 1;
        BYTE temp[8];
        len = long_addr ? sizeof(DWORD64) : sizeof(DWORD);

        if (read_emulated_memory(temp, data, data_size))
        {
            memcpy( &context->Rax, temp, data_size );
            context->Rip += prefixlen + len + 1;
            return ExceptionContinueExecution;
        }
        break;  /* Unable to emulate it */
    }

    case 0xaa: /* STOSB */
    case 0xab:
    {
        unsigned int data_size = (*instr == 0xab) ? get_op_size( long_op, ex_pfx ) : 1;

        if ((repprefix == 0xf2 || repprefix == 0xf3) && context->Rcx == 0)
            break;

        again1:
        if (write_emulated_memory((BYTE*)(context->Rdi & (long_addr ? (DWORD64)-1 : (DWORD)-1)), &context->Rax, data_size))
        {
            if (context->EFlags & 0x400) context->Rdi -= data_size; else context->Rdi += data_size;

            if (repprefix == 0xf2 || repprefix == 0xf3)
            {
                context->Rcx--;
                if (context->Rax != 0)
                    goto again1;
            }

            context->Rip += prefixlen + 1;
            return ExceptionContinueExecution;
        }

        break;
    }

    case 0xae: /* SCAS */
    case 0xaf:
    {
        BYTE op2[8];
        unsigned int data_size = (*instr == 0xaf) ? get_op_size( long_op, ex_pfx ) : 1;

        if ((repprefix == 0xf2 || repprefix == 0xf3) && context->Rcx == 0)
            break;

        again2:
        if (read_emulated_memory(op2, (BYTE*)(context->Rdi & (long_addr ? (DWORD64)-1 : (DWORD)-1)), data_size))
        {
            INSTR_sub(&context->EFlags, (BYTE*)&context->Rax, data_size, op2, data_size);
            if (context->EFlags & 0x400) context->Rdi -= data_size; else context->Rdi += data_size;

            if (repprefix == 0xf2 || repprefix == 0xf3)
            {
                context->Rcx--;
                if (context->Rax != 0 || (*instr == 0xf3) ==  !!(context->EFlags & 0x40))
                goto again2;
            }

            context->Rip += prefixlen + 1;
            return ExceptionContinueExecution;
        }

        break;
    }

    case 0xc6:
    case 0xc7:
    {
        BYTE *data = INSTR_GetOperandAddr(context, &instr[1], prefixlen + 1, long_addr, ex_pfx, segprefix, &len);
        unsigned int data_size = (*instr == 0xc7) ? get_op_size( long_op, ex_pfx ) : 1;
        int reg = REGMODRM_REG( instr[1], ex_pfx );
        ULONG imm_size = (*instr == 0xc7) ? (long_op ? 4 : 2) : 1;
        BYTE imm[8];

        switch (reg)
        {
            case 0x0: /* MOV [r], imm */
            {
                TRACE("mov [r], imm\n");

                memcpy(imm, instr + 1 + len, imm_size);
                memset(&imm[imm_size], imm[imm_size - 1] & 0x80, data_size - imm_size);

                if (write_emulated_memory(data, imm, data_size))
                {
                    context->Rip += prefixlen + 1 + len + imm_size;
                    return ExceptionContinueExecution;
                }
            }
        }
        break;  /* Unable to emulate it */
    }

    case 0xf6:
    case 0xf7:
    {
        BYTE *data = INSTR_GetOperandAddr(context, &instr[1], prefixlen + 1, long_addr, ex_pfx, segprefix, &len);
        unsigned int data_size = (*instr == 0xf7) ? get_op_size( long_op, ex_pfx ) : 1;
        int reg = REGMODRM_REG( instr[1], ex_pfx );
        ULONG imm_size = (*instr == 0xc7) ? (long_op ? 4 : 2) : 1;

        switch (reg)
        {
            case 0x0: /* test [r], imm */
            {
                TRACE("test [r], imm\n");

                INSTR_and(&context->EFlags, data, data_size, &instr[1 + len], imm_size);
                context->Rip += prefixlen + 1 + len + imm_size;
                return ExceptionContinueExecution;
            }
        }
        break;
    }

    case 0xfa: /* cli */
    case 0xfb: /* sti */
        context->Rip += prefixlen + 1;
        return ExceptionContinueExecution;
    case 0xff: /* near call */
    {
        BYTE *data = INSTR_GetOperandAddr(context, &instr[1], prefixlen + 1, long_addr, ex_pfx, segprefix, &len);
        DWORD64 func_addr;

        if (read_emulated_memory(&func_addr, data, sizeof(DWORD64)))
        {
            TRACE("call %lx\n", func_addr);
            context->Rsp -= sizeof(DWORD64);
            *(DWORD64*)context->Rsp = context->Rip + prefixlen + 1 + len;
            context->Rip = func_addr;
            return ExceptionContinueExecution;
        }
        break;
    }
    }
    return ExceptionContinueSearch;  /* Unable to emulate it */
}

DECLARE_CRITICAL_SECTION(emulate_cs);


/***********************************************************************
 *           vectored_handler
 *
 * Vectored exception handler used to emulate protected instructions
 * from 64-bit code.
 */
LONG CALLBACK vectored_handler( EXCEPTION_POINTERS *ptrs )
{
    EXCEPTION_RECORD *record = ptrs->ExceptionRecord;
    CONTEXT *context = ptrs->ContextRecord;

    if (record->ExceptionCode == EXCEPTION_PRIV_INSTRUCTION ||
        record->ExceptionCode == EXCEPTION_ACCESS_VIOLATION ||
        (record->ExceptionCode == EXCEPTION_STACK_OVERFLOW))
    {
        if (record->ExceptionCode == EXCEPTION_ACCESS_VIOLATION && (record->NumberParameters < 2 || !record->ExceptionInformation[1]))
            return ExceptionContinueSearch;

        EnterCriticalSection(&emulate_cs);
        if (emulate_instruction( record, context ) == ExceptionContinueExecution)
        {
            TRACE( "next instruction rip=%016llx\n", context->Rip );
            TRACE( "  rax=%016llx rbx=%016llx rcx=%016llx rdx=%016llx\n",
                   context->Rax, context->Rbx, context->Rcx, context->Rdx );
            TRACE( "  rsi=%016llx rdi=%016llx rbp=%016llx rsp=%016llx\n",
                   context->Rsi, context->Rdi, context->Rbp, context->Rsp );
            TRACE( "   r8=%016llx  r9=%016llx r10=%016llx r11=%016llx\n",
                   context->R8, context->R9, context->R10, context->R11 );
            TRACE( "  r12=%016llx r13=%016llx r14=%016llx r15=%016llx\n",
                   context->R12, context->R13, context->R14, context->R15 );
            LeaveCriticalSection(&emulate_cs);

            return EXCEPTION_CONTINUE_EXECUTION;
        }
        else
        {
            ERR("Unrecognized instruction at %016llx\n", context->Rip);

            ERR( "  rax=%016llx rbx=%016llx rcx=%016llx rdx=%016llx\n",
                   context->Rax, context->Rbx, context->Rcx, context->Rdx );
            ERR( "  rsi=%016llx rdi=%016llx rbp=%016llx rsp=%016llx\n",
                   context->Rsi, context->Rdi, context->Rbp, context->Rsp );
            ERR( "   r8=%016llx  r9=%016llx r10=%016llx r11=%016llx\n",
                   context->R8, context->R9, context->R10, context->R11 );
            ERR( "  r12=%016llx r13=%016llx r14=%016llx r15=%016llx\n",
                   context->R12, context->R13, context->R14, context->R15 );
        }
        LeaveCriticalSection(&emulate_cs);
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

#endif  /* __x86_64__ */
