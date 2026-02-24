#pragma once
#include "types.h"

PVOID   GetModuleBaseAndSize(const char *name, SIZE_T *outSize);
SIZE_T *SundaySearch(const BYTE *haystack, SIZE_T hLen,
                     const BYTE *needle,   SIZE_T nLen,
                     SIZE_T *outCount);

/* Inline LE read/write helpers */
static inline UINT16 ru16(const BYTE *b, SIZE_T *o) {
    UINT16 v = (UINT16)b[*o] | ((UINT16)b[*o + 1] << 8);
    *o += 2;
    return v;
}
static inline UINT32 ru32(const BYTE *b, SIZE_T *o) {
    UINT32 v = ru16(b, o);
    v |= (UINT32)ru16(b, o) << 16;
    return v;
}
static inline UINT64 ru64(const BYTE *b, SIZE_T *o) {
    UINT64 v = ru32(b, o);
    v |= (UINT64)ru32(b, o) << 32;
    return v;
}
static inline void wu16(BYTE *b, SIZE_T *o, UINT16 v) {
    b[*o] = (BYTE)v; b[*o + 1] = (BYTE)(v >> 8);
    *o += 2;
}
static inline void wu32(BYTE *b, SIZE_T *o, UINT32 v) {
    wu16(b, o, (UINT16)v);
    wu16(b, o, (UINT16)(v >> 16));
}
static inline void wu64(BYTE *b, SIZE_T *o, UINT64 v) {
    wu32(b, o, (UINT32)v);
    wu32(b, o, (UINT32)(v >> 32));
}
