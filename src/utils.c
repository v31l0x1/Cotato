#include "../includes/utils.h"

PVOID GetModuleBaseAndSize(const char *name, SIZE_T *outSize) {
    HMODULE hMod = LoadLibraryA(name);
    if (!hMod) return NULL;

    BYTE *base = (BYTE*)hMod;
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER*)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return NULL;

    IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return NULL;

    if (outSize) *outSize = nt->OptionalHeader.SizeOfImage;
    return base;
}

SIZE_T *SundaySearch(const BYTE *haystack, SIZE_T hLen,
                     const BYTE *needle,   SIZE_T nLen,
                     SIZE_T *outCount) {
    *outCount = 0;
    if (nLen == 0 || hLen < nLen) return NULL;

    SIZE_T shift[256];
    for (int i = 0; i < 256; i++) shift[i] = nLen + 1;
    for (SIZE_T i = 0; i < nLen; i++) shift[needle[i]] = nLen - i;

    SIZE_T  capacity = 16;
    SIZE_T *results  = (SIZE_T*)malloc(capacity * sizeof(SIZE_T));
    if (!results) return NULL;

    SIZE_T pos = 0;
    while (pos + nLen <= hLen) {
        if (memcmp(haystack + pos, needle, nLen) == 0) {
            if (*outCount >= capacity) {
                capacity *= 2;
                SIZE_T *tmp = (SIZE_T*)realloc(results, capacity * sizeof(SIZE_T));
                if (!tmp) { free(results); return NULL; }
                results = tmp;
            }
            results[(*outCount)++] = pos;
        }
        if (pos + nLen < hLen)
            pos += shift[haystack[pos + nLen]];
        else
            break;
    }
    return results;
}
