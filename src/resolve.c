#include "../includes/resolve.h"

const GUID ORCB_GUID = {
    0x18f70770, 0x8e64, 0x11cf,
    { 0x9a, 0xf1, 0x00, 0x20, 0xaf, 0x6e, 0x72, 0xf4 }
};

const IID IID_IUnknown_val = {
    0x00000000, 0x0000, 0x0000,
    { 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46 }
};

pfnNtOpenProcess              _NtOpenProcess              = NULL;
pfnNtClose                    _NtClose                    = NULL;
pfnNtOpenProcessToken         _NtOpenProcessToken         = NULL;
pfnNtDuplicateObject          _NtDuplicateObject          = NULL;
pfnNtDuplicateToken           _NtDuplicateToken           = NULL;
pfnNtQuerySystemInformation   _NtQuerySystemInformation   = NULL;
pfnNtQueryInformationToken    _NtQueryInformationToken    = NULL;
pfnNtProtectVirtualMemory     _NtProtectVirtualMemory     = NULL;
pfnNtWaitForSingleObject      _NtWaitForSingleObject      = NULL;
pfnNtReadFile                 _NtReadFile                 = NULL;
pfnNtSetInformationObject     _NtSetInformationObject     = NULL;
pfnNtQueryObject              _NtQueryObject              = NULL;
pfnNtCreateNamedPipeFile      _NtCreateNamedPipeFile      = NULL;
pfnCreateProcessWithTokenW    _CreateProcessWithTokenW    = NULL;

pfnCoUnmarshalInterface  _CoUnmarshalInterface  = NULL;
pfnCreateStreamOnHGlobal _CreateStreamOnHGlobal = NULL;
pfnCreateObjrefMoniker   _CreateObjrefMoniker   = NULL;
pfnCreateBindCtx         _CreateBindCtx_        = NULL;
pfnCoInitializeEx        _CoInitializeEx        = NULL;
pfnCoUninitialize        _CoUninitialize        = NULL;

BOOL ResolveApis(void) {
    HMODULE hNtdll    = GetModuleHandleA("ntdll.dll");
    HMODULE hAdvapi32 = GetModuleHandleA("advapi32.dll");
    if (!hNtdll || !hAdvapi32) {
        fprintf(stderr, "[-] Failed to get module handles\n");
        return FALSE;
    }

#define RESOLVE_NT(name) \
    _##name = (pfn##name)GetProcAddress(hNtdll, #name); \
    if (!_##name) { fprintf(stderr, "[-] Failed to resolve %s\n", #name); return FALSE; }

    RESOLVE_NT(NtOpenProcess)
    RESOLVE_NT(NtClose)
    RESOLVE_NT(NtOpenProcessToken)
    RESOLVE_NT(NtDuplicateObject)
    RESOLVE_NT(NtDuplicateToken)
    RESOLVE_NT(NtQuerySystemInformation)
    RESOLVE_NT(NtQueryInformationToken)
    RESOLVE_NT(NtProtectVirtualMemory)
    RESOLVE_NT(NtWaitForSingleObject)
    RESOLVE_NT(NtReadFile)
    RESOLVE_NT(NtSetInformationObject)
    RESOLVE_NT(NtQueryObject)
    RESOLVE_NT(NtCreateNamedPipeFile)
#undef RESOLVE_NT

    _CreateProcessWithTokenW = (pfnCreateProcessWithTokenW)GetProcAddress(hAdvapi32, "CreateProcessWithTokenW");
    if (!_CreateProcessWithTokenW) {
        fprintf(stderr, "[-] Failed to resolve CreateProcessWithTokenW\n");
        return FALSE;
    }

    return TRUE;
}

BOOL ResolveCOMApis(void) {
    HMODULE hOle32 = LoadLibraryA("ole32.dll");
    if (!hOle32) return FALSE;
#define RCOM(name) _##name = (pfn##name)GetProcAddress(hOle32, #name); \
    if (!_##name) { fprintf(stderr, "[-] %s not found\n", #name); return FALSE; }
    RCOM(CoUnmarshalInterface)
    RCOM(CreateStreamOnHGlobal)
    RCOM(CreateObjrefMoniker)
    RCOM(CoInitializeEx)
    RCOM(CoUninitialize)
#undef RCOM
    _CreateBindCtx_ = (pfnCreateBindCtx)GetProcAddress(hOle32, "CreateBindCtx");
    if (!_CreateBindCtx_) { fprintf(stderr, "[-] CreateBindCtx not found\n"); return FALSE; }
    return TRUE;
}
