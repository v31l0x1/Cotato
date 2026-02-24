#pragma once
#include "types.h"

typedef struct _HOOK_CTX {
    PVOID  *DispatchTablePtr;  /* pointer to first entry in MIDL dispatch table */
    PVOID   OriginalFn;        /* saved original first entry                    */
    UINT    ParamCount;        /* UseProtseq param count parsed from ProcString  */
    BOOL    Hooked;
    WCHAR   ClientPipeW[256];  /* ncacn_np binding string                        */
} HOOK_CTX;

extern HOOK_CTX g_HookCtx;

BOOL InitContext(void);
BOOL HookRpc(void);
void RestoreRpc(void);
