#pragma once
#include "types.h"

typedef struct _PIPE_CTX {
    WCHAR  PipeName[256];
    HANDLE hSystemToken; /* out: duplicated primary SYSTEM token */
    HANDLE hReady;       /* event signalled when search is done  */
} PIPE_CTX;

DWORD WINAPI PipeServerThread(LPVOID param);