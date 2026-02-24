#include "../includes/exec.h"

BOOL EnablePrivilege(const wchar_t *privName) {
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

BOOL ExecuteCommand(HANDLE hToken, const wchar_t *cmdLine) {
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

    printf("[+] Process PID %lu - output:\n", pi.dwProcessId);

    char buf[1024];
    DWORD bytesRead;
    while (ReadFile(hReadPipe, buf, sizeof(buf) - 1, &bytesRead, NULL) && bytesRead > 0) {
        buf[bytesRead] = '\0';
        printf("%s", buf);
    }

    WaitForSingleObject(pi.hProcess, INFINITE);
    CloseHandle(hReadPipe);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return TRUE;
}
