#include "../includes/token.h"

DWORD GetTokenIntegrityRID(HANDLE hToken) {
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

BOOL IsSystemToken(HANDLE hToken) {
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
                                     0, 0, 0, 0, 0, 0, 0, &systemSid)) {
            result = EqualSid(tu->User.Sid, systemSid);
            FreeSid(systemSid);
        }
    }
    HeapFree(GetProcessHeap(), 0, buf);
    return result;
}

int GetTokenImpersonationLevel(HANDLE hToken) {
    SECURITY_IMPERSONATION_LEVEL lvl = 0;
    ULONG needed = 0;
    NTSTATUS st = _NtQueryInformationToken(hToken, TokenImpersonationLevel,
                                           &lvl, sizeof(lvl), &needed);
    if (!NT_SUCCESS(st)) return -1;
    return (int)lvl;
}

int GetTokenType(HANDLE hToken) {
    TOKEN_TYPE tt = 0;
    ULONG needed  = 0;
    NTSTATUS st   = _NtQueryInformationToken(hToken, (ULONG)TokenType,
                                              &tt, sizeof(tt), &needed);
    if (!NT_SUCCESS(st)) return -1;
    return (int)tt;
}

HANDLE DuplicateAsPrimary(HANDLE hToken) {
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
