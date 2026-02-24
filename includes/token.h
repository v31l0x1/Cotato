#pragma once
#include "types.h"

DWORD  GetTokenIntegrityRID(HANDLE hToken);
BOOL   IsSystemToken(HANDLE hToken);
int    GetTokenImpersonationLevel(HANDLE hToken);
int    GetTokenType(HANDLE hToken);
HANDLE DuplicateAsPrimary(HANDLE hToken);
