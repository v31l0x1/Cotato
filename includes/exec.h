#pragma once
#include "types.h"

BOOL EnablePrivilege(const wchar_t *privName);
BOOL ExecuteCommand(HANDLE hToken, const wchar_t *cmdLine);