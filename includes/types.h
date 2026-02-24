#pragma once

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <sddl.h>
#include <objbase.h>
#include <objidl.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "Native.h"

/* =========================================================================
 * Macros
 * ========================================================================= */
#define NT_SUCCESS(s)               ((NTSTATUS)(s) >= 0)
#ifndef STATUS_INFO_LENGTH_MISMATCH
#define STATUS_INFO_LENGTH_MISMATCH 0xC0000004
#endif
#ifndef STATUS_BUFFER_TOO_SMALL
#define STATUS_BUFFER_TOO_SMALL     0xC0000023
#endif

#ifndef OBJ_CASE_INSENSITIVE
#define OBJ_CASE_INSENSITIVE  0x40UL
#endif
#ifndef HEAP_ZERO_MEMORY
#define HEAP_ZERO_MEMORY      0x00000008
#endif

#define TOKEN_ELEVATION_QUERY 0x0020
#ifndef TOKEN_DUPLICATE
#define TOKEN_DUPLICATE       0x0002
#endif
#ifndef TOKEN_QUERY
#define TOKEN_QUERY           0x0008
#endif
#ifndef TOKEN_IMPERSONATE
#define TOKEN_IMPERSONATE     0x0004
#endif
#ifndef TOKEN_ASSIGN_PRIMARY
#define TOKEN_ASSIGN_PRIMARY  0x0001
#endif
#ifndef TOKEN_ALL_ACCESS_P
#define TOKEN_ALL_ACCESS_P    0x000F01FF
#endif

#ifndef PROCESS_DUP_HANDLE
#define PROCESS_DUP_HANDLE         0x0040
#endif
#ifndef PROCESS_QUERY_INFORMATION
#define PROCESS_QUERY_INFORMATION  0x0400
#endif

#ifndef HANDLE_FLAG_INHERIT
#define HANDLE_FLAG_INHERIT   0x00000001
#endif

#ifndef SecurityDelegation
#define SecurityDelegation    4
#endif
#ifndef SecurityImpersonation
#define SecurityImpersonation 2
#endif
#ifndef TokenPrimary
#define TokenPrimary          1
#endif
#ifndef TokenImpersonation
#define TokenImpersonation    2
#endif

/* TokenInformationClass */
#ifndef TokenUser
#define TokenUser             1
#endif
#ifndef TokenType
#define TokenType             8
#endif
#ifndef TokenImpersonationLevel
#define TokenImpersonationLevel 9
#endif
#ifndef TokenIntegrityLevel
#define TokenIntegrityLevel   25
#endif
#ifndef TokenElevationType
#define TokenElevationType    18
#endif

#ifndef TokenElevationTypeFull
#define TokenElevationTypeFull    2
#endif
#define OBJECT_TYPE_TOKEN         0x05

#ifndef CREATE_NO_WINDOW
#define CREATE_NO_WINDOW           0x08000000
#endif
#ifndef CREATE_UNICODE_ENVIRONMENT
#define CREATE_UNICODE_ENVIRONMENT 0x00000400
#endif
#ifndef STARTF_USESTDHANDLES
#define STARTF_USESTDHANDLES       0x00000100
#endif

#define SystemHandleInformation    16
#ifndef SECURITY_MANDATORY_SYSTEM_RID
#define SECURITY_MANDATORY_SYSTEM_RID  0x4000
#endif

typedef LONG NTSTATUS;

extern const GUID ORCB_GUID;
extern const IID  IID_IUnknown_val;

typedef NTSTATUS (NTAPI *pfnNtOpenProcess)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PCLIENT_ID);
typedef NTSTATUS (NTAPI *pfnNtClose)(HANDLE);
typedef NTSTATUS (NTAPI *pfnNtOpenProcessToken)(HANDLE, ACCESS_MASK, PHANDLE);
typedef NTSTATUS (NTAPI *pfnNtDuplicateObject)(HANDLE, HANDLE, HANDLE, PHANDLE, ACCESS_MASK, ULONG, ULONG);
typedef NTSTATUS (NTAPI *pfnNtDuplicateToken)(HANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, BOOLEAN, TOKEN_TYPE, PHANDLE);
typedef NTSTATUS (NTAPI *pfnNtQuerySystemInformation)(ULONG, PVOID, ULONG, PULONG);
typedef NTSTATUS (NTAPI *pfnNtQueryInformationToken)(HANDLE, ULONG, PVOID, ULONG, PULONG);
typedef NTSTATUS (NTAPI *pfnNtProtectVirtualMemory)(HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);
typedef NTSTATUS (NTAPI *pfnNtWaitForSingleObject)(HANDLE, BOOLEAN, PLARGE_INTEGER);
typedef NTSTATUS (NTAPI *pfnNtReadFile)(HANDLE, HANDLE, PVOID, PVOID, PIO_STATUS_BLOCK, PVOID, ULONG, PLARGE_INTEGER, PULONG);
typedef NTSTATUS (NTAPI *pfnNtSetInformationObject)(HANDLE, ULONG, PVOID, ULONG);
typedef NTSTATUS (NTAPI *pfnNtQueryObject)(HANDLE, ULONG, PVOID, ULONG, PULONG);
typedef NTSTATUS (NTAPI *pfnNtCreateNamedPipeFile)(PHANDLE, ULONG, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK, ULONG, ULONG, ULONG, ULONG, ULONG, ULONG, ULONG, ULONG, ULONG, PLARGE_INTEGER);
typedef BOOL (WINAPI *pfnCreateProcessWithTokenW)(HANDLE, DWORD, LPCWSTR, LPWSTR, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION);

/* =========================================================================
 * COM function typedefs
 * ========================================================================= */
typedef HRESULT (STDAPICALLTYPE *pfnCoUnmarshalInterface)(IStream*, REFIID, LPVOID*);
typedef HRESULT (STDAPICALLTYPE *pfnCreateStreamOnHGlobal)(HGLOBAL, BOOL, IStream**);
typedef HRESULT (STDAPICALLTYPE *pfnCreateObjrefMoniker)(LPUNKNOWN, IMoniker**);
typedef HRESULT (STDAPICALLTYPE *pfnCreateBindCtx)(DWORD, IBindCtx**);
typedef HRESULT (STDAPICALLTYPE *pfnCoInitializeEx)(LPVOID, DWORD);
typedef void    (STDAPICALLTYPE *pfnCoUninitialize)(void);

extern pfnNtOpenProcess              _NtOpenProcess;
extern pfnNtClose                    _NtClose;
extern pfnNtOpenProcessToken         _NtOpenProcessToken;
extern pfnNtDuplicateObject          _NtDuplicateObject;
extern pfnNtDuplicateToken           _NtDuplicateToken;
extern pfnNtQuerySystemInformation   _NtQuerySystemInformation;
extern pfnNtQueryInformationToken    _NtQueryInformationToken;
extern pfnNtProtectVirtualMemory     _NtProtectVirtualMemory;
extern pfnNtWaitForSingleObject      _NtWaitForSingleObject;
extern pfnNtReadFile                 _NtReadFile;
extern pfnNtSetInformationObject     _NtSetInformationObject;
extern pfnNtQueryObject              _NtQueryObject;
extern pfnNtCreateNamedPipeFile      _NtCreateNamedPipeFile;
extern pfnCreateProcessWithTokenW    _CreateProcessWithTokenW;

extern pfnCoUnmarshalInterface  _CoUnmarshalInterface;
extern pfnCreateStreamOnHGlobal _CreateStreamOnHGlobal;
extern pfnCreateObjrefMoniker   _CreateObjrefMoniker;
extern pfnCreateBindCtx         _CreateBindCtx_;
extern pfnCoInitializeEx        _CoInitializeEx;
extern pfnCoUninitialize        _CoUninitialize;
