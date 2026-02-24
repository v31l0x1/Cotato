# Cotato

Cotato is a **C port of [RustPotato](https://github.com/safedv/RustPotato)** — itself a reimplementation of [GodPotato](https://github.com/BeichenDream/GodPotato) — a privilege escalation tool that abuses DCOM and RPC to leverage `SeImpersonatePrivilege` and gain `NT AUTHORITY\SYSTEM` privileges on Windows systems.

## Overview

Below is a step-by-step breakdown of the execution flow:

### 1. Resolve APIs

Cotato dynamically resolves all required NT/Win32 functions at startup through `GetModuleHandleA` and `GetProcAddress`. No imports are linked statically for sensitive APIs, keeping the import table clean.

### 2. Initialize and Hook RPC Context

1. **Locate `RPC_SERVER_INTERFACE`:** Scans the in-memory image of `combase.dll` using a Boyer-Moore-Sunday byte search to find the `RPC_SERVER_INTERFACE` structure matching the ORCB GUID — the interface used by the OXID Resolver.
2. **Probe Dispatch Table:** Reads `MIDL_SERVER_INFO` to determine the parameter count of the `UseProtseq` procedure, then selects a matching hook stub (supports 4–14 parameters).
3. **Patch the Table:** Uses `NtProtectVirtualMemory` to flip the first `MIDL` dispatch table entry to the hook function, intercepting subsequent `UseProtseq` calls.

### 3. Start Named Pipe Server and Trigger DCOM

1. **Create Named Pipe:** A named pipe (`\\.\pipe\Cotato\pipe\epmapper`) is created with an open DACL (`D:(A;OICI;GA;;;WD)`), making it accessible to `SYSTEM`-level RPCSS.
2. **Trigger DCOM Unmarshal:** Cotato crafts and unmarshals a custom COM `OBJREF`, causing RPCSS to invoke an RPC call that passes through the hooked dispatch table,  which redirects the transport endpoint to the named pipe.
3. **Impersonate Client:** Once RPCSS connects to the pipe, `ImpersonateNamedPipeClient` is called to assume its security context.

### 4. Harvest SYSTEM Token

While impersonating, Cotato calls `NtQuerySystemInformation(SystemHandleInformation)` to enumerate all open handles system-wide. For each process, it opens the process token, checks the SID against `S-1-5-18`, verifies integrity level (`≥ System`) and impersonation level (`≥ SecurityImpersonation`), then calls `DuplicateTokenEx` to produce a usable primary token.

### 5. Execute Command and Cleanup

1. **Enable Privileges:** Enables `SeImpersonatePrivilege`, `SeAssignPrimaryTokenPrivilege`, and `SeIncreaseQuotaPrivilege` on the current token.
2. **Spawn Process:** Calls `CreateProcessWithTokenW` with the duplicated `SYSTEM` token to execute the user-supplied command.
3. **Restore Hook:** Writes the original function pointer back into the dispatch table and terminates the pipe server thread, releasing all handles.

## Building

```sh
make
```

## Usage

```
Usage:
  cotato.exe <command line>

Description:
  Execute a command as NT AUTHORITY\SYSTEM by abusing SeImpersonatePrivilege
  via DCOM/RPC named-pipe impersonation.

Examples:
  cotato.exe "cmd.exe /c whoami"
```

## Credits

Special thanks to:

- [safedv](https://github.com/safedv) for [RustPotato](https://github.com/safedv/RustPotato), the direct inspiration and reference implementation for this port.
- [BeichenDream](https://github.com/BeichenDream) for the original [GodPotato](https://github.com/BeichenDream/GodPotato) technique.