---
title: "Anatomy of a Hyperion Emulator: Full Teardown of a Drop-In RobloxPlayerBeta.dll"
date: 2026-10-10 16:45:00 -0700
categories: [Anti-Cheat, Reverse Engineering]
tags: [hyperion, byfron, roblox, unpacking, veh, static-analysis, ida]
description: A complete static teardown of a 37.5MB Hyperion emulator DLL — how it fingerprints the host, decodes a 100MB client image, splats it over the running process, reimplements Hyperion's VEH syscall contract, and spoofs hardware fingerprints.
---

Hyperion is Roblox's anti-tamper layer — the Byfron technology that ships as the protection envelope around the client. In current builds the split is simple: `RobloxPlayerBeta.exe` is the big client binary (~150 MB), and `RobloxPlayerBeta.dll` is the ~37 MB Hyperion module whose only export, `run`, is invoked by the exe to bootstrap the supervisor.

The DLL analyzed in this post **looks** like that module — same name, same export, same giant encrypted resource — but it is a community-built **emulator**: a drop-in replacement that reimplements Hyperion's half of the contract so the real client runs without Hyperion's supervision. This is a full static teardown (IDA Pro 9.4 + Hex-Rays) of how it works.

## 0. Artifact triage

| Property | Value |
|---|---|
| File | `RobloxPlayerBeta.dll` — 37,559,296 bytes |
| Arch | x64, imagebase `0x180000000` |
| Exports | `run` (ord 1), `DllEntryPoint` |
| Build | **Debug** — `VCRUNTIME140D`, /RTC checks, `.msvcjmc` (Just-My-Code), `.fptable` |
| PDB leak | `C:\Users\c6e\Downloads\test\emulator\bin\Debug\RobloxPlayerBeta.pdb` |
| Version info | `FileDescription="rip hyperion owo"`, `CompanyName="Oracle"`, `ProductName="emulator"` |
| Timestamp | 2026-10-01 |

The single most important structural fact: **`.rsrc` is 34 MB of the file**, and nearly all of it is one `RT_RCDATA` entry — resource **101**, `0x1C9899F` (~29.8 MB) of entropy-8.0 ciphertext. Everything else in the file exists to serve that blob and the contract around it.

## 1. `run` is a decoy — `DllMain` is the payload

`run` decompiles to essentially nothing:

```c
__int64 run() {
    sub_180003470(&unk_18017B0D1);   // reads one flag byte
    return 1;
}
```

It reads a flag and returns 1 — the "Hyperion initialized successfully" answer, after the fact. The real work happens inside `DllMain` on `DLL_PROCESS_ATTACH`, which is a strict four-gate sequence — any gate failing logs a message (via an encrypted-string logger, more on that later) and returns 0:

```c
BOOL DllMain(HMODULE h, DWORD reason) {
    if (reason == DLL_PROCESS_ATTACH) {
        hModule = h;
        DisableThreadLibraryCalls(h);
        BaseAddress = GetModuleHandleW(NULL);          // host exe
        if (!check_host_fingerprint())  return fail();
        if (!emu_init())                return fail(); // the giant one
        if (!install_veh_and_thread())  return fail();
        if (!patch_entrypoint())        return fail();
        return 1;
    }
    ...
}
```

## 2. Host fingerprinting

Gate 1 (`sub_18002CBA0`) pins the host to **exactly one build** of `RobloxPlayerBeta.exe` by parsing its in-memory PE headers:

```c
*(WORD*)base          == 0x5A4D          // MZ
pe->Signature         == 0x4550          // PE\0\0
pe->Magic             == 0x20B           // PE32+
pe->SizeOfImage       == 0x909E000       // 151,642,112 bytes
pe->AddressOfEntryPoint == 0x909C004
```

No version negotiation — a different Roblox build fails attach outright. Every subsequent offset in the emulator is a hardcoded RVA into this exact host image.

## 3. The container format

Gate 2 is the main installer (`sub_180020670`). Its first real step resolves the blob:

```c
hRes  = FindResourceW(hModule, (LPCWSTR)0x65 /* 101 */, (LPCWSTR)0xA /* RCDATA */);
size  = SizeofResource(hModule, hRes);              // 0x1C9899F
data  = LockResource(LoadResource(hModule, hRes));
sub_1800050E0(ctx, 105656368);                      // grow output buffer
status = sub_1800075E0(ctx, &out_size, data, &in_size,
                       &fmt, 5, 1, &mode, off_180168000);
ok = (status == 0 && out_size == 105656368 && (mode == 1 || mode == 4));
```

Resource 101 decodes to a **105,656,368-byte** (~100.8 MB) package — a 3.55× expansion, consistent with a compressed+encrypted container. The decoder is a custom routine (mode/algorithm params `5`, `1`), not a Windows API call you can breakpoint on. A second stage (`sub_180031980`) then validates the decoded image by computing `sub_180009D50(buf)` and requiring it to equal **`0xE2523380`** — an integrity checksum baked into the build.

The package layout, recovered from the installer (`sub_18002CEB0`):

| Package offset | Size | Destination |
|---|---|---|
| `0` | `0x6188000` (~97.5 MB) | `host + 0x1000` — the client image |
| `0x6188C00` | 4 | trailer magic, must equal `0x44DAE` |
| `0x6188C08` | 3,384,360 | `host + 0x8B93000` — RUNTIME_FUNCTION table |

Note `0x44DAE` = 282,030 — and 3,384,360 / 12 = 282,030. The trailer is the **count of `RUNTIME_FUNCTION` entries**; the tail of the package is the client's `.pdata`.

## 4. The in-memory image swap

This is the part that makes the design interesting. The emulator does not load the decoded client as a module — it **overwrites the host exe's own image in place**, using a RWX write primitive:

```c
bool write_code(void* dst, void* src, SIZE_T n, DWORD final_prot) {
    VirtualProtect(dst, n, PAGE_EXECUTE_READWRITE, &old);
    memcpy(dst, src, n);
    FlushInstructionCache(GetCurrentProcess(), dst, n);
    VirtualProtect(dst, n, final_prot, &old2);   // final: PAGE_EXECUTE_READ
}
```

Sequence:

1. `write_code(host + 0x1000, pkg, 0x6188000, RX)` — splat the decoded client over the first 97.5 MB of the host
2. Zero one page at `host + 0x6189000`
3. `write_code(host + 0x8B93000, pkg+0x6188C08, 0x33A428, RW)` — install `.pdata`
4. `RtlAddFunctionTable(host + 0x8B93000, 0x44DAE, host)` — register unwind info so SEH works inside the swapped image
5. `*(u64*)(host + 0x8A0C938) = BCryptGenRandom(8)` — plant a random session cookie where the client expects one

The original exe's first ~97.5 MB is a stub/shell; the emulator replaces it with the genuine client. The host's tail (~49 MB, including the entry point) is left alone — it's needed for the hand-off.

## 5. Post-swap surgery

With the client image resident, the installer applies a series of surgical fixes — each signature-verified against the expected bytes:

- **Section hardening** (`sub_18002D170`): walks the host's section table and forces `.text` **and the `tempest` section** to `0x60000020` (CODE|EXECUTE|READ). `tempest` is Byfron's section name — the swapped client still carries Hyperion's own section; the emulator preserves the image shape rather than stripping it.
- **IAT hooks** (`sub_18002D420`): walks a {dll, function, IAT-RVA} table and patches two specific imports inside the client:
  - `GetSystemFirmwareTable` → `sub_18002C0F0`: forwards to the real API, then post-processes the result when the provider signature is `'RSMB'` — **rewrites SMBIOS firmware table data**
  - `GetAdaptersAddresses` → `sub_18002C1B0`: walks the adapter list and **replaces every MAC address** with a keyed stream: `0x9E3779B9*(j+1) ^ adapter->Luid ^ adapter->IfIndex ^ session_rand`, then fixes the length field. Deterministic per session, different per adapter.
- **Flag clear** (`sub_18002D750`): writes `0` to `host + 0x7E254C0` (after verifying it's currently ≤ 1)
- **Code patch A** at `host + 0x484DC0D`: expects `44 8B 7D B8 45 0B FA` (`mov r15d,[rbp-48h]; or r15d,r15d`), writes `6A 07 41 5F 90 90 90` (`push 7; pop r15; nop×3`) — **forces a status register to constant 7**
- **Code patch B** at `host + 0x41FEA90`: expects a `push rbx; sub rsp,30h; mov rbx,rdx` prologue, writes `C7 02 07 00 00 00 48 8B C2 C3` (`mov dword [rdx],7; mov rax,rdx; ret`) — **forces a function to return status 7**
- **Inline hooks** (`sub_180025B30`): verifies two 16-byte signatures at `host + 0x4E57C80` and `host + 0x4E579E0`, installs trampolined hooks redirecting them to emulator callbacks (`sub_180026DC0`, `sub_180026490`), then `_InterlockedExchange`s a ready flag.

The constant `7` twice, the SMBIOS rewrite, and the MAC spoofing are the fingerprint of intent: the client is fed a fabricated-but-consistent hardware identity and "all checks passed" status codes.

## 6. Entry point redirection

Two writes land around the host's entry point (`0x909C004`):

- Early in init (`sub_1800216B0`): `48 B8 <imm64> FF E0` — `mov rax, &sub_180008140; jmp rax`, a 12-byte absolute trampoline at the EP itself. The callback (`sub_1800213A0`) re-verifies the VEH install then **tail-calls `host + 0x5B779F0`** — the real client's entry inside the swapped image. On failure it returns `1114` (`ERROR_DLL_INIT_FAILED`, fittingly).
- Late in `DllMain` (`sub_180021100`): `E9 <rel32>` + NOP sled at `EP-4` jumping to the same `0x5B779F0` — a second redirect covering whichever path reaches that address first.

## 7. The VEH syscall layer — the actual emulation

Gate 3 installs a first-chance `AddVectoredExceptionHandler` and a worker thread. The handler (`sub_180025D90`) is the heart of the emulator, and it reveals exactly how Hyperion's client↔supervisor IPC works:

The client "calls" Hyperion by dereferencing **bogus sentinel addresses** (`0xFFFFFFFFFFFFFFF3`…`0xFFFFFFFFFFFFFFF6`, i.e. ExceptionInformation[1] = −3…−13). The access violations funnel into the VEH, which:

1. Filters to `STATUS_ACCESS_VIOLATION` with a sentinel fault address
2. Reads `*Rsp` — the return address — requires it inside the host image `[+0x1000, +0x6189000)`, and **verifies a 7-byte instruction signature** at every call site: `EB 05 B8 01 00 00 00` (`jmp +5; mov eax,1` — the client's fallback path if nobody answers)
3. Dispatches on `(sentinel, callsite RVA)` against a hardcoded allowlist of 13 sites:

| Sentinel | Call-site RVAs | Service |
|---|---|---|
| −10 | `0x4E59656` | answered (constant) |
| −12 | `0x4E59684` | timing/telemetry block — synthesizes a 64-byte FILETIME+QPC structure with plausible monotonic values (`sub_180027B00`) |
| −9 | `0x4E596A4` | writes the **317-byte Roblox §1201 legal notice** into the caller's buffer — the client literally requests this string from the AC module |
| −11 | `0x4E596D8` (rcx=1) | crypto service: builds a 192-byte challenge block — `BCryptGenRandom` keys, a `0xC3823` magic-OR'd constant, and a 128-byte keyed table (`sub_180027770`) |
| −11 | `0x4E59714` (rcx=3) | answered |
| −5 | `0x360A2DC` | answered |
| −8 | `0x360A307` | answered |
| −7 | `0xB02BEA`,`0xB03F6A`,`0xFE3E4A`,`0x2A32A3A`,`0x4CA187A` and −3/`0x2A34FA1` | callback registration: writes `{2, &cb_a, &cb_b}` — pointers **into the emulator** the client invokes later — returns `0xD3A84AB4` |
| −3 | `0x2A38C01` | answered |
| −11 | `0x4E59D84` (rcx=4) | answered |
| −4 | `0x4E59DA1` | answered |
| −11 | `0x4E5A6AF`,`0x4E5A6FF` (rcx=5) | answered |

4. Emulates the return: `Rax = result`, `Rip = retaddr`, `Rsp += 8` (pops the frame), returns `EXCEPTION_CONTINUE_EXECUTION`

Unhandled sites get logged through the encrypted-string logger and passed on (`EXCEPTION_CONTINUE_SEARCH`). This is a faithful reproduction of the documented Hyperion syscall design — magic-constant AVs routed through a first-chance VEH, defeating inline hooks and static call graphs — minus the actual checks. Every site the *real* supervisor would service at these exact call addresses is answered with a fabricated healthy response.

## 8. The second stage

The worker thread is dead simple:

```c
Sleep(5000);
path = dll_dir + L"module.dll";     // our own directory
LoadLibraryW(path);
```

Five seconds after attach it loads `module.dll` from beside the emulator — an external payload slot. Nothing in the DLL writes this file; it's a companion the loader expects to exist (or fails silently — the return value is unchecked).

## 9. Craft details worth noting

- **Encrypted log strings.** Every status/failure message is stored as a length-prefixed ciphertext blob (`{0x14, 0x002C, <40B>}` style) and decrypted by per-callsite getter functions. Casual string triage shows nothing; the log only exists at runtime.
- **`__eh34` runtime.** A custom exception-handling framework (`__eh34_enter_wind_state`, `__eh34_unwind`, `__eh34_propagate_exception_into_caller`) wraps the installer — not stock MSVC SEH machinery, likely a small C++ EH library the author vendored.
- **`sub_180003470(&unk_*)` prologue calls** appear at the top of nearly every function — a per-function static-init / frame-cookie ritual, probably the author's own runtime scaffolding.
- **CFG is left intact** — the binary calls `__guard_dispatch_icall_fptr` for indirect calls and uses `SetProcessValidCallTargets`-related imports; the swapped image is registered for unwind (`RtlAddFunctionTable`) so it doesn't stand out to SEH-based checks.

## 10. Opsec failures

For a Hyperion circumvention tool, the author was sloppy:

- **Debug build** shipped: `VCRUNTIME140D`, /RTC instrumentation, JMC section, heap-check strings — a huge fingerprint and a performance tax on an anti-tamper-sensitive path
- **PDB path** `C:\Users\c6e\Downloads\test\emulator\bin\Debug\RobloxPlayerBeta.pdb` — Windows username and project layout embedded
- `rip hyperion owo` / `CompanyName=Oracle` in version info — a one-string YARA signature
- The whole binary is unobfuscated C++ with clean decompilation — no VM, no packer on the emulator itself (ironic, given what it ships inside)

## 11. Detection notes

- `FindResourceW(hModule, 0x65, 0xA)` + `RtlAddFunctionTable` + `AddVectoredExceptionHandler` in a single DllMain path is a strong behavioral signature
- IAT writes to `GetSystemFirmwareTable`/`GetAdaptersAddresses` from a non-system module
- The 7-byte call-site sig `EB 05 B8 01 00 00 00` and sentinel range (−3…−13) are characteristic of the Hyperion contract generally — useful for hunting other emulators
- File-level: `tempest` section name references, the `0xE2523380` image checksum constant, `0xC3823000000` challenge magic, `0xD3A84AB4` registration token

## 12. Conclusion

This binary is best understood as **a loader contract, reimplemented**. The author didn't try to defeat Hyperion's cryptography or VM — they observed that the client↔supervisor interface is narrow (one export, a handful of VEH-routed services, a session cookie, an unwind table) and rebuilt the server side of it. The genuine client image rides along encrypted in a resource, gets splatted over the host at attach, and starts answering to an emulator that says what Hyperion would say — minus everything Hyperion would check.

The elegant part is the restraint: `run` does nothing because there's nothing left to do. The heavy machinery (VEH contract, sentinel dispatch, call-site allowlisting) is replicated faithfully enough that the client can't tell the difference — and where it could tell (hardware fingerprinting, status constants), the answers are fabricated.

Open questions for a follow-up: the container cipher (`sub_1800075E0` internals — worth reversing properly since it's the only thing standing between the blob and a static unpack), the semantics of the two inline hooks at `0x4E57C80`/`0x4E579E0`, and what `module.dll` is expected to be. If a second sample turns up I'll diff the pinned constants — a version bump on this thing is a full rebuild, which is itself worth documenting.

---

*Analysis: IDA Pro 9.4 headless + Hex-Rays, static only. Binary retained privately; offsets are RVAs into the specific host build fingerprinted above.*
