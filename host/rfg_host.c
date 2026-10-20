/*
 * rfg_host.dll: the native32 host for Red Faction Guerrilla Re-Mars-tered (GOG rfg.exe,
 * sha256 7a82d2d0...). Loaded by rfg_recomp.exe, the stub EXE (host/make_stub_exe.py) that holds
 * 0x00400000..0x03D7B000 from process creation. Layout expected:
 *     <game dir>\rfg.exe            the original GOG executable (its bytes are the guest image)
 *     <game dir>\rfg_recomp.exe     the stub
 *     <game dir>\rfg_host.dll       this DLL (lifted code + native32)
 * plus the game's own DLLs (binkw32.dll, sw_api.dll, discord-rpc.dll, ...) beside them, which
 * native32_bind loads with LoadLibrary like the Windows loader would.
 *
 * Environment: RFG_EXE overrides the guest path; RFG_TRACE_NATIVE=1 / RFG_TRACE_CALLBACKS=1
 * enable native32 tracing.
 */
#define WIN32_LEAN_AND_MEAN
#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include "native32.h"

#define RFG_BASE  0x00400000u
#define RFG_ENTRY 0x00FB440Du     /* WinMainCRTStartup (PDB; = AddressOfEntryPoint) */
#define RFG_SPAN  0x0397B000u     /* SizeOfImage */
#define LIFT_STACK (512u << 20)   /* host stack for the lifted call tree */

recomp_func_t recomp_lookup_manual(uint32_t va) { (void)va; return NULL; }

/* Generated code is built with RECOMP_STRICT_ICALL: an indirect call/jump whose target has no
 * lifted body arrives here instead of printing and running on. Every distinct (kind, va, from)
 * is logged once to stderr and to rfg_unresolved.log; with RFG_STRICT=1 the first one stops the
 * game (exit 0x7D) so a test cannot pass over it. */
void recomp_unresolved(const char* kind, uint32_t va, uint32_t from) {
    static struct { uint32_t va, from; char k; } seen[256];
    static int n;
    for (int i = 0; i < n; i++)
        if (seen[i].va == va && seen[i].from == from && seen[i].k == kind[1]) goto strict;
    if (n < 256) { seen[n].va = va; seen[n].from = from; seen[n].k = kind[1]; n++; }
    fprintf(stderr, "rfg_host: UNRESOLVED %s target %08X from %08X\n", kind, va, from);
    {
        FILE* f = fopen("rfg_unresolved.log", "a");
        if (f) { fprintf(f, "%s\t%08X\t%08X\n", kind, va, from); fclose(f); }
    }
strict:
    {
        char v[8];
        if (GetEnvironmentVariableA("RFG_STRICT", v, sizeof v) && v[0] == '1') ExitProcess(0x7D);
    }
}

/* recomp_types.h declares it and says a host may define it; no runtime file does. */
void recomp_unimpl(uint32_t va, const char* what) {
    fprintf(stderr, "rfg_host: UNIMPLEMENTED instruction at %08X: %s\n", va, what);
    ExitProcess(0x7E);
}

static int g_exit;
static DWORD WINAPI run_guest(LPVOID p) {
    (void)p;
    native32_call_guest(RFG_ENTRY, 0, NULL);   /* WinMainCRTStartup normally ends in ExitProcess */
    g_exit = (int)g_eax;
    return 0;
}

static int env_flag(const char* n) {
    char v[8];
    return GetEnvironmentVariableA(n, v, sizeof v) && v[0] == '1';
}

/* RFG_SAMPLE=1: every 10 ms, read g_cur_func (the last lifted function entered) and count it;
 * every 5 s rewrite rfg_sample.tsv with the counts so far (flushed: survives a killed process).
 * Diagnoses "busy but no frame": where the guest is spending its time. */
#define SAMPLE_SLOTS 65536
static struct { uint32_t va; uint32_t n; } g_samp[SAMPLE_SLOTS];
static DWORD WINAPI sampler(LPVOID p) {
    (void)p;
    DWORD last = GetTickCount();
    uint32_t total = 0;
    for (;;) {
        Sleep(10);
        uint32_t va = g_cur_func;
        uint32_t h = (va * 2654435761u) >> 16;
        for (uint32_t k = 0; k < SAMPLE_SLOTS; k++, h = (h + 1) & (SAMPLE_SLOTS - 1)) {
            if (g_samp[h].va == va || g_samp[h].va == 0) { g_samp[h].va = va; g_samp[h].n++; break; }
        }
        total++;
        if (GetTickCount() - last >= 5000) {
            last = GetTickCount();
            FILE* f = fopen("rfg_sample.tsv", "w");
            if (f) {
                fprintf(f, "va\tsamples\ttotal=%u\n", total);
                for (uint32_t k = 0; k < SAMPLE_SLOTS; k++)
                    if (g_samp[k].n) fprintf(f, "0x%08X\t%u\n", g_samp[k].va, g_samp[k].n);
                fclose(f);
            }
        }
    }
}

__declspec(dllexport) int __cdecl rfg_main(void) {
    char exe[MAX_PATH], dir[MAX_PATH];
    setvbuf(stderr, NULL, _IONBF, 0);
    if (!GetEnvironmentVariableA("RFG_EXE", exe, MAX_PATH)) {
        GetModuleFileNameA(NULL, dir, MAX_PATH);           /* the stub, in the game dir */
        char* s = strrchr(dir, '\\');
        if (s) *s = 0;
        _snprintf(exe, MAX_PATH, "%s\\rfg.exe", dir);
    }
    strcpy(dir, exe);
    { char* s = strrchr(dir, '\\'); if (s) { *s = 0; SetCurrentDirectoryA(dir); SetDllDirectoryA(dir); } }
    if ((uint32_t)(uintptr_t)GetModuleHandleA(NULL) != RFG_BASE) {
        fprintf(stderr, "rfg_host: the process EXE is not the stub at %08X; refusing\n", RFG_BASE);
        return 0x70;
    }
    native32_trace_native = env_flag("RFG_TRACE_NATIVE");
    native32_trace_callbacks = env_flag("RFG_TRACE_CALLBACKS");
    native32_init();
    if (env_flag("RFG_SAMPLE")) CreateThread(NULL, 0, sampler, NULL, 0, NULL);
    uint32_t span = native32_map(exe, RFG_BASE);
    if (span != RFG_SPAN) {
        fprintf(stderr, "rfg_host: map %s gave span %08X, expected %08X; refusing\n", exe, span, RFG_SPAN);
        return 0x71;
    }
    int unresolved = native32_bind(RFG_BASE, NULL, 0);
    fprintf(stderr, "rfg_host: mapped %s, %d unresolved imports\n", exe, unresolved);
    HANDLE t = CreateThread(NULL, LIFT_STACK, run_guest, NULL, STACK_SIZE_PARAM_IS_A_RESERVATION, NULL);
    if (!t) { fprintf(stderr, "rfg_host: CreateThread failed %lu\n", GetLastError()); return 0x72; }
    WaitForSingleObject(t, INFINITE);
    return g_exit;
}
