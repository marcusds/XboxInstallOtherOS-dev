/* Experimental check: can this app use Windows Hypervisor Platform (what QEMU's -accel whpx needs)?
   UWP apps may not import LoadLibraryExW, so it is looked up at run time in kernelbase.dll,
   found by walking the loaded-module list. Nothing here is used by the VM itself. */
#include <windows.h>
#include <stdio.h>
#include <stdarg.h>
#include <intrin.h>

typedef HMODULE (WINAPI *LoadLibraryExW_t)(LPCWSTR, HANDLE, DWORD);
typedef HRESULT (WINAPI *WHvGetCapability_t)(int, void *, UINT32, UINT32 *);
typedef HRESULT (WINAPI *WHvCreatePartition_t)(void **);
typedef HRESULT (WINAPI *WHvSetPartitionProperty_t)(void *, int, const void *, UINT32);
typedef HRESULT (WINAPI *WHvSetupPartition_t)(void *);
typedef HRESULT (WINAPI *WHvDeletePartition_t)(void *);

static char *g_out;
static int g_len, g_pos;

static void say(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    if (g_pos < g_len - 1) {
        int n = vsnprintf(g_out + g_pos, g_len - g_pos, fmt, ap);
        if (n > 0) g_pos = (g_pos + n < g_len - 1) ? g_pos + n : g_len - 1;
    }
    va_end(ap);
}

static int name_is(const WCHAR *s, int chars, const char *want)
{
    int i;
    for (i = 0; i < chars && want[i]; i++) {
        WCHAR c = s[i];
        if (c >= 'A' && c <= 'Z') c += 32;
        if (c != (WCHAR)want[i]) return 0;
    }
    return i == chars && want[i] == 0;
}

/* x64 PEB -> Ldr -> InMemoryOrderModuleList; offsets are relative to each entry's InMemoryOrderLinks. */
static HMODULE find_module(const char *lower_name)
{
    unsigned char *peb = (unsigned char *)__readgsqword(0x60);
    unsigned char *ldr = *(unsigned char **)(peb + 0x18);
    LIST_ENTRY *head = (LIST_ENTRY *)(ldr + 0x20), *e;
    for (e = head->Flink; e != head; e = e->Flink) {
        unsigned char *p = (unsigned char *)e;
        USHORT bytes = *(USHORT *)(p + 0x48);
        const WCHAR *buf = *(const WCHAR **)(p + 0x50);
        if (buf && name_is(buf, bytes / 2, lower_name)) return *(HMODULE *)(p + 0x20);
    }
    return NULL;
}

__declspec(dllexport) int qemu_dll_whpx_probe(char *out, int len)
{
    g_out = out; g_len = len; g_pos = 0;
    if (!out || len < 2) return -1;
    out[0] = 0;

    HMODULE kb = find_module("kernelbase.dll");
    if (!kb) kb = find_module("kernel32.dll");
    LoadLibraryExW_t loadEx = kb ? (LoadLibraryExW_t)GetProcAddress(kb, "LoadLibraryExW") : NULL;
    if (!loadEx) { say("RESULT: could not find LoadLibraryExW, so the test could not run.\n"); return -1; }

    HMODULE hv = loadEx(L"WinHvPlatform.dll", NULL, 0x800 /* LOAD_LIBRARY_SEARCH_SYSTEM32 */);
    if (!hv) {
        say("Loading WinHvPlatform.dll failed, error %lu.\n", GetLastError());
        say("RESULT: WinHvPlatform.dll is not available to apps on this console (software emulation only).\n");
        return 0;
    }
    WHvGetCapability_t getCap = (WHvGetCapability_t)GetProcAddress(hv, "WHvGetCapability");
    WHvCreatePartition_t create = (WHvCreatePartition_t)GetProcAddress(hv, "WHvCreatePartition");
    WHvSetPartitionProperty_t setProp = (WHvSetPartitionProperty_t)GetProcAddress(hv, "WHvSetPartitionProperty");
    WHvSetupPartition_t setup = (WHvSetupPartition_t)GetProcAddress(hv, "WHvSetupPartition");
    WHvDeletePartition_t del = (WHvDeletePartition_t)GetProcAddress(hv, "WHvDeletePartition");
    if (!getCap || !create || !setProp || !setup || !del) {
        say("RESULT: WinHvPlatform.dll loaded but is missing functions.\n");
        return 0;
    }

    unsigned char cap[1024] = { 0 };
    UINT32 written = 0;
    HRESULT hr = getCap(0 /* HypervisorPresent */, cap, sizeof cap, &written);
    say("WinHvPlatform.dll loaded. HypervisorPresent: hr=0x%08lX, value=%d\n", (unsigned long)hr, *(int *)cap);
    if (hr != 0 || *(int *)cap == 0) {
        say("RESULT: no usable hypervisor for apps (QEMU must keep using software emulation).\n");
        return 0;
    }
    memset(cap, 0, sizeof cap);
    hr = getCap(1 /* Features */, cap, sizeof cap, &written);
    say("Features: hr=0x%08lX, value=0x%llX\n", (unsigned long)hr, *(unsigned long long *)cap);

    void *part = NULL;
    hr = create(&part);
    say("Create partition: hr=0x%08lX\n", (unsigned long)hr);
    if (hr != 0) { say("RESULT: hypervisor reports present, but the app may not create a VM.\n"); return 0; }
    UINT32 cpus = 1;
    hr = setProp(part, 0x1fff /* ProcessorCount */, &cpus, sizeof cpus);
    say("Set processor count: hr=0x%08lX\n", (unsigned long)hr);
    hr = setup(part);
    say("Set up partition: hr=0x%08lX\n", (unsigned long)hr);
    say(hr == 0 ? "RESULT: SUCCESS - the app can create a hardware VM; QEMU -accel whpx is worth trying.\n"
                : "RESULT: the VM could not be set up, so hardware virtualization is not usable.\n");
    del(part);
    return 1;
}
