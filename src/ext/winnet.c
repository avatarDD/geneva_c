#include "winnet.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "log.h"
#include "plat.h"

/* ---- helpers ----------------------------------------------------------------- */

static int hexv(int c)
{
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    return -1;
}

int xwinnet_guid(const char *s, uint8_t g[16])
{
    /* the text's bytes in order, then Data1-3 to little endian */
    static const int dash[] = {8, 13, 18, 23};
    uint8_t b[16];
    int k = 0;
    if (strlen(s) != 36)
        return -1;
    for (int i = 0; i < 36;) {
        int hi, lo;
        if (i == dash[0] || i == dash[1] || i == dash[2] || i == dash[3]) {
            if (s[i] != '-')
                return -1;
            i++;
            continue;
        }
        if ((hi = hexv(s[i])) < 0 || (lo = hexv(s[i + 1])) < 0)
            return -1;
        b[k++] = (uint8_t)(hi << 4 | lo);
        i += 2;
    }
    g[0] = b[3], g[1] = b[2], g[2] = b[1], g[3] = b[0];
    g[4] = b[5], g[5] = b[4];
    g[6] = b[7], g[7] = b[6];
    memcpy(g + 8, b + 8, 8);
    return 0;
}

void xwinnet_guid_str(const uint8_t g[16], char out[37])
{
    snprintf(out, 37, "%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X", g[3], g[2], g[1], g[0],
             g[5], g[4], g[7], g[6], g[8], g[9], g[10], g[11], g[12], g[13], g[14], g[15]);
}

int xwinnet_list_parse(const char *v, size_t maxlen, char ***out, size_t *n)
{
    for (;;) {
        const char *e = strchr(v, ',');
        size_t l = e ? (size_t)(e - v) : strlen(v);
        char *s;
        if (!l || l > maxlen)
            return -1;
        s = xmalloc(l + 1);
        memcpy(s, v, l);
        s[l] = 0;
        *out = xrealloc(*out, sizeof(**out) * (*n + 1));
        (*out)[(*n)++] = s;
        if (!e)
            return 0;
        v = e + 1;
    }
}

void xwinnet_list_free(char **v, size_t n)
{
    for (size_t i = 0; i < n; i++)
        free(v[i]);
    free(v);
}

int xwinnet_list_has(char *const *v, size_t n, const char *name, const uint8_t *guid)
{
    for (size_t i = 0; i < n; i++) {
        uint8_t g[16];
        if (name && !strcmp(v[i], name))
            return 1;
        if (guid && !xwinnet_guid(v[i], g) && !memcmp(g, guid, 16))
            return 1;
    }
    return 0;
}

/* ---- the filters ---------------------------------------------------------------- */

static struct {
    char **ssid, **nlm;
    size_t nssid, nnlm;
    int ssid_neg, nlm_neg;
    int on;              /* filters given */
    volatile int ok;     /* the networks are there */
    volatile int stop;
    plat_thread_t th;
} g;

static int neg_opt(const args_t *a, const char *name, int *out, sbuf *err)
{
    const char *v = arg_str(a, name, NULL);
    *out = 0;
    if (!arg_has(a, name))
        return 0;
    if (v && *v && strcmp(v, "0") && strcmp(v, "1")) {
        sb_printf(err, "bad --%s %s (0 or 1)", name, v);
        return -1;
    }
    *out = !v || !*v || !strcmp(v, "1");
    return 0;
}

static int lists(const args_t *a, sbuf *err)
{
    static const struct {
        const char *name;
        size_t max;
        int nlm;
    } o[] = {{"ssid-filter", 32, 0}, {"nlm-filter", 127, 1}};
    for (size_t k = 0; k < 2; k++) {
        int idx = 0;
        const char *v;
        while ((v = arg_next(a, o[k].name, &idx))) {
            if (xwinnet_list_parse(v, o[k].max, o[k].nlm ? &g.nlm : &g.ssid, o[k].nlm ? &g.nnlm : &g.nssid) < 0) {
                sb_printf(err, "bad --%s %s (names of 1 to %u bytes, separated by commas)", o[k].name, v,
                          (unsigned)o[k].max);
                return -1;
            }
        }
    }
    if (neg_opt(a, "ssid-filter-neg", &g.ssid_neg, err) < 0 || neg_opt(a, "nlm-filter-neg", &g.nlm_neg, err) < 0)
        return -1;
    return 0;
}

static void clear(void)
{
    xwinnet_list_free(g.ssid, g.nssid);
    xwinnet_list_free(g.nlm, g.nnlm);
    memset((void *)&g, 0, sizeof(g));
}

int xwinnet_ok(void) { return !g.on || atomic_load_int(&g.ok); }

#ifdef _WIN32
#  include <netlistmgr.h>
#  include <wlanapi.h>

typedef DWORD(WINAPI *t_WlanOpenHandle)(DWORD, PVOID, PDWORD, PHANDLE);
typedef DWORD(WINAPI *t_WlanCloseHandle)(HANDLE, PVOID);
typedef DWORD(WINAPI *t_WlanEnumInterfaces)(HANDLE, PVOID, PWLAN_INTERFACE_INFO_LIST *);
typedef DWORD(WINAPI *t_WlanQueryInterface)(HANDLE, const GUID *, WLAN_INTF_OPCODE, PVOID, PDWORD, PVOID *,
                                            PWLAN_OPCODE_VALUE_TYPE);
typedef VOID(WINAPI *t_WlanFreeMemory)(PVOID);
typedef HRESULT(WINAPI *t_CoInitializeEx)(LPVOID, DWORD);
typedef void(WINAPI *t_CoUninitialize)(void);
typedef HRESULT(WINAPI *t_CoCreateInstance)(REFCLSID, LPUNKNOWN, DWORD, REFIID, LPVOID *);
typedef void(WINAPI *t_SysFreeString)(BSTR);

static struct {
    HMODULE wlan, ole, oleaut;
    t_WlanOpenHandle open;
    t_WlanCloseHandle close;
    t_WlanEnumInterfaces enumi;
    t_WlanQueryInterface query;
    t_WlanFreeMemory freem;
    t_CoInitializeEx coinit;
    t_CoUninitialize couninit;
    t_CoCreateInstance cocreate;
    t_SysFreeString sysfree;
} w;

/* netlistmgr.h's CLSID_NetworkListManager and IID_INetworkListManager
 * (their symbols are in libuuid) */
static const GUID clsid_nlm = {0xDCB00C01, 0x570F, 0x4A9B, {0x8D, 0x69, 0x19, 0x9F, 0xDB, 0xA5, 0x72, 0x3B}};
static const GUID iid_nlm = {0xDCB00000, 0x570F, 0x4A9B, {0x8D, 0x69, 0x19, 0x9F, 0xDB, 0xA5, 0x72, 0x3B}};

static HMODULE sys_dll(const wchar_t *name)
{
    /* never from the current directory */
    return LoadLibraryExW(name, NULL, 0x00000800 /* LOAD_LIBRARY_SEARCH_SYSTEM32 */);
}

#  define IMPORT(lib, var, type, name) (w.var = (type)(void (*)(void))GetProcAddress(w.lib, name))

static int load_wlan(sbuf *err)
{
    if (w.wlan)
        return 0;
    if (!(w.wlan = sys_dll(L"wlanapi.dll"))) {
        sb_printf(err, "--ssid-filter: cannot load wlanapi.dll (error %lu; Windows Server needs the Wireless LAN "
                       "Service)", (unsigned long)GetLastError());
        return -1;
    }
    if (!IMPORT(wlan, open, t_WlanOpenHandle, "WlanOpenHandle") ||
        !IMPORT(wlan, close, t_WlanCloseHandle, "WlanCloseHandle") ||
        !IMPORT(wlan, enumi, t_WlanEnumInterfaces, "WlanEnumInterfaces") ||
        !IMPORT(wlan, query, t_WlanQueryInterface, "WlanQueryInterface") ||
        !IMPORT(wlan, freem, t_WlanFreeMemory, "WlanFreeMemory")) {
        sb_puts(err, "--ssid-filter: wlanapi.dll lacks a function");
        return -1;
    }
    return 0;
}

static int load_com(sbuf *err)
{
    if (w.ole)
        return 0;
    if (!(w.ole = sys_dll(L"ole32.dll")) || !(w.oleaut = sys_dll(L"oleaut32.dll"))) {
        sb_printf(err, "--nlm-filter: cannot load ole32.dll or oleaut32.dll (error %lu)", (unsigned long)GetLastError());
        return -1;
    }
    if (!IMPORT(ole, coinit, t_CoInitializeEx, "CoInitializeEx") ||
        !IMPORT(ole, couninit, t_CoUninitialize, "CoUninitialize") ||
        !IMPORT(ole, cocreate, t_CoCreateInstance, "CoCreateInstance") ||
        !IMPORT(oleaut, sysfree, t_SysFreeString, "SysFreeString")) {
        sb_puts(err, "--nlm-filter: ole32.dll or oleaut32.dll lacks a function");
        return -1;
    }
    return 0;
}

static void unload(void)
{
    if (w.wlan)
        FreeLibrary(w.wlan);
    if (w.ole)
        FreeLibrary(w.ole);
    if (w.oleaut)
        FreeLibrary(w.oleaut);
    memset(&w, 0, sizeof(w));
}

/* zapret2's wlan_filter_match: a connected interface with one of the SSIDs;
 * -1 when the WLAN service cannot be asked */
static int wlan_match(void)
{
    HANDLE h = NULL;
    DWORD ver, r;
    PWLAN_INTERFACE_INFO_LIST l = NULL;
    int found = 0;
    if ((r = w.open(2, NULL, &ver, &h)) != ERROR_SUCCESS)
        return -1;
    if ((r = w.enumi(h, NULL, &l)) != ERROR_SUCCESS) {
        w.close(h, NULL);
        return -1;
    }
    for (DWORD i = 0; i < l->dwNumberOfItems && !found; i++) {
        PWLAN_CONNECTION_ATTRIBUTES ca = NULL;
        DWORD sz = 0;
        if (l->InterfaceInfo[i].isState != wlan_interface_state_connected)
            continue;
        if (w.query(h, &l->InterfaceInfo[i].InterfaceGuid, wlan_intf_opcode_current_connection, NULL, &sz,
                    (PVOID *)&ca, NULL) != ERROR_SUCCESS)
            continue;
        {
            const DOT11_SSID *s = &ca->wlanAssociationAttributes.dot11Ssid;
            for (size_t k = 0; k < g.nssid && !found; k++)
                found = strlen(g.ssid[k]) == s->uSSIDLength && !memcmp(g.ssid[k], s->ucSSID, s->uSSIDLength);
        }
        w.freem(ca);
    }
    w.freem(l);
    w.close(h, NULL);
    return found;
}

static void utf8(BSTR s, char *out, int cap)
{
    if (!WideCharToMultiByte(CP_UTF8, 0, s, -1, out, cap, NULL, NULL))
        out[0] = 0;
}

/* zapret2's nlm_filter_match: a connected network of the names or GUIDs */
static int nlm_match(INetworkListManager *m)
{
    IEnumNetworks *en = NULL;
    INetwork *n;
    int found = 0;
    if (FAILED(m->lpVtbl->GetNetworks(m, NLM_ENUM_NETWORK_CONNECTED, &en)))
        return -1;
    while (!found && en->lpVtbl->Next(en, 1, &n, NULL) == S_OK) {
        GUID id;
        BSTR bs = NULL;
        char name[256];
        if (SUCCEEDED(n->lpVtbl->GetNetworkId(n, &id)) && SUCCEEDED(n->lpVtbl->GetName(n, &bs))) {
            utf8(bs, name, sizeof(name));
            found = xwinnet_list_has(g.nlm, g.nnlm, name, (const uint8_t *)&id);
            w.sysfree(bs);
        }
        n->lpVtbl->Release(n);
    }
    en->lpVtbl->Release(en);
    return found;
}

static int check(INetworkListManager *m)
{
    int a = 1, b = 1;
    if (g.nssid) {
        int r = wlan_match();
        a = r < 0 ? 0 : r ^ g.ssid_neg;
    }
    if (g.nnlm) {
        int r = m ? nlm_match(m) : -1;
        b = r < 0 ? 0 : r ^ g.nlm_neg;
    }
    return a && b;
}

static void monitor(void *arg)
{
    INetworkListManager *m = NULL;
    (void)arg;
    if (g.nnlm) {
        w.coinit(NULL, COINIT_MULTITHREADED);
        if (FAILED(w.cocreate(&clsid_nlm, NULL, CLSCTX_ALL, &iid_nlm, (LPVOID *)&m)))
            m = NULL;
    }
    while (!atomic_load_int(&g.stop)) {
        int ok = check(m), was = atomic_load_int(&g.ok);
        if (ok != was) {
            atomic_store_int(&g.ok, ok);
            LOGI("winnet", ok ? "the network is present: the strategies run"
                              : "the network is not present: every packet passes untouched");
        }
        for (int i = 0; i < 10 && !atomic_load_int(&g.stop); i++)
            plat_sleep_ms(100);
    }
    if (m)
        m->lpVtbl->Release(m);
    if (g.nnlm)
        w.couninit();
}

int xwinnet_start(const args_t *a, sbuf *err)
{
    xwinnet_stop();
    if (lists(a, err) < 0) {
        clear();
        return -1;
    }
    if (!g.nssid && !g.nnlm)
        return 0;
    if ((g.nssid && load_wlan(err) < 0) || (g.nnlm && load_com(err) < 0)) {
        unload();
        clear();
        return -1;
    }
    if (g.nnlm) {
        /* the manager once here: an error now, not in the thread */
        INetworkListManager *m = NULL;
        HRESULT hr;
        w.coinit(NULL, COINIT_MULTITHREADED);
        hr = w.cocreate(&clsid_nlm, NULL, CLSCTX_ALL, &iid_nlm, (LPVOID *)&m);
        if (FAILED(hr)) {
            w.couninit();
            sb_printf(err, "--nlm-filter: cannot create the Network List Manager (0x%08lX)", (unsigned long)hr);
            unload();
            clear();
            return -1;
        }
        atomic_store_int(&g.ok, check(m));
        m->lpVtbl->Release(m);
        w.couninit();
    } else {
        atomic_store_int(&g.ok, check(NULL));
    }
    LOGI("winnet", "%s", atomic_load_int(&g.ok) ? "the network is present: the strategies run"
                                                 : "the network is not present: every packet passes untouched");
    g.on = 1;
    if (plat_thread_start(&g.th, monitor, NULL) != 0) {
        sb_puts(err, "--ssid-filter/--nlm-filter: cannot start a thread");
        g.on = 0;
        unload();
        clear();
        return -1;
    }
    return 1;
}

void xwinnet_stop(void)
{
    if (g.on) {
        atomic_store_int(&g.stop, 1);
        plat_thread_join(g.th);
        unload();
    }
    clear();
}

int xwinnet_nlm_list(int all, sbuf *out, sbuf *err)
{
    INetworkListManager *m = NULL;
    IEnumNetworks *en = NULL;
    HRESULT hr;
    int rc = 0;
    if (load_com(err) < 0) {
        unload();
        return -1;
    }
    w.coinit(NULL, COINIT_MULTITHREADED);
    if (FAILED(hr = w.cocreate(&clsid_nlm, NULL, CLSCTX_ALL, &iid_nlm, (LPVOID *)&m)) ||
        FAILED(hr = m->lpVtbl->GetNetworks(m, all ? NLM_ENUM_NETWORK_ALL : NLM_ENUM_NETWORK_CONNECTED, &en))) {
        sb_printf(err, "Network List Manager: 0x%08lX", (unsigned long)hr);
        rc = -1;
    } else {
        INetwork *n;
        while (en->lpVtbl->Next(en, 1, &n, NULL) == S_OK) {
            GUID id;
            BSTR bs = NULL;
            VARIANT_BOOL conn = 0, inet = 0;
            NLM_NETWORK_CATEGORY cat = NLM_NETWORK_CATEGORY_PUBLIC;
            char name[256], gs[37];
            if (SUCCEEDED(n->lpVtbl->GetNetworkId(n, &id)) && SUCCEEDED(n->lpVtbl->GetName(n, &bs))) {
                IEnumNetworkConnections *ec;
                INetworkConnection *c;
                n->lpVtbl->get_IsConnected(n, &conn);
                n->lpVtbl->get_IsConnectedToInternet(n, &inet);
                n->lpVtbl->GetCategory(n, &cat);
                utf8(bs, name, sizeof(name));
                w.sysfree(bs);
                xwinnet_guid_str((const uint8_t *)&id, gs);
                sb_printf(out, "Name    : %s%s%s (%s)\nNetID   : %s\n", name, conn ? " (connected)" : "",
                          inet ? " (inet)" : "",
                          cat == NLM_NETWORK_CATEGORY_PUBLIC                 ? "public"
                          : cat == NLM_NETWORK_CATEGORY_PRIVATE              ? "private"
                          : cat == NLM_NETWORK_CATEGORY_DOMAIN_AUTHENTICATED ? "domain"
                                                                             : "unknown",
                          gs);
                if (conn && SUCCEEDED(n->lpVtbl->GetNetworkConnections(n, &ec))) {
                    while (ec->lpVtbl->Next(ec, 1, &c, NULL) == S_OK) {
                        GUID ad;
                        if (SUCCEEDED(c->lpVtbl->GetAdapterId(c, &ad))) {
                            xwinnet_guid_str((const uint8_t *)&ad, gs);
                            sb_printf(out, "Adapter : %s\n", gs);
                        }
                        c->lpVtbl->Release(c);
                    }
                    ec->lpVtbl->Release(ec);
                }
                sb_puts(out, "\n");
            }
            n->lpVtbl->Release(n);
        }
        en->lpVtbl->Release(en);
    }
    if (m)
        m->lpVtbl->Release(m);
    w.couninit();
    unload();
    return rc;
}

#else

int xwinnet_start(const args_t *a, sbuf *err)
{
    xwinnet_stop();
    if (lists(a, err) < 0) {
        clear();
        return -1;
    }
    if (!g.nssid && !g.nnlm && !g.ssid_neg && !g.nlm_neg) {
        clear();
        return 0;
    }
    clear();
    sb_puts(err, "--ssid-filter and --nlm-filter are Windows-only (Linux: --filter-ssid of a profile)");
    return -1;
}

void xwinnet_stop(void) { clear(); }

int xwinnet_nlm_list(int all, sbuf *out, sbuf *err)
{
    (void)all, (void)out;
    sb_puts(err, "--nlm-list is Windows-only (the Network List Manager)");
    return -1;
}

#endif
