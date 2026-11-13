#include "sec_win.h"

#include <stdlib.h>
#include <string.h>

#include "log.h"
#include "plat.h"

/* ---- the files (every platform) --------------------------------------------- */

static char **g_files;
static size_t g_nfiles;

void xsbx_file(const char *path)
{
    if (!path || !*path)
        return;
    for (size_t i = 0; i < g_nfiles; i++)
        if (!strcmp(g_files[i], path))
            return;
    g_files = xrealloc(g_files, (g_nfiles + 1) * sizeof(*g_files));
    g_files[g_nfiles++] = xstrdup(path);
}

size_t xsbx_nfiles(void) { return g_nfiles; }

const char *xsbx_file_at(size_t i) { return i < g_nfiles ? g_files[i] : NULL; }

void xsbx_reset(void)
{
    for (size_t i = 0; i < g_nfiles; i++)
        free(g_files[i]);
    free(g_files);
    g_files = NULL;
    g_nfiles = 0;
}

int xsbx_parse(const args_t *a, int *on, sbuf *err)
{
    const char *v;
#ifdef _WIN32
    *on = 1;
#else
    *on = 0;
#endif
    if (!arg_has(a, "ext-sandbox"))
        return 0;
    v = arg_str(a, "ext-sandbox", "");
    if (*v && strcmp(v, "0") && strcmp(v, "1")) {
        sb_printf(err, "bad --ext-sandbox %s (0 or 1)", v);
        return -1;
    }
#ifdef _WIN32
    *on = strcmp(v, "0") != 0;
    return 0;
#else
    if (strcmp(v, "0")) {
        sb_puts(err, "--ext-sandbox is Windows-only (Linux: --ext-seccomp, --user)");
        return -1;
    }
    return 0;
#endif
}

#ifdef _WIN32
#  include <windows.h>
#  include <aclapi.h>

static void win_err(sbuf *err, const char *what, DWORD code)
{
    char msg[256];
    DWORD n = FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, code, 0, msg,
                             sizeof(msg), NULL);
    while (n && (msg[n - 1] == '\n' || msg[n - 1] == '\r' || msg[n - 1] == '.'))
        msg[--n] = 0;
    sb_printf(err, "%s: %s (error %lu)", what, n ? msg : "failed", (unsigned long)code);
}

static SID_IDENTIFIER_AUTHORITY label_authority = {SECURITY_MANDATORY_LABEL_AUTHORITY};

/* zapret2's SetMandatoryLabelFileW: a Low no-write-up label */
static DWORD label_low(const wchar_t *path)
{
    union {
        SID sid;
        char b[16];
    } label;
    union {
        ACL acl;
        char b[32];
    } acl;
    DWORD attrs = 0, e;
    if (wcsncmp(path, L"\\\\.\\", 4)) {
        attrs = GetFileAttributesW(path);
        if (attrs == INVALID_FILE_ATTRIBUTES)
            return GetLastError();
    }
    InitializeSid(&label.sid, &label_authority, 1);
    *GetSidSubAuthority(&label.sid, 0) = SECURITY_MANDATORY_LOW_RID;
    if (!InitializeAcl(&acl.acl, sizeof(acl), ACL_REVISION) ||
        !AddMandatoryAce(&acl.acl, (attrs & FILE_ATTRIBUTE_DIRECTORY) ? ACL_REVISION_DS : ACL_REVISION, 0,
                         SYSTEM_MANDATORY_LABEL_NO_WRITE_UP, &label.sid))
        return GetLastError();
    e = SetNamedSecurityInfoW((wchar_t *)path, SE_FILE_OBJECT, LABEL_SECURITY_INFORMATION, NULL, NULL, NULL,
                              &acl.acl);
    return e;
}

static DWORD label_file(const char *path)
{
    wchar_t w[1024];
    HANDLE h;
    /* the file must exist to get a label: an empty one, as the run makes it */
    h = CreateFileA(path, FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
                    OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE)
        return GetLastError();
    CloseHandle(h);
    if (!MultiByteToWideChar(CP_ACP, 0, path, -1, w, (int)(sizeof(w) / sizeof(*w))))
        return GetLastError();
    return label_low(w);
}

/* zapret2's RemoveTokenPrivs: all but SeChangeNotifyPrivilege */
static DWORD remove_privs(void)
{
    HANDLE t;
    DWORD n = 0, e = 0;
    TOKEN_PRIVILEGES *p;
    LUID keep;
    if (!LookupPrivilegeValueW(NULL, L"SeChangeNotifyPrivilege", &keep))
        return GetLastError();
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &t))
        return GetLastError();
    if (GetTokenInformation(t, TokenPrivileges, NULL, 0, &n) || GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
        e = GetLastError();
        CloseHandle(t);
        return e ? e : ERROR_INVALID_DATA;
    }
    p = xmalloc(n);
    if (!GetTokenInformation(t, TokenPrivileges, p, n, &n))
        e = GetLastError();
    else {
        for (DWORD k = 0; k < p->PrivilegeCount; k++)
            if (memcmp(&p->Privileges[k].Luid, &keep, sizeof(keep)))
                p->Privileges[k].Attributes = SE_PRIVILEGE_REMOVED;
        if (!AdjustTokenPrivileges(t, FALSE, p, n, NULL, NULL))
            e = GetLastError();
    }
    free(p);
    CloseHandle(t);
    return e;
}

/* zapret2's LowMandatoryLevel */
static DWORD low_integrity(void)
{
    union {
        SID sid;
        char b[16];
    } sid;
    TOKEN_MANDATORY_LABEL tl;
    HANDLE t;
    DWORD e = 0;
    InitializeSid(&sid.sid, &label_authority, 1);
    *GetSidSubAuthority(&sid.sid, 0) = SECURITY_MANDATORY_LOW_RID;
    tl.Label.Sid = &sid.sid;
    tl.Label.Attributes = SE_GROUP_INTEGRITY;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_DEFAULT, &t))
        return GetLastError();
    if (!SetTokenInformation(t, TokenIntegrityLevel, &tl, sizeof(tl)))
        e = GetLastError();
    CloseHandle(t);
    return e;
}

/* zapret2's JobSandbox */
static DWORD job(void)
{
    JOBOBJECT_BASIC_LIMIT_INFORMATION lim;
    JOBOBJECT_BASIC_UI_RESTRICTIONS ui;
    DWORD e = 0;
    HANDLE j = CreateJobObjectW(NULL, NULL);
    if (!j)
        return GetLastError();
    memset(&lim, 0, sizeof(lim));
    lim.LimitFlags = JOB_OBJECT_LIMIT_ACTIVE_PROCESS;
    lim.ActiveProcessLimit = 1; /* no child process */
    ui.UIRestrictionsClass = JOB_OBJECT_UILIMIT_DESKTOP | JOB_OBJECT_UILIMIT_DISPLAYSETTINGS |
                             JOB_OBJECT_UILIMIT_EXITWINDOWS | JOB_OBJECT_UILIMIT_GLOBALATOMS |
                             JOB_OBJECT_UILIMIT_HANDLES | JOB_OBJECT_UILIMIT_READCLIPBOARD |
                             JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS | JOB_OBJECT_UILIMIT_WRITECLIPBOARD;
    if (!SetInformationJobObject(j, JobObjectBasicLimitInformation, &lim, sizeof(lim)) ||
        !SetInformationJobObject(j, JobObjectBasicUIRestrictions, &ui, sizeof(ui)) ||
        !AssignProcessToJobObject(j, GetCurrentProcess()))
        e = GetLastError();
    CloseHandle(j); /* the process keeps the job */
    return e;
}

int xsbx_apply(sbuf *err)
{
    DWORD e;
    /* as zapret2: a file without the label is a warning (FAT, a share) */
    for (size_t i = 0; i < g_nfiles; i++)
        if ((e = label_file(g_files[i])) != 0) {
            sbuf w;
            sb_init(&w);
            win_err(&w, "the Low label", e);
            LOGW("sandbox", "%s: %s; the file may not be writable once running", g_files[i], w.data);
            sb_free(&w);
        }
    /* set_filter opens WinDivert again (zapret2 does this for --nlm-filter) */
    if ((e = label_low(L"\\\\.\\WinDivert")) != 0) {
        sbuf w;
        sb_init(&w);
        win_err(&w, "the Low label on the WinDivert device", e);
        LOGW("sandbox", "%s; set_filter will fail once running", w.data);
        sb_free(&w);
    }
    if ((e = remove_privs()) != 0) {
        win_err(err, "the sandbox: removing the privileges", e);
        return -1;
    }
    if ((e = low_integrity()) != 0) {
        win_err(err, "the sandbox: Low integrity", e);
        return -1;
    }
    if ((e = job()) != 0) {
        win_err(err, "the sandbox: the job object", e);
        return -1;
    }
    LOGI("sandbox", "on: Low integrity, no privileges but SeChangeNotifyPrivilege, no child processes "
                    "(--ext-sandbox 0: without)");
    return 0;
}

#else

int xsbx_apply(sbuf *err)
{
    (void)err;
    return 0;
}

#endif
