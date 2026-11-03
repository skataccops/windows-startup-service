// launch_svc.cpp
// POC: Windows Service that launches multiple applications in interactive user sessions
// on startup and session lifecycle events (fresh boot, logon, switch user, unlock, resume).
//
// Key Security Feature:
// Launches strictly with STANDARD USER privileges (Medium Integrity Level),
// stripping/filtering out administrative privileges even if the logged-in user is an Administrator.

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <wtsapi32.h>
#include <userenv.h>
#include <sddl.h>

#include <condition_variable>
#include <cstdarg>
#include <cstdio>
#include <ctime>
#include <deque>
#include <map>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#pragma comment(lib, "wtsapi32.lib")
#pragma comment(lib, "userenv.lib")
#pragma comment(lib, "advapi32.lib")

static const wchar_t* SVC_NAME    = L"LaunchSvcPoc";
static const wchar_t* SVC_DISPLAY = L"Launch App Service (POC)";
static const wchar_t* LOG_DIR     = L"C:\\ProgramData\\LaunchSvcPoc";
static const wchar_t* LOG_FILE    = L"C:\\ProgramData\\LaunchSvcPoc\\service.log";
static const wchar_t* DEFAULT_APP = L"C:\\Windows\\System32\\notepad.exe";

// ---------------------------------------------------------------- logging
static std::mutex g_logMutex;

static void Log(const char* fmt, ...)
{
    char msg[2048];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);

    std::time_t t = std::time(nullptr);
    std::tm tmv;
    localtime_s(&tmv, &t);
    char ts[32];
    std::strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", &tmv);

    std::lock_guard<std::mutex> lk(g_logMutex);
    CreateDirectoryW(LOG_DIR, nullptr);
    FILE* f = nullptr;
    if (_wfopen_s(&f, LOG_FILE, L"a") == 0 && f) {
        std::fprintf(f, "%s [pid %lu] %s\n", ts, GetCurrentProcessId(), msg);
        std::fclose(f);
    }
    OutputDebugStringA(msg);
}

static std::string Narrow(const std::wstring& w)
{
    if (w.empty()) return {};
    int n = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), -1, nullptr, 0, nullptr, nullptr);
    std::string s(n, '\0');
    WideCharToMultiByte(CP_UTF8, 0, w.c_str(), -1, &s[0], n, nullptr, nullptr);
    if (!s.empty() && s.back() == '\0') s.pop_back();
    return s;
}

// ------------------------------------------------------------ apps to launch
// Reads all application lines from app.txt next to service binary
static std::vector<std::wstring> GetAppCommands()
{
    std::vector<std::wstring> commands;
    wchar_t exe[MAX_PATH];
    GetModuleFileNameW(nullptr, exe, MAX_PATH);
    std::wstring cfg = exe;
    size_t slash = cfg.find_last_of(L"\\/");
    if (slash != std::wstring::npos) cfg.resize(slash + 1);
    cfg += L"app.txt";

    FILE* f = nullptr;
    if (_wfopen_s(&f, cfg.c_str(), L"rb") == 0 && f) {
        std::string content;
        char buf[1024];
        while (size_t n = std::fread(buf, 1, sizeof(buf), f)) {
            content.append(buf, n);
        }
        std::fclose(f);

        // Strip UTF-8 BOM if present
        if (content.size() >= 3 && (unsigned char)content[0] == 0xEF &&
            (unsigned char)content[1] == 0xBB && (unsigned char)content[2] == 0xBF) {
            content.erase(0, 3);
        }

        size_t start = 0;
        while (start < content.size()) {
            size_t end = content.find_first_of("\r\n", start);
            if (end == std::string::npos) end = content.size();
            std::string line = content.substr(start, end - start);
            start = end + 1;

            // Trim whitespace
            while (!line.empty() && (line.front() == ' ' || line.front() == '\t')) line.erase(line.begin());
            while (!line.empty() && (line.back() == ' ' || line.back() == '\t' || line.back() == '\r')) line.pop_back();

            // Skip empty or commented lines
            if (line.empty() || line[0] == '#' || (line.size() >= 2 && line[0] == '/' && line[1] == '/')) {
                continue;
            }

            int w = MultiByteToWideChar(CP_UTF8, 0, line.c_str(), -1, nullptr, 0);
            if (w > 1) {
                std::wstring wline(w, L'\0');
                MultiByteToWideChar(CP_UTF8, 0, line.c_str(), -1, &wline[0], w);
                if (!wline.empty() && wline.back() == L'\0') wline.pop_back();
                commands.push_back(wline);
            }
        }
    }

    if (commands.empty()) {
        commands.push_back(DEFAULT_APP);
    }
    return commands;
}

// --------------------------------------------------------- session tracking
// sessionId -> list of process handles launched in that session
static std::map<DWORD, std::vector<HANDLE>> g_apps;
static std::mutex g_appsMutex;

static bool AnyProcessRunning(const std::vector<HANDLE>& handles)
{
    for (HANDLE h : handles) {
        if (h && WaitForSingleObject(h, 0) == WAIT_TIMEOUT) {
            return true;
        }
    }
    return false;
}

static void ForgetSession(DWORD sid)
{
    std::lock_guard<std::mutex> lk(g_appsMutex);
    auto it = g_apps.find(sid);
    if (it != g_apps.end()) {
        for (HANDLE h : it->second) {
            if (h) CloseHandle(h);
        }
        g_apps.erase(it);
    }
}

// Helper: Checks if token has administrative privileges
static bool TokenIsMemberOfAdmin(HANDLE token)
{
    SID_IDENTIFIER_AUTHORITY ntAuth = SECURITY_NT_AUTHORITY;
    PSID adminGroup = nullptr;
    if (!AllocateAndInitializeSid(&ntAuth, 2, SECURITY_BUILTIN_DOMAIN_RID,
                                 DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &adminGroup)) {
        return false;
    }
    BOOL isMember = FALSE;
    CheckTokenMembership(token, adminGroup, &isMember);
    FreeSid(adminGroup);
    return isMember != FALSE;
}

// Drops administrative rights from a token using CreateRestrictedToken
static HANDLE CreateRestrictedStandardToken(HANDLE srcToken)
{
    SID_IDENTIFIER_AUTHORITY ntAuth = SECURITY_NT_AUTHORITY;
    PSID adminGroup = nullptr;
    if (!AllocateAndInitializeSid(&ntAuth, 2, SECURITY_BUILTIN_DOMAIN_RID,
                                 DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &adminGroup)) {
        return nullptr;
    }

    SID_AND_ATTRIBUTES dropSids[1] = {};
    dropSids[0].Sid = adminGroup;
    dropSids[0].Attributes = 0;

    HANDLE restrictedToken = nullptr;
    BOOL ok = CreateRestrictedToken(srcToken, DISABLE_MAX_PRIVILEGE,
                                    1, dropSids,
                                    0, nullptr,
                                    0, nullptr,
                                    &restrictedToken);
    FreeSid(adminGroup);
    if (!ok) {
        return nullptr;
    }
    return restrictedToken;
}

// Ensures the token runs strictly with standard user privileges (Medium Integrity, Non-Elevated).
static HANDLE MakeLimitedUserToken(HANDLE token, DWORD sid)
{
    HANDLE primary = nullptr;
    TOKEN_ELEVATION_TYPE type = TokenElevationTypeDefault;
    DWORD len = 0;

    if (GetTokenInformation(token, TokenElevationType, &type, sizeof(type), &len) &&
        type == TokenElevationTypeFull) {
        TOKEN_LINKED_TOKEN linked = {};
        if (GetTokenInformation(token, TokenLinkedToken, &linked, sizeof(linked), &len) && linked.LinkedToken) {
            BOOL ok = DuplicateTokenEx(linked.LinkedToken, MAXIMUM_ALLOWED, nullptr,
                                       SecurityIdentification, TokenPrimary, &primary);
            DWORD err = ok ? 0 : GetLastError();
            CloseHandle(linked.LinkedToken);
            if (!ok) {
                Log("session %lu: DuplicateTokenEx(linked) failed, error %lu", sid, err);
                return nullptr;
            }
            SetTokenInformation(primary, TokenSessionId, &sid, sizeof(sid));
            Log("session %lu: user is admin with UAC split token -> switched to linked limited (standard user) token", sid);
            return primary;
        }
    }

    // If UAC was disabled or user is built-in admin, explicitly restrict token to standard user
    if (TokenIsMemberOfAdmin(token)) {
        HANDLE restricted = CreateRestrictedStandardToken(token);
        if (restricted) {
            BOOL ok = DuplicateTokenEx(restricted, MAXIMUM_ALLOWED, nullptr,
                                       SecurityIdentification, TokenPrimary, &primary);
            CloseHandle(restricted);
            if (ok) {
                SetTokenInformation(primary, TokenSessionId, &sid, sizeof(sid));
                Log("session %lu: token has admin rights without split token -> created restricted standard user token", sid);
                return primary;
            }
        }
    }

    // Default: duplicate standard user token
    if (!DuplicateTokenEx(token, MAXIMUM_ALLOWED, nullptr, SecurityIdentification,
                          TokenPrimary, &primary)) {
        Log("session %lu: DuplicateTokenEx failed, error %lu", sid, GetLastError());
        return nullptr;
    }
    SetTokenInformation(primary, TokenSessionId, &sid, sizeof(sid));
    Log("session %lu: using standard user token (elevation type %d)", sid, (int)type);
    return primary;
}

// Retrieves the user's home profile directory (e.g. C:\Users\<Username>)
static std::wstring GetUserProfilePath(HANDLE userToken)
{
    wchar_t path[MAX_PATH] = {};
    DWORD size = MAX_PATH;
    if (GetUserProfileDirectoryW(userToken, path, &size)) {
        return std::wstring(path);
    }
    return L"";
}

// Expands per-user variables and prepares command line for CreateProcessAsUser
static std::wstring PrepareCommandLine(HANDLE userToken, const std::wstring& rawLine)
{
    std::wstring line = rawLine;

    // 1. Expand environment variables like %LOCALAPPDATA% or %PROGRAMFILES%
    wchar_t expanded[2048] = {};
    if (ExpandEnvironmentStringsForUserW(userToken, line.c_str(), expanded, 2048)) {
        line = expanded;
    }

    // Trim whitespace
    while (!line.empty() && (line.front() == L' ' || line.front() == L'\t')) line.erase(line.begin());
    while (!line.empty() && (line.back() == L' ' || line.back() == L'\t' || line.back() == L'\r' || line.back() == L'\n')) line.pop_back();

    if (line.empty()) return {};

    // If line already starts with quotes or contains command-line arguments (like --app-id or switches),
    // pass it directly as the command line so CreateProcessAsUserW parses quotes correctly!
    if (line.front() == L'\"' || line.find(L" --") != std::wstring::npos || line.find(L" -") != std::wstring::npos) {
        return line;
    }

    // If bare path has no quotes and no arguments, wrap in quotes
    return L"\"" + line + L"\"";
}

// Launch all configured apps in the given session, using that session's user token.
static bool LaunchAllInSession(DWORD sid)
{
    HANDLE userToken = nullptr;
    // Requires SeTcbPrivilege: available to LocalSystem service
    if (!WTSQueryUserToken(sid, &userToken)) {
        Log("session %lu: WTSQueryUserToken failed, error %lu (user session not ready yet)",
            sid, GetLastError());
        return false;
    }

    // The apps must run with the user's normal (standard user) rights, never as admin.
    HANDLE primary = MakeLimitedUserToken(userToken, sid);
    CloseHandle(userToken);
    if (!primary) {
        Log("session %lu: could not get a non-elevated user token, aborting launch", sid);
        return false;
    }

    // Prepare environment block for the specific user
    LPVOID env = nullptr;
    if (!CreateEnvironmentBlock(&env, primary, FALSE)) {
        Log("session %lu: CreateEnvironmentBlock failed, error %lu", sid, GetLastError());
        env = nullptr;
    }

    std::wstring userDir = GetUserProfilePath(primary);
    std::vector<std::wstring> rawCommands = GetAppCommands();

    ForgetSession(sid);
    std::vector<HANDLE> launchedHandles;
    bool anySuccess = false;

    for (size_t i = 0; i < rawCommands.size(); ++i) {
        std::wstring cmd = PrepareCommandLine(primary, rawCommands[i]);
        if (cmd.empty()) continue;

        STARTUPINFOW si = {};
        si.cb = sizeof(si);
        si.lpDesktop = const_cast<LPWSTR>(L"winsta0\\default");

        PROCESS_INFORMATION pi = {};
        BOOL ok = CreateProcessAsUserW(
            primary,
            nullptr,
            &cmd[0],
            nullptr,
            nullptr,
            FALSE,
            CREATE_UNICODE_ENVIRONMENT | CREATE_NEW_CONSOLE,
            env,
            userDir.empty() ? nullptr : userDir.c_str(),
            &si,
            &pi
        );
        DWORD err = ok ? 0 : GetLastError();

        if (ok) {
            CloseHandle(pi.hThread);
            launchedHandles.push_back(pi.hProcess);
            anySuccess = true;
            Log("session %lu: [%zu/%zu] successfully launched '%s' (PID %lu)",
                sid, i + 1, rawCommands.size(), Narrow(cmd).c_str(), pi.dwProcessId);
        } else {
            Log("session %lu: [%zu/%zu] CreateProcessAsUser failed for '%s', error %lu",
                sid, i + 1, rawCommands.size(), Narrow(cmd).c_str(), err);
        }

        // Brief delay between launching multiple PWAs to allow Chrome proxy IPC to complete
        if (i + 1 < rawCommands.size()) {
            Sleep(600);
        }
    }

    if (env) DestroyEnvironmentBlock(env);
    CloseHandle(primary);

    if (anySuccess) {
        std::lock_guard<std::mutex> lk(g_appsMutex);
        g_apps[sid] = launchedHandles;
    }
    return anySuccess;
}

// Launch with retry logic: when a session logs on, the desktop may need a moment to initialize
static void EnsureLaunched(DWORD sid, const char* reason)
{
    if (sid == 0 || sid == 0xFFFFFFFF) return; // Session 0 is non-interactive

    {
        std::lock_guard<std::mutex> lk(g_appsMutex);
        auto it = g_apps.find(sid);
        if (it != g_apps.end() && AnyProcessRunning(it->second)) {
            Log("session %lu: apps already running, skip launch (%s)", sid, reason);
            return;
        }
    }

    Log("session %lu: ensuring apps are launched (reason: %s)", sid, reason);

    // Up to 4 attempts with brief backoff for freshly logged-on sessions
    for (int attempt = 1; attempt <= 4; ++attempt) {
        if (LaunchAllInSession(sid)) {
            return;
        }
        if (attempt < 4) {
            Log("session %lu: launch attempt %d failed, retrying in 1s...", sid, attempt);
            Sleep(1000);
        }
    }
    Log("session %lu: all launch attempts exhausted", sid);
}

static void EnsureActiveConsole(const char* reason)
{
    DWORD sid = WTSGetActiveConsoleSessionId();
    if (sid == 0xFFFFFFFF) {
        Log("no active console session (%s)", reason);
        return;
    }
    EnsureLaunched(sid, reason);
}

// Scans and launches apps in all active sessions (physical console, RDP, etc.)
static void EnsureAllActiveSessions(const char* reason)
{
    PWTS_SESSION_INFOW info = nullptr;
    DWORD count = 0;
    if (!WTSEnumerateSessionsW(WTS_CURRENT_SERVER_HANDLE, 0, 1, &info, &count)) {
        Log("WTSEnumerateSessions failed, error %lu", GetLastError());
        EnsureActiveConsole(reason);
        return;
    }
    for (DWORD i = 0; i < count; ++i) {
        if (info[i].State == WTSActive) {
            EnsureLaunched(info[i].SessionId, reason);
        }
    }
    WTSFreeMemory(info);
}

// ------------------------------------------------------------ event queue
struct Event {
    enum Type { SessionChange, Power, Stop } type;
    DWORD code;      // WTS_* or PBT_*
    DWORD sessionId; // for SessionChange
};

static std::mutex g_qMutex;
static std::condition_variable g_qCv;
static std::deque<Event> g_queue;

static void Enqueue(const Event& e)
{
    {
        std::lock_guard<std::mutex> lk(g_qMutex);
        g_queue.push_back(e);
    }
    g_qCv.notify_one();
}

static const char* WtsEventName(DWORD code)
{
    switch (code) {
    case WTS_CONSOLE_CONNECT:    return "WTS_CONSOLE_CONNECT (Switch User / Attach)";
    case WTS_CONSOLE_DISCONNECT: return "WTS_CONSOLE_DISCONNECT (Switch User / Detach)";
    case WTS_REMOTE_CONNECT:     return "WTS_REMOTE_CONNECT (RDP Connect)";
    case WTS_REMOTE_DISCONNECT:  return "WTS_REMOTE_DISCONNECT (RDP Disconnect)";
    case WTS_SESSION_LOGON:      return "WTS_SESSION_LOGON (User Logon)";
    case WTS_SESSION_LOGOFF:     return "WTS_SESSION_LOGOFF (User Logoff)";
    case WTS_SESSION_LOCK:       return "WTS_SESSION_LOCK (Desktop Locked)";
    case WTS_SESSION_UNLOCK:     return "WTS_SESSION_UNLOCK (Desktop Unlocked)";
    default:                     return "WTS_OTHER";
    }
}

static void HandleSessionChange(DWORD code, DWORD sid)
{
    Log("session change event: %s (%lu) for session %lu", WtsEventName(code), code, sid);
    switch (code) {
    case WTS_SESSION_LOGON:
    case WTS_SESSION_UNLOCK:
    case WTS_CONSOLE_CONNECT:  // switch user / reconnect at physical console
    case WTS_REMOTE_CONNECT:   // RDP session connect
        EnsureLaunched(sid, WtsEventName(code));
        break;

    case WTS_SESSION_LOGOFF:
        // Windows terminates the session processes upon logoff; cleanup state
        Log("session %lu: user logged off, cleaning tracking state", sid);
        ForgetSession(sid);
        break;

    default:
        // LOCK / DISCONNECT: keep apps running
        break;
    }
}

static void HandlePower(DWORD code)
{
    switch (code) {
    case PBT_APMRESUMEAUTOMATIC:
    case PBT_APMRESUMESUSPEND:
        Log("power event: system resume from standby/hibernation (code %lu)", code);
        EnsureAllActiveSessions("power resume");
        break;
    case PBT_APMSUSPEND:
        Log("power event: system entering standby/suspend");
        break;
    default:
        break;
    }
}

static void WorkerLoop()
{
    Log("worker loop started");

    // Fresh startup: check all currently active sessions on system boot or service start
    EnsureAllActiveSessions("fresh startup / service start");

    for (;;) {
        Event ev;
        {
            std::unique_lock<std::mutex> lk(g_qMutex);
            g_qCv.wait(lk, [] { return !g_queue.empty(); });
            ev = g_queue.front();
            g_queue.pop_front();
        }
        if (ev.type == Event::Stop) break;
        if (ev.type == Event::SessionChange) HandleSessionChange(ev.code, ev.sessionId);
        else if (ev.type == Event::Power) HandlePower(ev.code);
    }

    {
        std::lock_guard<std::mutex> lk(g_appsMutex);
        for (auto& kv : g_apps) {
            for (HANDLE h : kv.second) {
                if (h) CloseHandle(h);
            }
        }
        g_apps.clear();
    }
    Log("worker loop finished");
}

// ----------------------------------------------------------- service plumbing
static SERVICE_STATUS_HANDLE g_statusHandle = nullptr;
static SERVICE_STATUS g_status = {};

static void SetState(DWORD state, DWORD exitCode = NO_ERROR, DWORD waitHint = 0)
{
    static DWORD checkPoint = 1;
    g_status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    g_status.dwCurrentState = state;
    g_status.dwWin32ExitCode = exitCode;
    g_status.dwWaitHint = waitHint;
    g_status.dwControlsAccepted =
        (state == SERVICE_START_PENDING)
            ? 0
            : (SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_PRESHUTDOWN |
               SERVICE_ACCEPT_SESSIONCHANGE | SERVICE_ACCEPT_POWEREVENT);
    g_status.dwCheckPoint =
        (state == SERVICE_RUNNING || state == SERVICE_STOPPED) ? 0 : checkPoint++;
    SetServiceStatus(g_statusHandle, &g_status);
}

static DWORD WINAPI CtrlHandler(DWORD ctrl, DWORD evType, LPVOID evData, LPVOID)
{
    switch (ctrl) {
    case SERVICE_CONTROL_STOP:
    case SERVICE_CONTROL_PRESHUTDOWN:
        Log("control received: %s", ctrl == SERVICE_CONTROL_STOP ? "STOP" : "PRESHUTDOWN");
        SetState(SERVICE_STOP_PENDING, NO_ERROR, 10000);
        Enqueue({Event::Stop, 0, 0});
        return NO_ERROR;

    case SERVICE_CONTROL_SESSIONCHANGE: {
        auto* n = static_cast<WTSSESSION_NOTIFICATION*>(evData);
        Enqueue({Event::SessionChange, evType, n ? n->dwSessionId : 0});
        return NO_ERROR;
    }

    case SERVICE_CONTROL_POWEREVENT:
        Enqueue({Event::Power, evType, 0});
        return NO_ERROR;

    case SERVICE_CONTROL_INTERROGATE:
        return NO_ERROR;

    default:
        return ERROR_CALL_NOT_IMPLEMENTED;
    }
}

static void WINAPI ServiceMain(DWORD, LPWSTR*)
{
    g_statusHandle = RegisterServiceCtrlHandlerExW(SVC_NAME, CtrlHandler, nullptr);
    if (!g_statusHandle) return;

    SetState(SERVICE_START_PENDING, NO_ERROR, 5000);
    Log("=== service starting ===");

    std::thread worker(WorkerLoop);
    SetState(SERVICE_RUNNING);
    Log("service running and ready");

    worker.join();

    Log("=== service stopped ===");
    SetState(SERVICE_STOPPED);
}

// -------------------------------------------------------- service management CLI
static int InstallService()
{
    wchar_t path[MAX_PATH];
    GetModuleFileNameW(nullptr, path, MAX_PATH);
    std::wstring bin = L"\"" + std::wstring(path) + L"\"";

    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CREATE_SERVICE);
    if (!scm) {
        std::fwprintf(stderr, L"OpenSCManager failed: error %lu (make sure to run as Administrator)\n", GetLastError());
        return 1;
    }

    SC_HANDLE svc = CreateServiceW(
        scm,
        SVC_NAME,
        SVC_DISPLAY,
        SERVICE_ALL_ACCESS,
        SERVICE_WIN32_OWN_PROCESS,
        SERVICE_AUTO_START,
        SERVICE_ERROR_NORMAL,
        bin.c_str(),
        nullptr, nullptr, nullptr, nullptr, nullptr
    ); // LocalSystem account

    if (!svc) {
        DWORD err = GetLastError();
        if (err == ERROR_SERVICE_EXISTS) {
            std::fwprintf(stderr, L"Service '%s' already exists.\n", SVC_NAME);
        } else {
            std::fwprintf(stderr, L"CreateService failed: error %lu\n", err);
        }
        CloseServiceHandle(scm);
        return 1;
    }

    // Auto-recovery: restart service if it crashes
    SC_ACTION actions[3] = {
        {SC_ACTION_RESTART, 5000},
        {SC_ACTION_RESTART, 5000},
        {SC_ACTION_RESTART, 30000},
    };
    SERVICE_FAILURE_ACTIONSW fa = {};
    fa.dwResetPeriod = 86400; // 1 day
    fa.cActions = 3;
    fa.lpsaActions = actions;
    ChangeServiceConfig2W(svc, SERVICE_CONFIG_FAILURE_ACTIONS, &fa);

    SERVICE_DESCRIPTIONW desc = {const_cast<LPWSTR>(
        L"POC: Windows service that launches user applications in interactive sessions on startup and logon events with standard user privileges.")};
    ChangeServiceConfig2W(svc, SERVICE_CONFIG_DESCRIPTION, &desc);

    // Least Privilege Restriction:
    // Strip all unnecessary LocalSystem privileges except the exact 4 required
    static wchar_t privs[] =
        L"SeTcbPrivilege\0SeAssignPrimaryTokenPrivilege\0"
        L"SeIncreaseQuotaPrivilege\0SeChangeNotifyPrivilege\0";
    SERVICE_REQUIRED_PRIVILEGES_INFOW rp = {privs};
    if (!ChangeServiceConfig2W(svc, SERVICE_CONFIG_REQUIRED_PRIVILEGES_INFO, &rp)) {
        std::fwprintf(stderr, L"Warning: could not restrict service required privileges: %lu\n", GetLastError());
    }

    std::wprintf(L"Service '%s' installed successfully.\n", SVC_NAME);
    std::wprintf(L"Run 'launch_svc.exe start' or 'sc start %s' to start.\n", SVC_NAME);

    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    return 0;
}

static int StartServiceCmd()
{
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scm) {
        std::fwprintf(stderr, L"OpenSCManager failed: %lu (run as admin)\n", GetLastError());
        return 1;
    }
    SC_HANDLE svc = OpenServiceW(scm, SVC_NAME, SERVICE_START | SERVICE_QUERY_STATUS);
    if (!svc) {
        std::fwprintf(stderr, L"OpenService failed: %lu\n", GetLastError());
        CloseServiceHandle(scm);
        return 1;
    }
    if (!StartServiceW(svc, 0, nullptr)) {
        DWORD err = GetLastError();
        if (err == ERROR_SERVICE_ALREADY_RUNNING) {
            std::wprintf(L"Service is already running.\n");
        } else {
            std::fwprintf(stderr, L"StartService failed: %lu\n", err);
            CloseServiceHandle(svc);
            CloseServiceHandle(scm);
            return 1;
        }
    } else {
        std::wprintf(L"Service start requested successfully.\n");
    }
    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    return 0;
}

static int StopServiceCmd()
{
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scm) {
        std::fwprintf(stderr, L"OpenSCManager failed: %lu (run as admin)\n", GetLastError());
        return 1;
    }
    SC_HANDLE svc = OpenServiceW(scm, SVC_NAME, SERVICE_STOP | SERVICE_QUERY_STATUS);
    if (!svc) {
        std::fwprintf(stderr, L"OpenService failed: %lu\n", GetLastError());
        CloseServiceHandle(scm);
        return 1;
    }
    SERVICE_STATUS st = {};
    if (ControlService(svc, SERVICE_CONTROL_STOP, &st)) {
        std::wprintf(L"Service stop requested successfully.\n");
    } else {
        std::fwprintf(stderr, L"ControlService STOP failed: %lu\n", GetLastError());
    }
    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    return 0;
}

static int StatusServiceCmd()
{
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scm) {
        std::fwprintf(stderr, L"OpenSCManager failed: %lu\n", GetLastError());
        return 1;
    }
    SC_HANDLE svc = OpenServiceW(scm, SVC_NAME, SERVICE_QUERY_STATUS);
    if (!svc) {
        std::fwprintf(stderr, L"OpenService failed: %lu (service may not be installed)\n", GetLastError());
        CloseServiceHandle(scm);
        return 1;
    }
    SERVICE_STATUS st = {};
    if (QueryServiceStatus(svc, &st)) {
        const wchar_t* stateStr = L"UNKNOWN";
        switch (st.dwCurrentState) {
        case SERVICE_STOPPED:          stateStr = L"STOPPED"; break;
        case SERVICE_START_PENDING:    stateStr = L"START_PENDING"; break;
        case SERVICE_STOP_PENDING:     stateStr = L"STOP_PENDING"; break;
        case SERVICE_RUNNING:          stateStr = L"RUNNING"; break;
        case SERVICE_CONTINUE_PENDING: stateStr = L"CONTINUE_PENDING"; break;
        case SERVICE_PAUSE_PENDING:    stateStr = L"PAUSE_PENDING"; break;
        case SERVICE_PAUSED:           stateStr = L"PAUSED"; break;
        }
        std::wprintf(L"Service '%s' state: %s (dwCurrentState=%lu)\n", SVC_NAME, stateStr, st.dwCurrentState);
    } else {
        std::fwprintf(stderr, L"QueryServiceStatus failed: %lu\n", GetLastError());
    }
    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    return 0;
}

static int UninstallService()
{
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scm) {
        std::fwprintf(stderr, L"OpenSCManager failed: %lu (run as admin)\n", GetLastError());
        return 1;
    }

    SC_HANDLE svc = OpenServiceW(scm, SVC_NAME, SERVICE_STOP | DELETE | SERVICE_QUERY_STATUS);
    if (!svc) {
        std::fwprintf(stderr, L"OpenService failed: %lu\n", GetLastError());
        CloseServiceHandle(scm);
        return 1;
    }

    SERVICE_STATUS st = {};
    ControlService(svc, SERVICE_CONTROL_STOP, &st);
    for (int i = 0; i < 20; ++i) {
        if (!QueryServiceStatus(svc, &st) || st.dwCurrentState == SERVICE_STOPPED) break;
        Sleep(500);
    }

    int rc = DeleteService(svc) ? 0 : 1;
    if (rc) std::fwprintf(stderr, L"DeleteService failed: %lu\n", GetLastError());
    else std::wprintf(L"Service '%s' uninstalled successfully.\n", SVC_NAME);

    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    return rc;
}

// -------------------------------------------------------- Entry point
int wmain(int argc, wchar_t** argv)
{
    if (argc > 1) {
        std::wstring a = argv[1];
        if (a == L"install")   return InstallService();
        if (a == L"uninstall") return UninstallService();
        if (a == L"start")     return StartServiceCmd();
        if (a == L"stop")      return StopServiceCmd();
        if (a == L"status")    return StatusServiceCmd();

        std::wprintf(L"Usage:\n");
        std::wprintf(L"  launch_svc.exe install    - Install service (auto-start on Windows boot)\n");
        std::wprintf(L"  launch_svc.exe start      - Start service immediately\n");
        std::wprintf(L"  launch_svc.exe status     - Check service state\n");
        std::wprintf(L"  launch_svc.exe stop       - Stop service\n");
        std::wprintf(L"  launch_svc.exe uninstall  - Remove service\n");
        return 2;
    }

    SERVICE_TABLE_ENTRYW table[] = {
        {const_cast<LPWSTR>(SVC_NAME), ServiceMain},
        {nullptr, nullptr},
    };
    if (!StartServiceCtrlDispatcherW(table)) {
        std::wprintf(L"This is a Windows Service executable.\n");
        std::wprintf(L"Usage: launch_svc.exe [install | start | status | stop | uninstall]\n");
        return 1;
    }
    return 0;
}
