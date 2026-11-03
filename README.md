# Windows Startup Application Launcher Service (`launch_svc.exe`)

A standalone Windows Service that automatically launches interactive desktop applications upon **Windows boot and session lifecycle events**, strictly enforcing **standard user privileges (Medium Integrity Level, non-admin)**.

---

## Key Capabilities

- **Automatic Startup**: Starts with Windows (`SERVICE_AUTO_START`) in Session 0 before user logon.
- **Guaranteed Standard User Rights**: Even if the logged-in user is an Administrator, administrative rights are stripped (`TokenLinkedToken` / `CreateRestrictedToken`) so the application never runs elevated.
- **Full Lifecycle Handling**: Triggers automatically on **Fresh Boot**, **User Logon**, **Switch User**, **Desktop Unlock**, and **System Resume**.
- **Multi-App & PWA Support**: Can launch multiple applications, scripts, or Chrome/Edge PWAs.
- **Zero Dependencies**: Statically compiled (`/MT`) x64 binary. No runtimes or SDKs required.

---

## Quick Start (3 Steps)

### Step 1: Copy Files
Place `launch_svc.exe` into a permanent directory on the target machine (e.g. `C:\Program Files\YourProject\LaunchService`).

### Step 2: Configure Applications (`app.txt`)
Create a file named `app.txt` in the same folder as `launch_svc.exe`. Add one application or command line per line:

```text
# Example 1: Standard executable
C:\Windows\System32\notepad.exe

# Example 2: Per-user application using environment variables
%LOCALAPPDATA%\Programs\MyApp\app.exe

# Example 3: Chrome/Edge PWA with command-line arguments
"C:\Program Files\Google\Chrome\Application\chrome_proxy.exe" --profile-directory="Profile 1" --app-id=hddihfeenjkjdfhhidapmhkhnhmapanm
```

### Step 3: Install & Start
Open **Command Prompt or PowerShell as Administrator** and run:

```cmd
launch_svc.exe install
launch_svc.exe start
```

*The configured application(s) will immediately appear on the desktop.*

---

## Service Management Commands

Run from an elevated Command Prompt:

| Command | Action |
|---|---|
| `launch_svc.exe install` | Registers the service with Windows SCM to start automatically on boot. |
| `launch_svc.exe start` | Starts the service immediately. |
| `launch_svc.exe status` | Displays current service state (`RUNNING`, `STOPPED`). |
| `launch_svc.exe stop` | Stops the service. |
| `launch_svc.exe uninstall` | Stops and removes the service cleanly from Windows. |

---

## Verification & Telemetry

1. **Verify Non-Admin Rights**:
   - Open **Task Manager** -> **Details** tab.
   - Right-click column headers -> **Select columns** -> enable **Elevated**.
   - Your launched app will display **"No"** under Elevated.

2. **Audit Logs**:
   - Telemetry is written to:
     ```
     C:\ProgramData\LaunchSvcPoc\service.log
     ```
