# Windows 10/11 Endpoint Setup Guide for ForensiTrace

This guide provides step-by-step instructions to configure a fresh Windows 10 or Windows 11 machine (or VM) for ForensiTrace agent telemetry collection.

> **Note:** All configuration commands in this guide must be run manually in an **elevated (Administrator) terminal**. ForensiTrace scripts and agents will **never** alter your system audit policies or clear event logs automatically.

---

## Prerequisites

1. **Operating System:** Windows 10 (Build 1809+) or Windows 11 (Pro, Enterprise, or Home).
2. **User Account:** Local Administrator account.
3. **Python Environment:** Python 3.10+ (64-bit recommended) installed with **"Add python.exe to PATH"** selected during installation.
4. **Git:** Git for Windows installed.

---

## Step 1: Open an Elevated Terminal

1. Press `Win + S` and type `PowerShell` (or `cmd`).
2. Right-click **Windows PowerShell** (or **Command Prompt**) and select **Run as Administrator**.
3. Confirm the User Account Control (UAC) prompt by clicking **Yes**.

---

## Step 2: Enable "Audit Process Creation" (Security Event ID 4688)

By default, Windows does not audit every process creation. You must enable success auditing for the "Process Creation" subcategory so Event ID 4688 is generated.

### Command to Enable Auditing
Run the following command in your elevated terminal:

```cmd
auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable
```

### Verification Command
Confirm the policy is enabled:

```cmd
auditpol /get /subcategory:"Process Creation"
```

**Expected Output:**
```text
System audit policy
Category/Subcategory                      Setting
Detailed Tracking
  Process Creation                        Success and Failure
```

---

## Step 3: Enable Command Line in Process Creation Events

By default, Event ID 4688 records the new process name (e.g., `cmd.exe`) but leaves the `CommandLine` field blank. To capture process command lines (critical for argument reconstruction and correlation):

### Method A: Registry (Works on all editions, including Windows Home)
Run the following command in your elevated terminal:

```cmd
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f
```

### Method B: Group Policy Editor (Windows Pro / Enterprise / Education)
1. Press `Win + R`, type `gpedit.msc`, and press **Enter**.
2. Navigate to:
   `Computer Configuration` > `Administrative Templates` > `System` > `Audit Process Creation`
3. Double-click **Include command line in process creation events**.
4. Set it to **Enabled** and click **OK**.
5. Update policy immediately:
   ```cmd
   gpupdate /force
   ```

### Verification Command
Run the following registry query:

```cmd
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled
```

**Expected Output:**
```text
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit
    ProcessCreationIncludeCmdLine_Enabled    REG_DWORD    0x1
```

---

## Step 4: Confirm Security and System Log Readability

Reading the `Security` event log requires Administrator privileges. Verify that both the `Security` and `System` log channels are enabled and readable.

### 1. Check Security Channel Status
```cmd
wevtutil gl Security
```
Verify that `enabled: true` appears in the output.

### 2. Confirm 4688 Events Are Appearing
Spawn a test process (e.g. `whoami` or `notepad`) and query the most recent 4688 event:

```powershell
notepad.exe
# Close notepad, then query:
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4688} -MaxEvents 1 | Format-List TimeCreated, Id, Message
```
Or via `wevtutil`:
```cmd
wevtutil qe Security "/q:*[System[(EventID=4688)]]" /c:1 /rd:true /f:text
```

### 3. Check System Channel Status
```cmd
wevtutil gl System
```
Verify that `enabled: true` appears in the output.

---

## Step 5: Understanding Log Cleared Events (Scenario Reference)

During forensic scenarios or cover-up testing (Rule R5):
- **Security Log Cleared (Event ID 1102):** Logged into `Security` when an administrator clears the Security log (e.g., `wevtutil cl Security`).
- **System Log Cleared (Event ID 104):** Logged into `System` when an administrator clears the System log (e.g., `wevtutil cl System`).

> ⚠️ **Warning:** Clearing event logs deletes historical telemetry on the host. Do NOT run clear commands during normal collection. Only execute log clear commands when explicitly testing scenario C on a dedicated test VM.

---

## Step 6: Clone Repository & Set Up Python Virtual Environment

Clone the repository and set up a dedicated virtual environment in an elevated terminal:

```powershell
# Navigate to your working directory
cd C:\PROJECTS\FORENSITRACE_1

# Create virtual environment
python -m venv venv

# Activate virtual environment
.\venv\Scripts\Activate.ps1
```
*(If PowerShell blocks script execution, run `Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process` first).*

### Install Required Dependencies
Ensure the project's core libraries are installed:

```powershell
pip install pywin32 python-evtx watchdog fastapi uvicorn requests
```

---

## Step 7: Run the Event Log Probe

Before running the agent, run the read-only probe script to verify which target Event IDs are present and inspect their raw field structures:

```powershell
python scenarios/probes/probe_eventlog.py
```

Check the console output:
- It will verify administrator privileges.
- It will inspect the last occurrence of Event ID 4688, 1102, and 104.
- Copy and record the output into `docs/evidence_notes/eventlog.md`.

---

## Step 8: Run the ForensiTrace Agent

Once the probe succeeds, run the ForensiTrace agent from the elevated terminal:

```powershell
python -m agent.main
```
The agent will initialize configured collectors (Event Log, USB, File System) and begin buffering and shipping telemetry to the backend ingestion endpoint.
