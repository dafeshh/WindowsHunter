# Window Hunter

> CLI tool to enumerate, manipulate, detect, screenshot, and monitor windows on Windows.
> Built for learning Windows API and malware analysis techniques.

## Features

### Tree listing

```
Window_Hunter.exe                          # List all windows as a tree
Window_Hunter.exe /pid 1234                # Filter by process ID
Window_Hunter.exe /title "Chrome"          # Filter by window title (substring)
Window_Hunter.exe /class "Notepad"         # Filter by class name (substring)
```

Displays the full window hierarchy: `Desktop → Process → Window → Child Window`.

### Window actions (11)

| Flag | Action |
|------|--------|
| `/h` `/hide` | Hide window |
| `/s` `/show` | Show hidden window |
| `/c` `/close` | Close window (`WM_CLOSE`) |
| `/k` `/kill` | Kill process (`TerminateProcess`) |
| `/min` `/minimize` | Minimize to taskbar |
| `/max` `/maximize` | Maximize to fullscreen |
| `/r` `/restore` | Restore previous size |
| `/d` `/disable` | Disable (grayed out, no input) |
| `/e` `/enable` | Re-enable |
| `/f` `/flash` | Flash on taskbar |
| `/t` `/top` | Keep on top |

Actions require a filter (`/pid`, `/title`, or `/class`):

```
Window_Hunter.exe /hide /pid 1234
Window_Hunter.exe /close /title "Notepad"
Window_Hunter.exe /topmost /class "Chrome_WidgetWin_1"
```

### Detect

```
Window_Hunter.exe /detect                   # All: debugger + hidden
Window_Hunter.exe /detect debugger          # Detect analysis tools
Window_Hunter.exe /detect hidden            # Detect non-visible windows
```

Detected tools: x64dbg, x32dbg, IDA Pro, WinDbg, OllyDbg, Wireshark, Process Monitor.

### Screenshot

```
Window_Hunter.exe /scr                      # Full screen (PrtSc)
Window_Hunter.exe /scr /pid 1234            # Capture specific process window
Window_Hunter.exe /scr                      # Capture window matching title
Window_Hunter.exe "C:\Shots" /scr           # Custom save folder
```

Saves as BMP. Default folder is the current directory.

### Real-time monitor

```
Window_Hunter.exe /monitor                  # Monitor all window events
Window_Hunter.exe /monitor /pid 1234        # Monitor one process only
Window_Hunter.exe /monitor /title "Chrome"    # Monitor windows matching title
```

Events tracked: `CREATE`, `DESTROY`, `SHOW`, `HIDE`, `RENAME`, `FOREGROUND`.

Automatically saves to a timestamped `.log` file. Auto-flushes every 3 minutes. Press `Ctrl+C` to stop (final flush + clean exit).

## Filters

| Flag | Description |
|------|-------------|
| `/pid` `<N>` | Filter by process ID |
| `/title` `<text>` | Filter by window title (case-insensitive substring) |
| `/class` `<name>` | Filter by class name (case-insensitive substring) |
| `/help` | Show help |

## Build

```powershell
cl /EHsc /std:c++17 Source.cpp user32.lib gdi32.lib advapi32.lib Shlwapi.lib
```

**Requirements:** Visual Studio 2022, Windows SDK.

## Architecture

```
Source.cpp
├── struct TREE                  # Tree node: Process / Window
├── BuildTree()                  # EnumWindows + EnumChildWindows
├── PrintTree()                  # Pretty-print with ├── └── branches
├── ScanTree()                   # Search windows by filter
├── IsNodeMatch() / HasAnyMatch()# Filter matching logic
│
├── Actions (11)                 # Hide, Show, Close, Kill, ...
├── ExectOption()                # Dispatch actions over matched HWNDs
│
├── DetectDBG()                  # Debugger detection (rule-based)
├── DetectHidden()               # Non-visible window detection
│
├── ScreenShotWindows()          # Full-screen + per-window capture (BMP)
│
├── Monitor()                    # SetWinEventHook + message loop + file log
├── WinEvtProc()                 # Window event callback
├── WriteLog()                   # Log event to file
│
├── PrintHelp()                  # Help text
└── wmain()                      # Parse argv → dispatch to mode
```

## Windows APIs used

| API | Purpose |
|-----|---------|
| `EnumWindows` / `EnumChildWindows` | Enumerate windows |
| `GetWindowTextW` / `RealGetWindowClassW` | Title & class name |
| `GetWindowThreadProcessId` | Map HWND → PID |
| `CreateToolhelp32Snapshot` | Enumerate processes |
| `ShowWindow` | Hide/show/minimize/maximize |
| `EnableWindow` | Disable/enable |
| `PostMessage(WM_CLOSE)` | Close window |
| `TerminateProcess` | Kill process |
| `FlashWindow` / `SetWindowPos` | Flash taskbar / topmost |
| `PrintWindow` / `BitBlt` | Window screenshot |
| `GetDC` / `CreateCompatibleDC` / `GetDIBits` | BMP output |
| `SetWinEventHook` | System-wide window event hook |
| `QueryFullProcessImageNameW` | Process path from PID |


## License

MIT — Free to use for learning and research.
