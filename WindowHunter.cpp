#include <stdio.h>
#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>
#include <vector>
#include <string>
#include <Shlwapi.h>
#include <set>
#include <chrono>
#include <iomanip>
#include <filesystem>
#include <sstream>
#include <unordered_map>

#pragma comment(lib, "Shlwapi.lib")

enum class TREETYPE {
	Process,
	Windows
};


typedef struct TREE {
	TREETYPE type;
	DWORD Pid;
	HWND hwnd;
	std::wstring PrName;
	wchar_t Title[256];
	wchar_t Classname[256];
	std::vector<TREE*> Child;
}TREEDATA, * PTREEDATA;


struct EnumCtx {
	std::unordered_map<DWORD, PTREEDATA>* PidMap;
};


struct Option {
	bool Hide = false;
	bool Show = false;
	bool Close = false;
	bool Kill = false;
	bool Minimize = false;
	bool Maximize = false;
	bool Restore = false;
	bool Disable = false;
	bool Enable = false;
	bool Flashing = false;
	bool Topmost = false;
	bool List = false;
	bool ForcePid = false;
	bool Screenshot = false;
	bool Detect = false;
	bool DetectDBG = false;
	bool DetectTiny = false;
	bool DetectHidden = false;
	bool DetectTopmost = false;
	bool Monitor = false;
	bool Output = false;
	std::wstring SavePath = L"";
	DWORD TargetPid = 0;
	wchar_t Title[256] = L"";
	wchar_t Class[256] = L"";
};


struct DebuggerRule {
	const wchar_t* classname;
	const wchar_t* title;
	const wchar_t* process;
	const wchar_t* description;
};



const DebuggerRule DBGRules[] = {//add more in future
	{L"QWindowIcon", nullptr, L"x64dbg.exe", L"x64dbg"},
	{L"QWindowIcon", nullptr, L"x32dbg.exe", L"x32dbg"},
	{L"QWindowIcon", L"IDA", nullptr, L"IDA Pro"},
	{L"QWindowIcon", L"Wireshark", nullptr, L"Wireshark"},
	{L"WinDbgFrameClass", nullptr, nullptr, L"WinDbg"},
	{L"OLLYDBG", nullptr, nullptr, L"OllyDbg"},
	{nullptr, nullptr, L"procmon64.exe", L"Process Monitor"},
	{nullptr, nullptr, L"procmon.exe", L"Process Monitor"},
	{nullptr, nullptr, L"windbg.exe", L"WinDbg"},
	{nullptr, nullptr, L"ollydbg.exe", L"OllyDbg"},
	{nullptr, L"Process Monitor", nullptr, L"Process Monitor"},
};



void AddChild(TREE* Parent, TREE* Children) {
	Parent->Child.push_back(Children);
}



TREE* CreateNode(TREETYPE type) {
	TREE* node = new TREE;
	node->Pid = 0;
	node->hwnd = nullptr;
	node->PrName = L"";
	node->Title[0] = L'\0';
	node->Classname[0] = L'\0';
	node->type = type;

	return node;
}



std::wstring GetProcessNameByPid(DWORD Pid) {
	wchar_t Path[MAX_PATH];
	DWORD pathLen = MAX_PATH;
	HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, Pid);
	if (!hProcess) {
		return L"Unknow";
	}

	if (!QueryFullProcessImageNameW(hProcess, 0, Path, &pathLen)) {
		CloseHandle(hProcess);
		return L"Unknow";
	}

	CloseHandle(hProcess);
	std::wstring FullPath(Path, pathLen);
	size_t Pos = FullPath.find_last_of(L"\\/");
	if (Pos != std::wstring::npos)
		return FullPath.substr(Pos + 1);

	return FullPath;
}



BOOL CALLBACK EnumChildProc(HWND hwnd, LPARAM lParam) {
	if (!IsWindowVisible(hwnd))
		return TRUE;

	PTREEDATA WindowsNode = (PTREEDATA)lParam;
	PTREEDATA WindowsChild = CreateNode(TREETYPE::Windows);
	WindowsChild->hwnd = hwnd;
	WindowsChild->Pid = WindowsNode->Pid;
	RealGetWindowClassW(WindowsChild->hwnd, WindowsChild->Classname, 256);
	WindowsChild->PrName = WindowsNode->PrName;
	AddChild(WindowsNode, WindowsChild);
	EnumChildWindows(WindowsChild->hwnd, EnumChildProc, (LPARAM)WindowsChild);
	return TRUE;
}




BOOL CALLBACK EnumWindowsProc(HWND hwnd, LPARAM lParam) {
	EnumCtx* ctx = (EnumCtx*)lParam;
	DWORD Pid;
	GetWindowThreadProcessId(hwnd, &Pid);
	auto it = ctx->PidMap->find(Pid);
	if (it == ctx->PidMap->end())
		return TRUE;
	PTREEDATA ProcessNode = it->second;
	TREE* WindowsNode = CreateNode(TREETYPE::Windows);
	WindowsNode->hwnd = hwnd;
	GetWindowTextW(WindowsNode->hwnd, WindowsNode->Title, 256);
	RealGetWindowClassW(WindowsNode->hwnd, WindowsNode->Classname, 256);
	WindowsNode->Pid = Pid;
	WindowsNode->PrName = ProcessNode->PrName;
	AddChild(ProcessNode, WindowsNode);
	EnumChildWindows(WindowsNode->hwnd, EnumChildProc, (LPARAM)WindowsNode);
	return TRUE;
}



Option MonitorOpt{};
HANDLE hLogFile = INVALID_HANDLE_VALUE;
void WriteLog(std::wstring Event, HWND hwnd, DWORD Pid, std::wstring ProcessName, std::wstring Title, std::wstring Classname) {
	wchar_t Buffer[1024];
	std::wstring Format_Msg = L"%s  HWND: %p  -  PROCESS: %s  -  PID: %u  -  TTILE: %s  -  CLASSNAME: %s\n";
	swprintf_s(Buffer, _countof(Buffer), Format_Msg.c_str(), Event.c_str(), hwnd, ProcessName.c_str(), Pid, Title.c_str(), Classname.c_str());
	if (hLogFile == INVALID_HANDLE_VALUE) {
		std::wcout << L"Create file fail\n";
		return;
	}
	DWORD WrittenBytes;
	WriteFile(hLogFile, Buffer, (DWORD)(wcslen(Buffer) * sizeof(wchar_t)), &WrittenBytes, NULL);
}



BOOL WINAPI HandlerRoutine(DWORD Sig) {
	if (Sig == CTRL_C_EVENT) {
		wchar_t End[] = L"Monitor Stoped\n";
		DWORD WrittenBytes;
		WriteFile(hLogFile, End, (DWORD)(wcslen(End) * sizeof(wchar_t)), &WrittenBytes, NULL);
		FlushFileBuffers(hLogFile);
		CloseHandle(hLogFile);
		std::wcout << L"Monitor Stoped\n";
		exit(0);
	}
	return TRUE;
}





void CALLBACK WinEvtProc(HWINEVENTHOOK hWinEvtHook, DWORD Event, HWND hwnd, LONG idObject, LONG idChild, DWORD idEventThread, DWORD dwmsEventTime) {
	if (idObject != OBJID_WINDOW || idChild != CHILDID_SELF)
		return;

	DWORD Pid;
	GetWindowThreadProcessId(hwnd, &Pid);

	wchar_t Title[256], Classname[256];
	GetWindowTextW(hwnd, Title, 256);
	RealGetWindowClassW(hwnd, Classname, 256);
	std::wstring ProcessName = GetProcessNameByPid(Pid);

	if (MonitorOpt.TargetPid != 0 && MonitorOpt.TargetPid != Pid)
		return;
	if (MonitorOpt.Title[0] != L'\0' && StrStrIW(Title, MonitorOpt.Title) == NULL)
		return;
	if (MonitorOpt.Class[0] != L'\0' && StrStrIW(Classname, MonitorOpt.Class) == NULL)
		return;

	switch (Event) {
	case EVENT_OBJECT_CREATE:
		std::wprintf(L"[CREATE]  HWND: %p  -  PROCESS: %s  -  PID: %u  -  TTILE: %s  -  CLASSNAME: %s\n", hwnd, ProcessName.c_str(), Pid, Title, Classname);
		WriteLog(L"[CREATE]", hwnd, Pid, ProcessName, Title, Classname);
		break;
	case EVENT_OBJECT_DESTROY:
		std::wprintf(L"[DESTROY] HWND: %p  -  PROCESS: %s  -  PID: %u  -  TTILE: %s  -  CLASSNAME: %s\n", hwnd, ProcessName.c_str(), Pid, Title, Classname);
		WriteLog(L"[DESTROY]", hwnd, Pid, ProcessName, Title, Classname);
		break;
	case EVENT_OBJECT_HIDE:
		std::wprintf(L"[HIDE]    HWND: %p  -  PROCESS: %s  -  PID: %u  -  TTILE: %s  -  CLASSNAME: %s\n", hwnd, ProcessName.c_str(), Pid, Title, Classname);
		WriteLog(L"[HIDE]", hwnd, Pid, ProcessName, Title, Classname);
		break;
	case EVENT_OBJECT_SHOW:
		std::wprintf(L"[SHOW]    HWND: %p  -  PROCESS: %s  -  PID: %u  -  TTILE: %s  -  CLASSNAME: %s\n", hwnd, ProcessName.c_str(), Pid, Title, Classname);
		WriteLog(L"[SHOW]", hwnd, Pid, ProcessName, Title, Classname);
		break;
	case EVENT_OBJECT_NAMECHANGE:
		std::wprintf(L"[RENAME]  HWND: %p  -  PROCESS: %s  -  PID: %u  -  TTILE: %s  -  CLASSNAME: %s\n", hwnd, ProcessName.c_str(), Pid, Title, Classname);
		WriteLog(L"[RENAME]", hwnd, Pid, ProcessName, Title, Classname);
		break;
	case EVENT_SYSTEM_FOREGROUND:
		std::wprintf(L"[FOREGROUND] HWND: %p  -  PROCESS: %s  -  PID: %u  -  TTILE: %s  -  CLASSNAME: %s\n", hwnd, ProcessName.c_str(), Pid, Title, Classname);
		WriteLog(L"[FOREGROUND]", hwnd, Pid, ProcessName, Title, Classname);
		break;
	}

}



TREE* BuildTree() {
	TREE* root = CreateNode(TREETYPE::Process);
	root->PrName = L"ROOT";

	HANDLE hPROCESSNAP;
	PROCESSENTRY32W pe32;

	hPROCESSNAP = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	pe32.dwSize = sizeof(PROCESSENTRY32W);
	if (!Process32FirstW(hPROCESSNAP, &pe32)) {
		std::wcout << L"There some problem with you\n";
		CloseHandle(hPROCESSNAP);
		return NULL;
	}

	std::unordered_map<DWORD, PTREEDATA> pidMap;

	do {
		TREE* ProcessNode = CreateNode(TREETYPE::Process);
		AddChild(root, ProcessNode);
		ProcessNode->Pid = pe32.th32ProcessID;
		ProcessNode->PrName = pe32.szExeFile;

		pidMap[ProcessNode->Pid] = ProcessNode;
	} while (Process32NextW(hPROCESSNAP, &pe32));

	CloseHandle(hPROCESSNAP);

	EnumCtx ctx{ &pidMap };
	EnumWindows(EnumWindowsProc, (LPARAM)&ctx);

	return root;
}



void FreeTree(TREE* node) {
	if (!node)
		return;
	for (TREE* child : node->Child) {
		FreeTree(child);
	}
	delete node;
}



bool IsNodeMatch(TREE* node, Option* Opt) {
	if (Opt == nullptr)
		return true;
	if (node->type == TREETYPE::Process)
		return false;

	if (Opt->TargetPid != 0 && node->Pid != Opt->TargetPid)
		return false;
	if (Opt->Title[0] != L'\0' && StrStrIW(node->Title, Opt->Title) == NULL)
		return false;
	if (Opt->Class[0] != L'\0' && StrStrIW(node->Classname, Opt->Class) == NULL)
		return false;

	return true;
}



bool HasAnyMatch(TREE* node, Option* Opt) {
	if (Opt == nullptr)
		return true;
	if (IsNodeMatch(node, Opt))
		return true;
	for (auto* Child : node->Child) {
		if (HasAnyMatch(Child, Opt))
			return true;
	}
	return false;
}



void PrintTree(TREE* node, const std::wstring& prefix, bool isLast, Option* Opt = nullptr) {
	if (node == nullptr) return;

	if (!HasAnyMatch(node, Opt)) return;

	wprintf(L"%s", prefix.c_str());

	if (node->PrName == L"ROOT") {
		wprintf(L"Desktop\n");
	}
	else {
		wprintf(L"%s", isLast ? L"+-- " : L"|-- ");

		if (node->type == TREETYPE::Process) {
			wprintf(L"PID: %u  %s (Process)\n",
				node->Pid, node->PrName.c_str());
		}
		else {
			if (node->Title[0] != L'\0')
				wprintf(L"PID: %u \"%s\" | \"%s\" (Window)\n", node->Pid, node->Title, node->Classname);
			else
				wprintf(L"PID: %u \"%s\" (Window Child)\n", node->Pid, node->Classname);
		}


	}

	std::wstring childPrefix = prefix;
	if (node->PrName != L"ROOT") {
		childPrefix += (isLast ? L"    " : L"|   ");
	}
	for (size_t i = 0; i < node->Child.size(); i++) {
		PrintTree(node->Child[i], childPrefix, i == node->Child.size() - 1, Opt);
	}
}



void ScanTree(TREE* node, Option* Opt, std::vector<HWND>& Result) {
	if (node == nullptr)
		return;

	if (node->type == TREETYPE::Windows && IsNodeMatch(node, Opt)) {
		Result.push_back(node->hwnd);
	}

	for (auto* Child : node->Child) {
		ScanTree(Child, Opt, Result);
	}
}



void DetectDBG(TREE* node) {
	static std::set<DWORD> DBGPids = { 0 };
	for (auto& Rule : DBGRules) {
		bool hit = true;
		if (Rule.classname && StrStrIW(node->Classname, Rule.classname) == NULL)
			hit = false;
		if (Rule.title && StrStrIW(node->Title, Rule.title) == NULL)
			hit = false;
		if (Rule.process && StrStrIW(node->PrName.c_str(), Rule.process) == NULL)
			hit = false;

		if (hit && DBGPids.insert(node->Pid).second) {
			wprintf(L"PID: %u -- %s (Debugger)\n", node->Pid, Rule.description);
		}
	}
}



void DetectHidden(TREE* node) {
	static std::set<DWORD> HiddenPid;
	bool hit = true;
	if (IsWindowVisible(node->hwnd) != 0)
		hit = false;

	if (hit && HiddenPid.insert(node->Pid).second)
		wprintf(L"Pid: %u -- %s (Hidden)\n", node->Pid, node->PrName.c_str());
}



void ScanDetect(TREE* node, Option* Opt) {
	if (node == nullptr)
		return;

	if (node->type == TREETYPE::Windows && IsNodeMatch(node, Opt)) {
		if (Opt->DetectDBG)
			DetectDBG(node);

		if (Opt->DetectHidden)
			DetectHidden(node);
	}
	for (auto* Child : node->Child)
		ScanDetect(Child, Opt);
}



bool IsValidPid(DWORD TargetPid) {
	if (TargetPid == 0) {
		std::wcout << "Invalid Pid.\n";
		return false;
	}
	HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, TargetPid);
	if (hProcess == NULL) {
		std::wcout << "Pid: " << TargetPid << " does not exist or insufficient authority.\n";
		return false;
	}
	CloseHandle(hProcess);
	return true;
}



void HideWindows(HWND hwnd) {
	ShowWindow(hwnd, SW_HIDE);
}



void ShowWindows(HWND hwnd) {
	ShowWindow(hwnd, SW_SHOW);
}



void CloseWindows(HWND hwnd) {
	PostMessageW(hwnd, WM_CLOSE, 0, 0);
}



void KillWindows(Option* Opt) {
	HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, Opt->TargetPid);
	TerminateProcess(hProcess, 1);
	CloseHandle(hProcess);
}



void MinimizeWindows(HWND hwnd) {
	CloseWindow(hwnd);
}


void MaximizeWindows(HWND hwnd) {
	PostMessageW(hwnd, WM_SYSCOMMAND, SC_MAXIMIZE, 0);
}



void RestoreWindows(HWND hwnd) {
	//GetHwndByPid(Opt->TargetPid, Opt);
	ShowWindow(hwnd, SW_RESTORE);
}



void DisableWindows(HWND hwnd) {
	EnableWindow(hwnd, FALSE);
}



void EnableWindows(HWND hwnd) {
	EnableWindow(hwnd, TRUE);
}



void FlashingWindows(HWND hwnd) {
	FlashWindow(hwnd, TRUE);
}



void WindowsOnTop(HWND hwnd) {
	SetWindowPos(hwnd, HWND_TOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE);
}



std::wstring GetSaveFilePath(std::wstring Savepath) {
	/*std::wstring pathtofilename = L"E:\\Screenshotdemo\\";*/
	if (Savepath.empty()) {
		wchar_t CurrentPath[MAX_PATH];
		GetCurrentDirectoryW(MAX_PATH, CurrentPath);
		Savepath = CurrentPath;
	}

	auto now = std::chrono::system_clock::now();
	auto milisec = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()) % 1000;
	std::time_t t = std::chrono::system_clock::to_time_t(now);
	std::tm tm = {};
	localtime_s(&tm, &t);

	std::wostringstream filename;
	filename << std::put_time(&tm, L"%Y-%m-%d_%H-%M-%S") << L"-" << std::setfill(L'0') << std::setw(3) << milisec.count();

	if (Savepath.back() == L'\\' || Savepath.back() == L'/')
		return Savepath + filename.str();
	return Savepath + L"\\" + filename.str();
}



void ScreenShotWindows(std::wstring SavePath) {
	std::wstring path = GetSaveFilePath(SavePath) + L".bmp";

	HDC hScreenDC = GetDC(NULL);
	HDC hMemoryDC = CreateCompatibleDC(hScreenDC);

	int Width = GetSystemMetrics(SM_CXSCREEN);
	int Height = GetSystemMetrics(SM_CYSCREEN);

	HBITMAP hBmpScreen = CreateCompatibleBitmap(hScreenDC, Width, Height);

	HGDIOBJ hOldBmp = SelectObject(hMemoryDC, hBmpScreen);

	BitBlt(hMemoryDC, 0, 0, Width, Height, hScreenDC, 0, 0, SRCCOPY);

	SelectObject(hMemoryDC, hOldBmp);

	BITMAPFILEHEADER bmfHeader{};
	BITMAPINFOHEADER bi{};
	bi.biSize = sizeof(BITMAPINFOHEADER);
	bi.biWidth = Width;
	bi.biHeight = Height;
	bi.biPlanes = 1;
	bi.biCompression = BI_RGB;
	bi.biBitCount = 32;

	DWORD dwBmpSize = ((Width * bi.biBitCount + 31) / 32) * 4 * Height;
	HGLOBAL hDIB = GlobalAlloc(GHND, dwBmpSize);

	if (hDIB == NULL) {
		DeleteDC(hMemoryDC);
		ReleaseDC(NULL, hScreenDC);
		std::cout << "GlobalAlloc Fail\n";
		return;
	}

	char* lpbitmap = (char*)GlobalLock(hDIB);

	if (lpbitmap == NULL) {
		GlobalFree(hDIB);
		std::cout << "GlobalLock Fail\n";
		return;
	}

	GetDIBits(hMemoryDC, hBmpScreen, 0, Height, lpbitmap, (BITMAPINFO*)&bi, DIB_RGB_COLORS);

	HANDLE hFILE = CreateFileW(path.c_str(), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

	DWORD dwFileWritten = 0;
	bmfHeader.bfSize = (DWORD)sizeof(BITMAPFILEHEADER) + (DWORD)sizeof(BITMAPINFOHEADER) + dwBmpSize;
	bmfHeader.bfOffBits = sizeof(BITMAPFILEHEADER) + sizeof(BITMAPINFOHEADER);
	bmfHeader.bfType = 0x4d42;

	WriteFile(hFILE, (LPSTR)&bmfHeader, sizeof(BITMAPFILEHEADER), &dwFileWritten, NULL);
	WriteFile(hFILE, (LPSTR)&bi, sizeof(BITMAPINFOHEADER), &dwFileWritten, NULL);
	WriteFile(hFILE, (LPSTR)lpbitmap, dwBmpSize, &dwFileWritten, NULL);

	CloseHandle(hFILE);
	GlobalUnlock(hDIB);
	GlobalFree(hDIB);

	DeleteObject(hBmpScreen);
	DeleteDC(hMemoryDC);
	ReleaseDC(NULL, hScreenDC);
}


void ScreenShotWindows(HWND hwnd, std::wstring SavePath) {
	std::wstring path = GetSaveFilePath(SavePath) + L".bmp";
	HDC WindowDC = GetDC(hwnd);
	HDC MemoryDC = CreateCompatibleDC(WindowDC);

	RECT R;
	GetClientRect(hwnd, &R);
	int Width = R.right - R.left;
	int Height = R.bottom - R.top;

	HBITMAP hbmWindow = CreateCompatibleBitmap(WindowDC, Width, Height);

	if (!hbmWindow) {
		std::cout << "Failed to create window bitmap\n";
		DeleteDC(MemoryDC);
		ReleaseDC(hwnd, WindowDC);
		return;
	}

	HBITMAP hOldBmp = (HBITMAP)SelectObject(MemoryDC, hbmWindow);
	PrintWindow(hwnd, MemoryDC, PW_RENDERFULLCONTENT);

	BITMAPFILEHEADER bmfHeader{};
	BITMAPINFOHEADER bi{};
	bi.biSize = sizeof(BITMAPINFOHEADER);
	bi.biWidth = Width;
	bi.biHeight = Height;
	bi.biPlanes = 1;
	bi.biCompression = BI_RGB;
	bi.biBitCount = 32;

	DWORD dwBmpSize = ((Width * bi.biBitCount + 31) / 32) * 4 * Height;
	HGLOBAL hDIB = GlobalAlloc(GHND, dwBmpSize);

	if (hDIB == NULL) {
		DeleteDC(MemoryDC);
		ReleaseDC(hwnd, WindowDC);
		std::cout << "GlobalAlloc failed\n";
		return;
	}

	char* lpbitmap = (char*)GlobalLock(hDIB);

	if (lpbitmap == NULL) {
		GlobalFree(hDIB);
		std::cout << "GlobalLock failed\n";
		return;
	}

	GetDIBits(MemoryDC, hbmWindow, 0, Height, lpbitmap, (BITMAPINFO*)&bi, DIB_RGB_COLORS);

	HANDLE hFILE = CreateFileW(path.c_str(), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

	DWORD dwFileWritten = 0;
	bmfHeader.bfSize = (DWORD)sizeof(BITMAPFILEHEADER) + (DWORD)sizeof(BITMAPINFOHEADER) + dwBmpSize;
	bmfHeader.bfOffBits = sizeof(BITMAPFILEHEADER) + sizeof(BITMAPINFOHEADER);
	bmfHeader.bfType = 0x4d42;

	WriteFile(hFILE, (LPSTR)&bmfHeader, sizeof(BITMAPFILEHEADER), &dwFileWritten, NULL);
	WriteFile(hFILE, (LPSTR)&bi, sizeof(BITMAPINFOHEADER), &dwFileWritten, NULL);
	WriteFile(hFILE, (LPSTR)lpbitmap, dwBmpSize, &dwFileWritten, NULL);

	CloseHandle(hFILE);
	GlobalUnlock(hDIB);
	GlobalFree(hDIB);

	SelectObject(MemoryDC, hOldBmp);
	DeleteObject(hbmWindow);
	DeleteDC(MemoryDC);
	ReleaseDC(hwnd, WindowDC);
}




void Monitor(std::wstring Path) {
	std::wstring LogPath = GetSaveFilePath(Path) + L".log";
	hLogFile = CreateFileW(LogPath.c_str(), FILE_APPEND_DATA, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

	HWINEVENTHOOK hook1 = SetWinEventHook(EVENT_MIN, EVENT_MAX, NULL, WinEvtProc, 0, 0, WINEVENT_OUTOFCONTEXT | WINEVENT_SKIPOWNPROCESS);

	if (!hook1) {
		std::wcout << "Hook Fail Try again!\n";
		if (hook1)
			UnhookWinEvent(hook1);
		return;
	}

	SetConsoleCtrlHandler(HandlerRoutine, TRUE);
	SetTimer(NULL, 0, 180000, NULL);

	MSG Msg{};
	while (GetMessageW(&Msg, NULL, 0, 0)) {
		if (Msg.message == WM_TIMER) {
			FlushFileBuffers(hLogFile);
			continue;
		}
		TranslateMessage(&Msg);
		DispatchMessageW(&Msg);
	}
	if (hook1)
		UnhookWinEvent(hook1);
}



void ExectOption(Option* Opt, std::vector<HWND> Target) { //note: break is very important:))
	for (HWND hwnd : Target) {
		if (Opt->Kill) {
			KillWindows(Opt);
			break;
		}

		else if (Opt->Hide) {
			HideWindows(hwnd);
			break;
		}

		else if (Opt->Show) {
			ShowWindows(hwnd);
			break;
		}

		else if (Opt->Close) {
			CloseWindows(hwnd);
			break;
		}

		else if (Opt->Minimize) {
			MinimizeWindows(hwnd);
			break;
		}

		else if (Opt->Maximize) {
			MaximizeWindows(hwnd);
			break;
		}

		else if (Opt->Restore) {
			RestoreWindows(hwnd);
			break;
		}

		else if (Opt->Disable) {
			DisableWindows(hwnd);
			break;
		}

		else if (Opt->Enable) {
			EnableWindows(hwnd);
			break;
		}

		else if (Opt->Flashing) {
			FlashingWindows(hwnd);
			break;
		}

		else if (Opt->Topmost) {
			WindowsOnTop(hwnd);
			break;
		}

		else if (Opt->Screenshot) {
			if (!Opt->TargetPid) {
				ScreenShotWindows(Opt->SavePath);
				break;
			}
			else {
				ScreenShotWindows(hwnd, Opt->SavePath);
				break;
			}
		}
	}
}



void PrintHelp() {
	std::wcout << L"\n"
		<< L"\n"
		<< L"  USAGE:  Window_Hunter.exe [Path] <mode> [filters]\n"
		<< L"  NOTE: [Path]: Save directory (only for /scr and /monitor)\n"
		<< L"\n"
		<< L"                   MODES\n"
		<< L"  (default)          List all windows as a tree\n"
		<< L"  /h, /hide          Hide window\n"
		<< L"  /s, /show          Show hidden window\n"
		<< L"  /c, /close         Close window\n"
		<< L"  /k, /kill          Kill process - TerminateProcess\n"
		<< L"  /min, /minimize    Minimize window\n"
		<< L"  /max, /maximize    Maximize window\n"
		<< L"  /r, /restore       Restore window size\n"
		<< L"  /d, /disable       Disable window - grayed out\n"
		<< L"  /e, /enable        Enable window\n"
		<< L"  /f, /flash         Flash window on taskbar\n"
		<< L"  /t, /top           Keep window on top\n"
		<< L"  /scr, /screenshot  Capture screenshot\n"
		<< L"  /detect            Detect debugger / hidden / tiny\n"
		<< L"  /monitor           Monitor window events in realtime\n"
		<< L"  /?, /help          Show this help\n"
		<< L"\n"
		<< L"                   FILTERS\n"
		<< L"  /pid    <PID>      Filter by process ID\n"
		<< L"  /title  <text>     Filter by window title (substring)\n"
		<< L"  /class  <name>     Filter by class name (substring)\n"
		<< L"\n"
		<< L"                   DETECT\n"
		<< L"  /detect            All: debugger + hidden\n"
		<< L"  /detect debugger   Detect analysis tools\n"
		<< L"  /detect hidden     Detect non-visible windows\n"
		<< L"\n"
		<< L"                   MONITOR\n"
		<< L"  /monitor           Monitor all window events + save .log\n"
		<< L"  Events: CREATE | DESTROY | SHOW | HIDE | RENAME | FOREGROUND\n"
		<< L"  Auto-save every 3 min | Ctrl+C to stop\n"
		<< L"\n"
		<< L"                   EXAMPLES\n"
		<< L"  Window_Hunter.exe\n"
		<< L"  Window_Hunter.exe /title \"Notepad\"\n"
		<< L"  Window_Hunter.exe /hide /pid 1234\n"
		<< L"  Window_Hunter.exe \"C:\\Screenshot\" /scr /pid 1234\n"
		<< L"  Window_Hunter.exe /detect debugger\n"
		<< L"  Window_Hunter.exe /monitor\n"
		<< L"\n";
}


int wmain(int argc, wchar_t* argv[]) {
	SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);
	Option Opt;
	std::vector<HWND> Target;
	TREE* ROOT = BuildTree();

	if (argc <= 1) {
		PrintTree(ROOT, L"", true);
		FreeTree(ROOT);
		return 1;
	}


	else {
		wchar_t* arg = argv[1];
		if (arg[0] != L'/') {
			Opt.SavePath = argv[1];
			if (GetFileAttributesW(Opt.SavePath.c_str()) == INVALID_FILE_ATTRIBUTES) {
				std::wcout << "Directory not found\n";
				return -1;
			}

		}

		for (int i = 1; i <= argc - 1; i++) {
			if (!StrCmpW(argv[i], L"/?") || !StrCmpW(argv[i], L"/help")) {
				PrintHelp();
				exit(0);
			}

			if (!StrCmpW(argv[i], L"/pid")) {
				if (i + 1 < argc) {
					Opt.TargetPid = static_cast<DWORD>(wcstoul(argv[i + 1], nullptr, 10));
					Opt.ForcePid = true;
					bool Valid = IsValidPid(Opt.TargetPid);
					if (!Valid)
						exit(0);
				}
				else {
					std::wcout << "Pid should not be blank.\n";
					exit(0);
				}
			}

			if (!StrCmpW(argv[i], L"/detect")) {
				Opt.Detect = true;
				if (i + 1 < argc) {
					if (!StrCmpW(argv[i + 1], L"debugger"))
						Opt.DetectDBG = true;
					else if (!StrCmpW(argv[i + 1], L"tiny"))
						Opt.DetectTiny = true;
					else if (!StrCmpW(argv[i + 1], L"hidden"))
						Opt.DetectHidden = true;
				}
				else
					Opt.DetectDBG = Opt.DetectHidden = Opt.DetectTiny = true;
			}

			if (!StrCmpW(argv[i], L"/title")) {
				if (i + 1 < argc) {
					StrCpyW(Opt.Title, argv[i + 1]);
				}
				else {
					std::wcout << "Title should not be blank.\n";
					exit(0);
				}
			}

			if (!StrCmpW(argv[i], L"/class")) {
				if (i + 1 < argc) {
					StrCpyW(Opt.Class, argv[i + 1]);
				}
				else {
					std::wcout << "Class name should not be blank.\n";
					exit(0);
				}
			}

			if (!StrCmpW(argv[i], L"/out")) {
				if (i + 1 < argc)
					Opt.SavePath = argv[i + 1];
			}

			if (!StrCmpW(argv[i], L"/h") || !StrCmpW(argv[i], L"/hide"))
				Opt.Hide = true;
			else if (!StrCmpW(argv[i], L"/s") || !StrCmpW(argv[i], L"/show"))
				Opt.Show = true;
			else if (!StrCmpW(argv[i], L"/c") || !StrCmpW(argv[i], L"/close"))
				Opt.Close = true;
			else if (!StrCmpW(argv[i], L"/k") || !StrCmpW(argv[i], L"/kill"))
				Opt.Kill = true;
			else if (!StrCmpW(argv[i], L"/min") || !StrCmpW(argv[i], L"/minimize"))
				Opt.Minimize = true;
			else if (!StrCmpW(argv[i], L"/max") || !StrCmpW(argv[i], L"/maximize"))
				Opt.Maximize = true;
			else if (!StrCmpW(argv[i], L"/r") || !StrCmpW(argv[i], L"/restore"))
				Opt.Restore = true;
			else if (!StrCmpW(argv[i], L"/d") || !StrCmpW(argv[i], L"/disable"))
				Opt.Disable = true;
			else if (!StrCmpW(argv[i], L"/e") || !StrCmpW(argv[i], L"/enable"))
				Opt.Enable = true;
			else if (!StrCmpW(argv[i], L"/f") || !StrCmpW(argv[i], L"/flash"))
				Opt.Flashing = true;
			else if (!StrCmpW(argv[i], L"/t") || !StrCmpW(argv[i], L"/top"))
				Opt.Topmost = true;
			else if (!StrCmpW(argv[i], L"/scr") || !StrCmpW(argv[i], L"/screenshot"))
				Opt.Screenshot = true;
			else if (!StrCmpW(argv[i], L"/monitor"))
				Opt.Monitor = true;
		}
	}

	bool HasAction = Opt.Hide || Opt.Show || Opt.Close || Opt.Kill || Opt.Minimize || Opt.Maximize || Opt.Restore || Opt.Disable || Opt.Enable || Opt.Flashing;

	if (HasAction) {
		if (Opt.ForcePid) {
			ScanTree(ROOT, &Opt, Target);
			if (Target.empty()) {
				std::wcout << L"No match Window found.\n";
				return -1;
			}
			ExectOption(&Opt, Target);
		}
		else
			std::cout << "/pid is needed";
	}

	else if (Opt.Screenshot) {
		ScanTree(ROOT, &Opt, Target);

		if (Target.empty()) {
			std::wcout << L"No match Window found.\n";
			return -1;
		}
		ExectOption(&Opt, Target);
	}

	else if (Opt.Monitor) {
		MonitorOpt = Opt;
		Monitor(Opt.SavePath);
	}

	else if (Opt.Detect) {
		ScanDetect(ROOT, &Opt);
	}

	else {
		PrintTree(ROOT, L"", true, &Opt);
	}

	return 0;
}



