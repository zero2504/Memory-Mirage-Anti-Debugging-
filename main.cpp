#include <windows.h>
#include <stdio.h>
#include <tchar.h>
#include <TlHelp32.h>
#include <psapi.h>
#include <string.h>

#define SET_COLOR(color) SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), color)
#define RESET_COLOR() SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE)

// Function to determine the name of the process based on the PID
void GetProcessNameByPID(DWORD pid, TCHAR* processName, DWORD maxLen) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (hProcess) {
        if (GetModuleBaseName(hProcess, NULL, processName, maxLen) == 0) {
            _tcscpy_s(processName, maxLen, _T("Unknown"));
        }
        CloseHandle(hProcess);
    }
    else {
        _tcscpy_s(processName, maxLen, _T("Unknown"));
    }
}

// Function for scanning the memory for specific strings
bool SearchStringsInProcessMemory(DWORD processID, const char* targetString) {
    HANDLE hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, processID);
    if (hProcess == NULL) {
        printf("[-] Unable to open process with ID %lu. Error: %lu\n", processID, GetLastError());
        return false;
    }

    SYSTEM_INFO si;
    GetSystemInfo(&si);

    LPVOID minAddress = si.lpMinimumApplicationAddress;
    LPVOID maxAddress = si.lpMaximumApplicationAddress;

    MEMORY_BASIC_INFORMATION mbi;
    char buffer[1024];
    size_t bytesRead;
    size_t targetLength = strlen(targetString);

    for (LPBYTE address = (LPBYTE)minAddress; address < (LPBYTE)maxAddress; address += mbi.RegionSize) {
        if (VirtualQueryEx(hProcess, address, &mbi, sizeof(mbi)) == 0) {
            break;
        }

        if (mbi.State != MEM_COMMIT ||
            !(mbi.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE))) {
            continue;
        }

        for (LPBYTE chunk = (LPBYTE)mbi.BaseAddress; chunk < (LPBYTE)mbi.BaseAddress + mbi.RegionSize; chunk += sizeof(buffer)) {
            if (ReadProcessMemory(hProcess, chunk, buffer, sizeof(buffer), &bytesRead)) {
                for (size_t i = 0; i <= bytesRead - targetLength; i++) {
                    if (memcmp(&buffer[i], targetString, targetLength) == 0) {
                        SET_COLOR(FOREGROUND_GREEN | FOREGROUND_INTENSITY);
                        printf("[+] Found \"%s\" at address: 0x%p\n", targetString, chunk + i);
                        CloseHandle(hProcess);
                        return true;
                    }
                }
            }
        }
    }

    CloseHandle(hProcess);
    return false;
}

int main() {
    DWORD currentPID = GetCurrentProcessId();
    DWORD parentPID = 0;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (hSnapshot == INVALID_HANDLE_VALUE) {
        printf("[-] Failed to get process snapshot.\n");
        return 1;
    }

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(hSnapshot, &pe)) {
        do {
            if (pe.th32ProcessID == currentPID) {
                parentPID = pe.th32ParentProcessID;
                break;
            }
        } while (Process32Next(hSnapshot, &pe));
    }
    else {
        printf("[-] Failed to iterate through processes.\n");
    }

    CloseHandle(hSnapshot);

    TCHAR processName[MAX_PATH];
    TCHAR parentProcessName[MAX_PATH];
    GetProcessNameByPID(currentPID, processName, MAX_PATH);
    GetProcessNameByPID(parentPID, parentProcessName, MAX_PATH);

    printf("Information:\n");
    printf("[+] Current Process ID: %lu\n", currentPID);
    printf("[+] Current Process Name: %ls\n", processName);
    printf("[+] Parent Process ID: %lu\n", parentPID);
    printf("[+] Parent Process Name: %ls\n\n", parentProcessName);

    if (SearchStringsInProcessMemory(parentPID, "A Debugger for the future!")) {
        SET_COLOR(FOREGROUND_RED | FOREGROUND_INTENSITY);
        printf("[+] Detected x64dbg via string match.\n");
    }
    else if (SearchStringsInProcessMemory(parentPID, "www.hex-rays.com")) {
        SET_COLOR(FOREGROUND_RED | FOREGROUND_INTENSITY);
        printf("[+] Detected IDA Pro via string match.\n");
    }
    else if (SearchStringsInProcessMemory(parentPID, "VsDebugConsole.exe")) {
        SET_COLOR(FOREGROUND_RED | FOREGROUND_INTENSITY);
        printf("[+] Detected Visual Studio Debugger.\n");
    }
    else if (SearchStringsInProcessMemory(parentPID, "http://home.t-online.de/home/Ollydbg")) {
        SET_COLOR(FOREGROUND_RED | FOREGROUND_INTENSITY);
        printf("[+] Detected Ollydbg Debugger.\n");
    }
    else {
        SET_COLOR(FOREGROUND_GREEN | FOREGROUND_INTENSITY);
        printf("[-] No known debugger strings detected.\n");
    }

    

    RESET_COLOR();
    Sleep(5000);

    return 0;
}
