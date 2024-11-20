# Memory-Mirage-Anti-Debugging
Use of in-memory string scans to outsmart reverse engineers
---

## Introduction

In a world where malware are under constant threat from reverse engineering and debugging, developers need robust methods to protect their applications (Malware is also an application). Traditional techniques, such as checking the parent process, are useful but predictable and easy to bypass.

This is where Memory Mirage steps in, an anti-debugging technique that scans the parent process memory for strings associated with known debuggers. This approach offers a dynamic and less predictable method of detection, which we explore in this paper, along with its implementation, advantages, and potential drawbacks.

---

## Background
### Traditional Anti-Debugging: Parent Process Checking

Parent process checking involves verifying the name or PID of the parent process to detect if a debugger is the one launching the application. For example, if the parent process isn't the usual 'explorer.exe', the application might suspect foul play.

Advantages:

- Simplicity: Easy to implement and understand.
- Performance: Minimal overhead due to straightforward checks.
  
Disadvantages:

- Predictability: Attackers can easily circumvent by spawning the process from the expected parent.
- False Positives: Legitimate processes might trigger the anti-debugging mechanisms inadvertently.
---

## Introducing Memory Mirage

Memory Mirage takes a different approach by scanning the parent process's memory for known strings associated with debuggers. It's like checking someone's bookshelf for detective novels to see if they're into sleuthing.

Advantages:

- Unpredictability: Harder for attackers to anticipate and bypass.
- Comprehensive Detection: Can identify debuggers even if they masquerade under different process names.

Disadvantages:

- Performance Overhead: Memory scanning is more resource-intensive.
- Complexity: Requires more intricate coding and handling of edge cases.

---

## Implementation Details

Let's dive into the code and explain the magic behind Memory Mirage.

### 1. Getting Process Names by PID
First, we need a function to retrieve the process name given its PID.

```c
void GetProcessNameByPID(DWORD pid, TCHAR* processName, DWORD maxLen) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (hProcess) {
        if (GetModuleBaseName(hProcess, NULL, processName, maxLen) == 0) {
            _tcscpy_s(processName, maxLen, _T("Unknown"));
        }
        CloseHandle(hProcess);
    } else {
        _tcscpy_s(processName, maxLen, _T("Unknown"));
    }
}
```
Explanation:

- OpenProcess: Opens the process with permissions to query information and read memory.
- GetModuleBaseName: Retrieves the name of the process.
- Error Handling: If the process can't be opened or the name retrieved, we label it as "Unknown".

### 2. Scanning Process Memory for Strings
The core of Memory Mirage lies in scanning the parent process's memory.

```c
bool SearchStringsInProcessMemory(DWORD processID, const char* targetString) {
    HANDLE hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, processID);
    // Error checking omitted for brevity
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    LPVOID minAddress = si.lpMinimumApplicationAddress;
    LPVOID maxAddress = si.lpMaximumApplicationAddress;

    MEMORY_BASIC_INFORMATION mbi;
    char buffer[1024];
    size_t bytesRead;
    size_t targetLength = strlen(targetString);

    for (LPBYTE address = (LPBYTE)minAddress; address < (LPBYTE)maxAddress; address += mbi.RegionSize) {
        if (VirtualQueryEx(hProcess, address, &mbi, sizeof(mbi)) == 0) break;
        if (mbi.State != MEM_COMMIT || !(mbi.Protect & (PAGE_READABLE_FLAGS))) continue;

        for (LPBYTE chunk = (LPBYTE)mbi.BaseAddress; chunk < (LPBYTE)mbi.BaseAddress + mbi.RegionSize; chunk += sizeof(buffer)) {
            if (ReadProcessMemory(hProcess, chunk, buffer, sizeof(buffer), &bytesRead)) {
                for (size_t i = 0; i <= bytesRead - targetLength; i++) {
                    if (memcmp(&buffer[i], targetString, targetLength) == 0) {
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

```

Explanation:

- System Range: We obtain the minimum and maximum application addresses to define our scanning range.
- Memory Regions: We use VirtualQueryEx to iterate through memory regions.
- Readable Pages: We filter for memory pages that are committed and readable.
- Reading Memory: ReadProcessMemory reads chunks of the parent process's memory.
- String Matching: We search these chunks for our target strings.

---
## Examples:

### Visual Studio
![VSCode](https://github.com/user-attachments/assets/c0363fa2-c103-4f7c-881c-cae9f33265bb)

### xdbg64
![xdbg64](https://github.com/user-attachments/assets/eb3dee69-7662-41d0-b282-d9eb3558d24d)

### IDA
![IDA](https://github.com/user-attachments/assets/f9b312de-8eb8-4fe5-91ae-03d1525defb6)

### No Debugger
![NoDebugger](https://github.com/user-attachments/assets/8927f8a0-c62d-45f4-b9fa-c26bb3ca3ae7)


---
## Advantages of Memory Mirage

1. Dynamic Detection: Since we're scanning memory content, even debuggers that change their process names can be detected if they contain identifiable strings.
2. Stealthiness: Harder for attackers to realize they're being monitored, much like a chameleon blending into its environment—hence the name Memory Mirage.
3. Flexibility: New debugger signatures can be added to the scanning list without altering the fundamental logic.

---

## Disadvantages

1. Performance Impact: Scanning large memory spaces can be time-consuming.
2. Anti-Anti-Debugging Techniques: Advanced debuggers may hide their strings or protect their memory.


---
## Conclusion
Memory Mirage opens up a new kind of debugging protection by going beyond simple surface checks and delving deep into the memory of potential attackers - yes, you reverse engineers are meant! In addition, all printf's that were only inserted for better understanding should be removed. 

---

## References:

[1] https://learn.microsoft.com/en-us/windows/win32/api/debugapi/nf-debugapi-debugactiveprocess

[2] https://learn.microsoft.com/en-us/windows/win32/secauthz/privilege-constants

[3] https://github.com/LordNoteworthy/al-khaser/tree/master

[4] https://0xpat.github.io/

[5] https://www.codeproject.com/Articles/30815/An-Anti-Reverse-Engineering-Guide

[6] https://maldevacademy.com/

To be honest, there is so much content and similar techniques that are always similar. These are the references you should definitely check out because there is so much to learn. If you have any suggestions for improvement or references I can add, please let me know.

---
