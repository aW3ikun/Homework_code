#include"pch.h"
#include"help.h"

BOOL Inject(CString pszfilePath, CString pszdllPath,CString &pszLog) {
    STARTUPINFO si;
    PROCESS_INFORMATION pi;
    BOOL bOK = FALSE;

    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));
    
    //挂起进程
    if (CreateProcess(pszfilePath,
        NULL,
        NULL,
        FALSE,
        NULL,
        CREATE_SUSPENDED,
        NULL,
        NULL,
        &si,
        &pi)) {
        CString pszProcess;
        pszProcess.Format(L"ProcessId: %d \r\n", pi.dwProcessId);
        pszLog += pszProcess.GetString();

        //EIP Hook
        CONTEXT Context = { 0 };
        Context.ContextFlags = CONTEXT_FULL;
        BYTE bHeadCode[6] = { 0 };
        if (GetThreadContext(pi.hThread, &Context)) {
            pszLog += "[+]获取上下文成功! \r\n";
            //获取前六字节
            if (ReadProcessMemory(pi.hProcess, (LPCVOID)Context.Eip, bHeadCode, sizeof(bHeadCode), NULL)) {
                pszLog += "[+]读取EIP成功! \r\n";
                //申请静态变量空间
                //申请shellcode空间
                if (VirtualAllocEx(pi.hProcess, NULL, pszdllPath.GetLength() + 1, MEM_COMMIT, PAGE_READWRITE)) {
                    pszLog += "[+]申请Dll路径内存成功! \r\n";
                    //WriteProcessMemory(pi.hProcess, )

                    bOK = TRUE;
                }
                else {
                    pszLog += "[-]申请Dll路径内存失败! \r\n";
                }
            }
            else {
                pszLog += "[-]读取EIP失败! \r\n";
            }
        }
        else {
            pszLog += "[-]获取上下文失败! \r\n";
        }

        ResumeThread(pi.hThread);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return bOK;
    }
    else {
        pszLog += "[-]加载进程失败! \r\n";
        return bOK;
    }
}
